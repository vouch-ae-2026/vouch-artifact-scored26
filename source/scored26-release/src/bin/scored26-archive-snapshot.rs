//! Trusted Linux archive snapshot boundary for the SCORED26 clean-room driver.
//!
//! The outer driver opens the untrusted archive path exactly once and passes
//! that already-open regular-file descriptor as fd 3. This helper performs the
//! only source read, hashes and fully copies each chunk into a sealed memfd,
//! authenticates the captured bytes, and gives only the retained memfd to the
//! trusted extractor.

#[cfg(target_os = "linux")]
mod linux {
    use sha2::{Digest, Sha256};
    use std::env;
    use std::fs::{self, File};
    use std::io::{self, Read, Seek, SeekFrom, Write};
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    const SOURCE_FD: RawFd = 3;
    const BUFFER_SIZE: usize = 1024 * 1024;

    pub fn main() -> Result<(), String> {
        let options = Options::parse(env::args().skip(1))?;
        require_digest(&options.expected_sha256)?;
        let metadata = fs::metadata(&options.extract_root)
            .map_err(|error| format!("extract root unavailable: {error}"))?;
        if !metadata.is_dir() {
            return Err("extract root is not a directory".to_string());
        }

        // fd 3 is created only by the trusted parent. Taking ownership ensures
        // it is closed before tar is started, so archive-supplied code cannot
        // inherit the untrusted source descriptor.
        let source = unsafe { File::from_raw_fd(SOURCE_FD) };
        require_regular_file(&source)?;
        let observed =
            authenticate_and_extract(source, &options.expected_sha256, &options.extract_root)?;
        println!("SCORED26 sealed archive snapshot extracted ({observed})");
        Ok(())
    }

    fn authenticate_and_extract(
        source: File,
        expected_sha256: &str,
        extract_root: &Path,
    ) -> Result<String, String> {
        let mut snapshot = capture(source)?;
        let observed = snapshot.digest().to_string();
        if observed != expected_sha256 {
            return Err(format!(
                "archive digest mismatch: expected {expected_sha256}, observed {observed}"
            ));
        }
        snapshot.extract(extract_root)?;
        Ok(observed)
    }

    struct Options {
        expected_sha256: String,
        extract_root: PathBuf,
    }

    impl Options {
        fn parse(mut args: impl Iterator<Item = String>) -> Result<Self, String> {
            let mut expected_sha256 = None;
            let mut extract_root = None;
            while let Some(name) = args.next() {
                let value = args
                    .next()
                    .ok_or_else(|| format!("{name} requires a value"))?;
                match name.as_str() {
                    "--expected-sha256" if expected_sha256.is_none() => {
                        expected_sha256 = Some(value)
                    }
                    "--extract-root" if extract_root.is_none() => {
                        extract_root = Some(PathBuf::from(value))
                    }
                    _ => return Err(format!("invalid or repeated option {name}")),
                }
            }
            Ok(Self {
                expected_sha256: expected_sha256
                    .ok_or_else(|| "--expected-sha256 is required".to_string())?,
                extract_root: extract_root
                    .ok_or_else(|| "--extract-root is required".to_string())?,
            })
        }
    }

    struct SealedSnapshot {
        file: File,
        sha256: String,
    }

    impl SealedSnapshot {
        fn digest(&self) -> &str {
            &self.sha256
        }

        fn extract(&mut self, root: &Path) -> Result<(), String> {
            self.file
                .seek(SeekFrom::Start(0))
                .map_err(|error| format!("snapshot rewind before extraction failed: {error}"))?;
            let input = self
                .file
                .try_clone()
                .map_err(|error| format!("snapshot handoff failed: {error}"))?;
            let status = Command::new("/usr/bin/tar")
                .args(["--zstd", "-xf", "-", "-C"])
                .arg(root)
                .stdin(Stdio::from(input))
                .status()
                .map_err(|error| format!("trusted extractor failed to start: {error}"))?;
            if !status.success() {
                return Err(format!("trusted extractor failed with {status}"));
            }
            Ok(())
        }
    }

    fn capture(mut source: File) -> Result<SealedSnapshot, String> {
        let descriptor = unsafe {
            libc::memfd_create(
                c"scored26-archive-snapshot".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        if descriptor < 0 {
            return Err(format!(
                "pathless snapshot creation failed: {}",
                io::Error::last_os_error()
            ));
        }
        let mut snapshot = unsafe { File::from_raw_fd(descriptor) };
        let mut hasher = Sha256::new();
        let mut chunk = vec![0_u8; BUFFER_SIZE];
        loop {
            let count = source
                .read(&mut chunk)
                .map_err(|error| format!("archive source read failed: {error}"))?;
            if count == 0 {
                break;
            }
            let bytes = &chunk[..count];
            hasher.update(bytes);
            snapshot
                .write_all(bytes)
                .map_err(|error| format!("snapshot full write failed: {error}"))?;
        }
        // The source descriptor is deliberately dropped before authentication
        // and extraction. It is never rewound and can no longer be inherited.
        drop(source);
        snapshot
            .sync_all()
            .map_err(|error| format!("snapshot flush failed: {error}"))?;
        snapshot
            .seek(SeekFrom::Start(0))
            .map_err(|error| format!("snapshot rewind failed: {error}"))?;
        let seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        if unsafe { libc::fcntl(snapshot.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
            return Err(format!(
                "snapshot sealing failed: {}",
                io::Error::last_os_error()
            ));
        }
        let digest = hasher.finalize();
        Ok(SealedSnapshot {
            file: snapshot,
            sha256: format!("sha256:{digest:x}"),
        })
    }

    fn require_regular_file(file: &File) -> Result<(), String> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
        if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(format!(
                "archive descriptor stat failed: {}",
                io::Error::last_os_error()
            ));
        }
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err("archive descriptor is not a regular file".to_string());
        }
        Ok(())
    }

    fn require_digest(value: &str) -> Result<(), String> {
        if value.len() == 71
            && value.starts_with("sha256:")
            && value[7..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(())
        } else {
            Err("--expected-sha256 is not a canonical digest".to_string())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::fs::{create_dir_all, remove_dir_all, rename, OpenOptions};
        use std::time::{SystemTime, UNIX_EPOCH};

        #[test]
        fn l14_path_replacement_after_digest_keeps_snapshot_a() {
            let root = temporary_root("l14");
            let a = build_archive(&root, "a", "authenticated archive A");
            let b = build_archive(&root, "b", "substituted archive B");
            let expected = digest(&fs::read(&a).unwrap());
            let mut snapshot = capture(File::open(&a).unwrap()).unwrap();
            assert_eq!(snapshot.digest(), expected);
            let predictable_staging = root.join("predictable-content-addressed-staging");
            fs::copy(&b, &predictable_staging).unwrap();
            rename(&b, &a).unwrap();
            let extraction = root.join("extract");
            create_dir_all(&extraction).unwrap();
            snapshot.extract(&extraction).unwrap();
            assert_eq!(
                fs::read_to_string(extraction.join("marker.txt")).unwrap(),
                "authenticated archive A\n"
            );
            assert!(!extraction.join("b-code-ran").exists());
            remove_dir_all(root).unwrap();
        }

        #[test]
        fn l19_same_inode_overwrite_after_digest_keeps_snapshot_a() {
            let root = temporary_root("l19");
            let archive = build_archive(&root, "a", "authenticated archive A");
            let malicious = build_archive(&root, "b", "same-inode mutation B");
            let expected = digest(&fs::read(&archive).unwrap());
            let mut snapshot = capture(File::open(&archive).unwrap()).unwrap();
            assert_eq!(snapshot.digest(), expected);
            let mut overwrite = OpenOptions::new().write(true).open(&archive).unwrap();
            overwrite.set_len(0).unwrap();
            overwrite.write_all(&fs::read(&malicious).unwrap()).unwrap();
            overwrite.sync_all().unwrap();
            let extraction = root.join("extract");
            create_dir_all(&extraction).unwrap();
            snapshot.extract(&extraction).unwrap();
            assert_eq!(
                fs::read_to_string(extraction.join("marker.txt")).unwrap(),
                "authenticated archive A\n"
            );
            assert!(!extraction.join("b-code-ran").exists());
            remove_dir_all(root).unwrap();
        }

        #[test]
        fn non_regular_source_descriptor_is_rejected() {
            let root = temporary_root("regular");
            create_dir_all(root.join("directory")).unwrap();
            let directory = File::open(root.join("directory")).unwrap();
            assert_eq!(
                require_regular_file(&directory).unwrap_err(),
                "archive descriptor is not a regular file"
            );
            remove_dir_all(root).unwrap();
        }

        #[test]
        fn bootstrap_substitution_rejects_before_extraction() {
            let root = temporary_root("substitution");
            let archive = root.join("archive-b");
            let extraction = root.join("extract");
            create_dir_all(&extraction).unwrap();
            fs::write(&archive, b"mutually consistent substituted archive B\n").unwrap();
            let expected = digest(b"authenticated archive A\n");
            let error =
                authenticate_and_extract(File::open(&archive).unwrap(), &expected, &extraction)
                    .unwrap_err();
            assert!(error.starts_with("archive digest mismatch:"));
            assert_eq!(fs::read_dir(&extraction).unwrap().count(), 0);
            remove_dir_all(root).unwrap();
        }

        fn digest(bytes: &[u8]) -> String {
            let digest = Sha256::digest(bytes);
            format!("sha256:{digest:x}")
        }

        fn build_archive(root: &Path, label: &str, marker: &str) -> PathBuf {
            let input = root.join(format!("input-{label}"));
            create_dir_all(&input).unwrap();
            fs::write(input.join("marker.txt"), format!("{marker}\n")).unwrap();
            if label == "b" {
                fs::write(input.join("b-code-ran"), b"must never execute\n").unwrap();
            }
            let archive = root.join(format!("archive-{label}.tar.zst"));
            let status = Command::new("/usr/bin/tar")
                .args(["--zstd", "-cf"])
                .arg(&archive)
                .arg("-C")
                .arg(&input)
                .arg(".")
                .status()
                .unwrap();
            assert!(status.success());
            archive
        }

        fn temporary_root(label: &str) -> PathBuf {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = env::temp_dir().join(format!(
                "scored26-archive-snapshot-{label}-{}-{nonce}",
                std::process::id()
            ));
            create_dir_all(&root).unwrap();
            root
        }
    }
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = linux::main() {
        eprintln!("SCORED26 archive integrity failure: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("scored26-archive-snapshot requires Linux memfd sealing");
    std::process::exit(2);
}

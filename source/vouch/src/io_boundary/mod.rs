//! Read-once ownership and fault-injectable file, key, and publication seams.

use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub struct FrozenBytes {
    bytes: Arc<[u8]>,
    access_count: Arc<AtomicUsize>,
}

impl FrozenBytes {
    /// Makes a defensive copy immediately; no later operation consults `source`.
    pub fn from_slice(source: &[u8]) -> Self {
        Self {
            bytes: Arc::from(source.to_vec()),
            access_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn bytes(&self) -> &[u8] {
        self.access_count.fetch_add(1, Ordering::SeqCst);
        &self.bytes
    }

    pub fn access_count(&self) -> usize {
        self.access_count.load(Ordering::SeqCst)
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IoBoundaryError {
    NotFound,
    ResourceLimit,
    WrongKeyHandle,
    ShortWrite,
    FsyncFailure,
    FinalRenameFailure,
    OutputExists,
    InvalidOutputName,
    PlatformIo,
}

impl fmt::Display for IoBoundaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::NotFound => "not-found",
            Self::ResourceLimit => "artifact-resource-limit",
            Self::WrongKeyHandle => "wrong-key-handle",
            Self::ShortWrite => "short-write",
            Self::FsyncFailure => "fsync-failure",
            Self::FinalRenameFailure => "final-rename-failure",
            Self::OutputExists => "output-exists",
            Self::InvalidOutputName => "invalid-output-name",
            Self::PlatformIo => "platform-io-failure",
        };
        f.write_str(name)
    }
}

impl Error for IoBoundaryError {}

pub trait FileProvider: Send + Sync {
    fn read_once(&self, handle: &str, maximum_bytes: usize)
        -> Result<FrozenBytes, IoBoundaryError>;
    fn read_count(&self) -> usize;
}

/// Production read-once provider. It observes at most `maximum_bytes + 1`
/// octets, so an over-limit file is rejected without buffering its remainder.
#[derive(Debug, Default)]
pub struct OsFileProvider {
    reads: AtomicUsize,
}

impl FileProvider for OsFileProvider {
    fn read_once(
        &self,
        handle: &str,
        maximum_bytes: usize,
    ) -> Result<FrozenBytes, IoBoundaryError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let observation_limit = maximum_bytes
            .checked_add(1)
            .ok_or(IoBoundaryError::ResourceLimit)?;
        let file = File::open(handle).map_err(|_| IoBoundaryError::NotFound)?;
        let mut limited = file.take(observation_limit as u64);
        let mut bytes = Vec::with_capacity(observation_limit.min(64 * 1024));
        limited
            .read_to_end(&mut bytes)
            .map_err(|_| IoBoundaryError::PlatformIo)?;
        if bytes.len() > maximum_bytes {
            return Err(IoBoundaryError::ResourceLimit);
        }
        Ok(FrozenBytes::from_slice(&bytes))
    }

    fn read_count(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }
}

#[derive(Clone, Debug)]
struct MemoryFile {
    inode: u64,
    bytes: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct MemoryFileProvider {
    files: Mutex<BTreeMap<String, MemoryFile>>,
    reads: AtomicUsize,
    next_inode: AtomicU64,
}

impl MemoryFileProvider {
    pub fn insert(&self, handle: impl Into<String>, bytes: Vec<u8>) {
        let inode = self.next_inode.fetch_add(1, Ordering::SeqCst) + 1;
        self.files
            .lock()
            .expect("memory file lock")
            .insert(handle.into(), MemoryFile { inode, bytes });
    }

    /// Replaces the path binding with a distinct in-memory inode.
    pub fn replace_path(&self, handle: &str, bytes: Vec<u8>) -> Result<(), IoBoundaryError> {
        let inode = self.next_inode.fetch_add(1, Ordering::SeqCst) + 1;
        let previous = self
            .files
            .lock()
            .expect("memory file lock")
            .insert(handle.to_owned(), MemoryFile { inode, bytes });
        previous.map(|_| ()).ok_or(IoBoundaryError::NotFound)
    }

    /// Mutates bytes while preserving the simulated inode identity.
    pub fn mutate_same_inode(&self, handle: &str, bytes: Vec<u8>) -> Result<(), IoBoundaryError> {
        let mut files = self.files.lock().expect("memory file lock");
        let file = files.get_mut(handle).ok_or(IoBoundaryError::NotFound)?;
        file.bytes = bytes;
        Ok(())
    }

    pub fn inode(&self, handle: &str) -> Option<u64> {
        self.files
            .lock()
            .expect("memory file lock")
            .get(handle)
            .map(|file| file.inode)
    }
}

impl FileProvider for MemoryFileProvider {
    fn read_once(
        &self,
        handle: &str,
        maximum_bytes: usize,
    ) -> Result<FrozenBytes, IoBoundaryError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        let files = self.files.lock().expect("memory file lock");
        let bytes = &files.get(handle).ok_or(IoBoundaryError::NotFound)?.bytes;
        if bytes.len() > maximum_bytes {
            return Err(IoBoundaryError::ResourceLimit);
        }
        Ok(FrozenBytes::from_slice(bytes))
    }

    fn read_count(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KeyAccessCounts {
    pub metadata: usize,
    pub resolution: usize,
    pub open: usize,
    pub query: usize,
    pub authentication: usize,
    pub load: usize,
    pub signing: usize,
}

impl KeyAccessCounts {
    pub const fn total(self) -> usize {
        self.metadata
            + self.resolution
            + self.open
            + self.query
            + self.authentication
            + self.load
            + self.signing
    }
}

#[derive(Clone)]
pub struct LoadedTestKey {
    signing_key: SigningKey,
}

impl LoadedTestKey {
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

pub trait KeyProvider: Send + Sync {
    fn resolve(&self, handle: &str) -> Result<LoadedTestKey, IoBoundaryError>;
    fn access_counts(&self) -> KeyAccessCounts;
}

#[derive(Debug, Default)]
pub struct MemoryKeyProvider {
    seeds: Mutex<BTreeMap<String, [u8; 32]>>,
    resolution: AtomicUsize,
    load: AtomicUsize,
}

impl MemoryKeyProvider {
    pub fn insert(&self, handle: impl Into<String>, seed: [u8; 32]) {
        self.seeds
            .lock()
            .expect("memory key lock")
            .insert(handle.into(), seed);
    }
}

impl KeyProvider for MemoryKeyProvider {
    fn resolve(&self, handle: &str) -> Result<LoadedTestKey, IoBoundaryError> {
        self.resolution.fetch_add(1, Ordering::SeqCst);
        let seed = self
            .seeds
            .lock()
            .expect("memory key lock")
            .get(handle)
            .copied()
            .ok_or(IoBoundaryError::WrongKeyHandle)?;
        self.load.fetch_add(1, Ordering::SeqCst);
        Ok(LoadedTestKey {
            signing_key: SigningKey::from_bytes(&seed),
        })
    }

    fn access_counts(&self) -> KeyAccessCounts {
        KeyAccessCounts {
            resolution: self.resolution.load(Ordering::SeqCst),
            load: self.load.load(Ordering::SeqCst),
            ..KeyAccessCounts::default()
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PublicationFault {
    #[default]
    None,
    ShortWrite,
    FsyncFailure,
    FinalRenameFailure,
}

#[derive(Clone, Copy, Debug)]
pub struct PublicationFile<'a> {
    pub name: &'a str,
    pub bytes: &'a [u8],
}

pub trait AtomicPublisher: Send + Sync {
    fn publish(&self, output: &str, bytes: &[u8]) -> Result<(), IoBoundaryError>;
    fn final_rename_count(&self) -> usize;
}

pub trait AtomicDirectoryPublisher: Send + Sync {
    fn publish_directory(
        &self,
        output: &str,
        files: &[PublicationFile<'_>],
    ) -> Result<(), IoBoundaryError>;
    fn final_rename_count(&self) -> usize;
}

/// Portable single-file publication via a fully written same-directory inode
/// and one no-replace hard-link operation. The final path never exposes a
/// partial file and an existing final path is never replaced.
#[derive(Debug, Default)]
pub struct FilesystemAtomicPublisher {
    publications: AtomicUsize,
}

impl AtomicPublisher for FilesystemAtomicPublisher {
    fn publish(&self, output: &str, bytes: &[u8]) -> Result<(), IoBoundaryError> {
        let output = Path::new(output);
        let file_name = output
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .ok_or(IoBoundaryError::InvalidOutputName)?;
        let parent = output.parent().unwrap_or_else(|| Path::new("."));
        let mut staged = None;
        for _ in 0..128 {
            let sequence = NEXT_STAGING_FILE.fetch_add(1, Ordering::SeqCst);
            let candidate = parent.join(format!(
                ".{file_name}.staging-{}-{sequence}",
                std::process::id()
            ));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&candidate)
            {
                Ok(file) => {
                    staged = Some((candidate, file));
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(IoBoundaryError::PlatformIo),
            }
        }
        let (staged_path, mut file) = staged.ok_or(IoBoundaryError::PlatformIo)?;
        if file.write_all(bytes).is_err() || file.sync_all().is_err() {
            drop(file);
            let _ = std::fs::remove_file(&staged_path);
            return Err(IoBoundaryError::PlatformIo);
        }
        drop(file);
        if std::fs::hard_link(&staged_path, output).is_err() {
            let output_exists = output.exists();
            let _ = std::fs::remove_file(&staged_path);
            return Err(if output_exists {
                IoBoundaryError::OutputExists
            } else {
                IoBoundaryError::PlatformIo
            });
        }
        self.publications.fetch_add(1, Ordering::SeqCst);
        let _ = std::fs::remove_file(staged_path);
        Ok(())
    }

    fn final_rename_count(&self) -> usize {
        self.publications.load(Ordering::SeqCst)
    }
}

static NEXT_STAGING_FILE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Default)]
pub struct MemoryAtomicPublisher {
    fault: Mutex<PublicationFault>,
    files: Mutex<BTreeMap<String, Vec<u8>>>,
    renames: AtomicUsize,
}

impl MemoryAtomicPublisher {
    pub fn set_fault(&self, fault: PublicationFault) {
        *self.fault.lock().expect("publisher fault lock") = fault;
    }

    pub fn read(&self, output: &str) -> Option<Vec<u8>> {
        self.files
            .lock()
            .expect("publisher files lock")
            .get(output)
            .cloned()
    }
}

impl AtomicPublisher for MemoryAtomicPublisher {
    fn publish(&self, output: &str, bytes: &[u8]) -> Result<(), IoBoundaryError> {
        let fault = *self.fault.lock().expect("publisher fault lock");
        if fault == PublicationFault::ShortWrite {
            return Err(IoBoundaryError::ShortWrite);
        }
        if fault == PublicationFault::FsyncFailure {
            return Err(IoBoundaryError::FsyncFailure);
        }
        if fault == PublicationFault::FinalRenameFailure {
            return Err(IoBoundaryError::FinalRenameFailure);
        }
        let mut files = self.files.lock().expect("publisher files lock");
        if files.contains_key(output) {
            return Err(IoBoundaryError::OutputExists);
        }
        self.renames.fetch_add(1, Ordering::SeqCst);
        files.insert(output.to_owned(), bytes.to_vec());
        Ok(())
    }

    fn final_rename_count(&self) -> usize {
        self.renames.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Default)]
pub struct MemoryAtomicDirectoryPublisher {
    fault: Mutex<PublicationFault>,
    directories: Mutex<BTreeMap<String, BTreeMap<String, Vec<u8>>>>,
    renames: AtomicUsize,
}

impl MemoryAtomicDirectoryPublisher {
    pub fn set_fault(&self, fault: PublicationFault) {
        *self.fault.lock().expect("directory publisher fault lock") = fault;
    }

    pub fn directory(&self, output: &str) -> Option<BTreeMap<String, Vec<u8>>> {
        self.directories
            .lock()
            .expect("published directories lock")
            .get(output)
            .cloned()
    }
}

impl AtomicDirectoryPublisher for MemoryAtomicDirectoryPublisher {
    fn publish_directory(
        &self,
        output: &str,
        files: &[PublicationFile<'_>],
    ) -> Result<(), IoBoundaryError> {
        let fault = *self.fault.lock().expect("directory publisher fault lock");
        match fault {
            PublicationFault::ShortWrite => return Err(IoBoundaryError::ShortWrite),
            PublicationFault::FsyncFailure => return Err(IoBoundaryError::FsyncFailure),
            PublicationFault::FinalRenameFailure => {
                return Err(IoBoundaryError::FinalRenameFailure)
            }
            PublicationFault::None => {}
        }
        let mut staged = BTreeMap::new();
        for file in files {
            if staged
                .insert(file.name.to_owned(), file.bytes.to_vec())
                .is_some()
            {
                return Err(IoBoundaryError::InvalidOutputName);
            }
        }
        let mut directories = self.directories.lock().expect("published directories lock");
        if directories.contains_key(output) {
            return Err(IoBoundaryError::OutputExists);
        }
        self.renames.fetch_add(1, Ordering::SeqCst);
        directories.insert(output.to_owned(), staged);
        Ok(())
    }

    fn final_rename_count(&self) -> usize {
        self.renames.load(Ordering::SeqCst)
    }
}

#[cfg(target_os = "linux")]
pub mod linux {
    use super::{
        AtomicDirectoryPublisher, AtomicPublisher, IoBoundaryError, PublicationFault,
        PublicationFile,
    };
    use sha2::{Digest, Sha256};
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::{Component, Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub struct LinuxAtomicPublisher {
        root: PathBuf,
        fault: PublicationFault,
        renames: AtomicUsize,
    }

    impl LinuxAtomicPublisher {
        pub fn new(root: PathBuf, fault: PublicationFault) -> Self {
            Self {
                root,
                fault,
                renames: AtomicUsize::new(0),
            }
        }
    }

    impl AtomicPublisher for LinuxAtomicPublisher {
        fn publish(&self, output: &str, bytes: &[u8]) -> Result<(), IoBoundaryError> {
            validate_name(output)?;
            let output_path = self.root.join(output);
            if output_path.exists() {
                return Err(IoBoundaryError::OutputExists);
            }
            let staging = self.root.join(format!(".stage-{}", random_hex()?));
            let result = (|| {
                let mut file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(&staging)
                    .map_err(|_| IoBoundaryError::PlatformIo)?;
                if self.fault == PublicationFault::ShortWrite {
                    let amount = bytes.len().saturating_sub(1);
                    file.write_all(&bytes[..amount])
                        .map_err(|_| IoBoundaryError::PlatformIo)?;
                    return Err(IoBoundaryError::ShortWrite);
                }
                file.write_all(bytes)
                    .map_err(|_| IoBoundaryError::PlatformIo)?;
                if self.fault == PublicationFault::FsyncFailure {
                    return Err(IoBoundaryError::FsyncFailure);
                }
                file.sync_all().map_err(|_| IoBoundaryError::FsyncFailure)?;
                if self.fault == PublicationFault::FinalRenameFailure {
                    return Err(IoBoundaryError::FinalRenameFailure);
                }
                fs::rename(&staging, &output_path)
                    .map_err(|_| IoBoundaryError::FinalRenameFailure)?;
                File::open(&self.root)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|_| IoBoundaryError::FsyncFailure)?;
                self.renames.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })();
            if result.is_err() && staging.exists() {
                let _ = fs::remove_file(&staging);
            }
            result
        }

        fn final_rename_count(&self) -> usize {
            self.renames.load(Ordering::SeqCst)
        }
    }

    pub struct LinuxAtomicDirectoryPublisher {
        root: PathBuf,
        fault: PublicationFault,
        renames: AtomicUsize,
    }

    impl LinuxAtomicDirectoryPublisher {
        pub fn new(root: PathBuf, fault: PublicationFault) -> Self {
            Self {
                root,
                fault,
                renames: AtomicUsize::new(0),
            }
        }
    }

    impl AtomicDirectoryPublisher for LinuxAtomicDirectoryPublisher {
        fn publish_directory(
            &self,
            output: &str,
            files: &[PublicationFile<'_>],
        ) -> Result<(), IoBoundaryError> {
            validate_name(output)?;
            let output_path = self.root.join(output);
            if output_path.exists() {
                return Err(IoBoundaryError::OutputExists);
            }
            let staging = self.root.join(format!(".stage-{}", random_hex()?));
            fs::create_dir(&staging).map_err(|_| IoBoundaryError::PlatformIo)?;
            let result = (|| {
                for publication in files {
                    validate_name(publication.name)?;
                    let mut file = OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .mode(0o600)
                        .open(staging.join(publication.name))
                        .map_err(|_| IoBoundaryError::PlatformIo)?;
                    if self.fault == PublicationFault::ShortWrite {
                        let amount = publication.bytes.len().saturating_sub(1);
                        file.write_all(&publication.bytes[..amount])
                            .map_err(|_| IoBoundaryError::PlatformIo)?;
                        return Err(IoBoundaryError::ShortWrite);
                    }
                    file.write_all(publication.bytes)
                        .map_err(|_| IoBoundaryError::PlatformIo)?;
                    if self.fault == PublicationFault::FsyncFailure {
                        return Err(IoBoundaryError::FsyncFailure);
                    }
                    file.sync_all().map_err(|_| IoBoundaryError::FsyncFailure)?;
                }
                File::open(&staging)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|_| IoBoundaryError::FsyncFailure)?;
                if self.fault == PublicationFault::FinalRenameFailure {
                    return Err(IoBoundaryError::FinalRenameFailure);
                }
                fs::rename(&staging, &output_path)
                    .map_err(|_| IoBoundaryError::FinalRenameFailure)?;
                self.renames.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })();
            if result.is_err() && staging.exists() {
                let _ = fs::remove_dir_all(&staging);
            }
            result
        }

        fn final_rename_count(&self) -> usize {
            self.renames.load(Ordering::SeqCst)
        }
    }

    fn validate_name(name: &str) -> Result<(), IoBoundaryError> {
        let path = Path::new(name);
        if name.is_empty()
            || path.is_absolute()
            || path.components().count() != 1
            || !matches!(path.components().next(), Some(Component::Normal(_)))
        {
            return Err(IoBoundaryError::InvalidOutputName);
        }
        Ok(())
    }

    // This deliberately stays private until the trusted bootstrap boundary is
    // built. Stage 1 exercises it in-module so no path or descriptor escapes.
    #[allow(dead_code)]
    trait ArchiveSnapshot {
        fn rewind_and_read(&mut self) -> Result<Vec<u8>, IoBoundaryError>;
    }

    #[allow(dead_code)]
    struct UnlinkedArchiveSnapshot {
        file: File,
        digest: [u8; 32],
    }

    impl ArchiveSnapshot for UnlinkedArchiveSnapshot {
        fn rewind_and_read(&mut self) -> Result<Vec<u8>, IoBoundaryError> {
            self.file
                .seek(SeekFrom::Start(0))
                .map_err(|_| IoBoundaryError::PlatformIo)?;
            let mut bytes = Vec::new();
            self.file
                .read_to_end(&mut bytes)
                .map_err(|_| IoBoundaryError::PlatformIo)?;
            Ok(bytes)
        }
    }

    #[allow(dead_code)]
    fn capture_snapshot(source: &mut File) -> Result<UnlinkedArchiveSnapshot, IoBoundaryError> {
        let trusted_directory =
            std::env::temp_dir().join(format!("vouch-snapshot-{}", random_hex()?));
        fs::create_dir(&trusted_directory).map_err(|_| IoBoundaryError::PlatformIo)?;
        let snapshot_path = trusted_directory.join(random_hex()?);
        let mut snapshot = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&snapshot_path)
            .map_err(|_| IoBoundaryError::PlatformIo)?;
        fs::remove_file(&snapshot_path).map_err(|_| IoBoundaryError::PlatformIo)?;
        fs::remove_dir(&trusted_directory).map_err(|_| IoBoundaryError::PlatformIo)?;
        let mut chunk = [0_u8; 64 * 1024];
        let mut hasher = Sha256::new();
        loop {
            let read = source
                .read(&mut chunk)
                .map_err(|_| IoBoundaryError::PlatformIo)?;
            if read == 0 {
                break;
            }
            hasher.update(&chunk[..read]);
            snapshot
                .write_all(&chunk[..read])
                .map_err(|_| IoBoundaryError::ShortWrite)?;
        }
        snapshot
            .sync_all()
            .map_err(|_| IoBoundaryError::FsyncFailure)?;
        snapshot
            .seek(SeekFrom::Start(0))
            .map_err(|_| IoBoundaryError::PlatformIo)?;
        Ok(UnlinkedArchiveSnapshot {
            file: snapshot,
            digest: hasher.finalize().into(),
        })
    }

    fn random_hex() -> Result<String, IoBoundaryError> {
        let mut bytes = [0_u8; 16];
        File::open("/dev/urandom")
            .and_then(|mut source| source.read_exact(&mut bytes))
            .map_err(|_| IoBoundaryError::PlatformIo)?;
        Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::Write;

        fn temp_root() -> PathBuf {
            let root =
                std::env::temp_dir().join(format!("vouch-linux-test-{}", random_hex().unwrap()));
            fs::create_dir(&root).unwrap();
            root
        }

        #[test]
        fn linux_pathless_snapshot_survives_path_replacement_and_same_inode_mutation() {
            let root = temp_root();
            let archive = root.join("archive.tar");
            fs::write(&archive, b"captured bytes").unwrap();
            let mut source = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&archive)
                .unwrap();
            let mut snapshot = capture_snapshot(&mut source).unwrap();

            let replacement = root.join("replacement.tar");
            fs::write(&replacement, b"replacement").unwrap();
            fs::rename(&replacement, &archive).unwrap();
            let mut same_inode = source.try_clone().unwrap();
            same_inode.seek(SeekFrom::Start(0)).unwrap();
            same_inode.write_all(b"MUTATED").unwrap();
            same_inode.flush().unwrap();

            assert_eq!(snapshot.rewind_and_read().unwrap(), b"captured bytes");
            let expected_digest: [u8; 32] = Sha256::digest(b"captured bytes").into();
            assert_eq!(snapshot.digest, expected_digest);
            drop(source);
            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn linux_directory_publication_uses_one_final_rename() {
            let root = temp_root();
            let publisher =
                LinuxAtomicDirectoryPublisher::new(root.clone(), PublicationFault::None);
            publisher
                .publish_directory(
                    "issued",
                    &[PublicationFile {
                        name: "payload.json",
                        bytes: b"{}\n",
                    }],
                )
                .unwrap();
            assert_eq!(publisher.final_rename_count(), 1);
            assert_eq!(fs::read(root.join("issued/payload.json")).unwrap(), b"{}\n");
            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn linux_file_publication_uses_fsync_and_one_final_rename() {
            let root = temp_root();
            let publisher = LinuxAtomicPublisher::new(root.clone(), PublicationFault::None);
            publisher.publish("report.json", b"{}\n").unwrap();
            assert_eq!(publisher.final_rename_count(), 1);
            assert_eq!(fs::read(root.join("report.json")).unwrap(), b"{}\n");
            fs::remove_dir_all(root).unwrap();
        }

        #[test]
        fn linux_fsync_and_final_rename_faults_publish_nothing() {
            for (fault, expected) in [
                (PublicationFault::ShortWrite, IoBoundaryError::ShortWrite),
                (
                    PublicationFault::FsyncFailure,
                    IoBoundaryError::FsyncFailure,
                ),
                (
                    PublicationFault::FinalRenameFailure,
                    IoBoundaryError::FinalRenameFailure,
                ),
            ] {
                let root = temp_root();
                let publisher = LinuxAtomicDirectoryPublisher::new(root.clone(), fault);
                assert_eq!(
                    publisher.publish_directory(
                        "issued",
                        &[PublicationFile {
                            name: "payload.json",
                            bytes: b"{}\n"
                        }],
                    ),
                    Err(expected)
                );
                assert!(!root.join("issued").exists());
                assert_eq!(publisher.final_rename_count(), 0);
                fs::remove_dir_all(root).unwrap();
            }
        }

        #[test]
        fn linux_file_publication_faults_publish_nothing() {
            for (fault, expected) in [
                (PublicationFault::ShortWrite, IoBoundaryError::ShortWrite),
                (
                    PublicationFault::FsyncFailure,
                    IoBoundaryError::FsyncFailure,
                ),
                (
                    PublicationFault::FinalRenameFailure,
                    IoBoundaryError::FinalRenameFailure,
                ),
            ] {
                let root = temp_root();
                let publisher = LinuxAtomicPublisher::new(root.clone(), fault);
                assert_eq!(publisher.publish("report.json", b"{}\n"), Err(expected));
                assert!(!root.join("report.json").exists());
                assert_eq!(publisher.final_rename_count(), 0);
                fs::remove_dir_all(root).unwrap();
            }
        }
    }
}

#[cfg(all(test, not(target_os = "linux")))]
mod non_linux_notice {
    #[test]
    fn linux_snapshot_and_atomic_fault_paths_are_ci_only() {
        eprintln!(
            "SKIP: real pathless snapshot, single-rename, and fsync fault paths run on Linux CI"
        );
    }
}

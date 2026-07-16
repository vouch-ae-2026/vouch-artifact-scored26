use sha2::{Digest, Sha256};
use std::process::ExitCode;
use std::thread;
use vouch::artifact_json::{write_canonical, JsonValue};

const AMOUNT_MIN: i64 = 0;
const AMOUNT_MAX: i64 = 1_000_000;
const DOMAIN: &[u8] = b"vouch/workload-interior/v0";

#[derive(Clone)]
struct Stratum {
    id: String,
    codes: [i64; 4],
}

#[derive(Clone)]
struct Interior {
    stratum_id: String,
    interval_id: usize,
    amount: i64,
    digest: [u8; 32],
}

fn main() -> ExitCode {
    let raw = std::env::args().skip(1).collect::<Vec<_>>();
    if raw.len() != 6 {
        eprintln!("usage: scored26-workload-interiors t1 t2 t3 t4 t5 t6");
        return ExitCode::from(2);
    }
    let thresholds = match raw
        .iter()
        .map(|value| value.parse::<i64>())
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(values) => values,
        Err(_) => {
            eprintln!("thresholds must be decimal integers");
            return ExitCode::from(2);
        }
    };
    if thresholds[0] < AMOUNT_MIN + 2
        || thresholds[5] > AMOUNT_MAX - 2
        || thresholds.windows(2).any(|pair| pair[1] - pair[0] < 4)
    {
        eprintln!("threshold spacing is outside the SCORED26 workload contract");
        return ExitCode::from(2);
    }

    let strata = strata();
    // The release generator is pinned to eight deterministic work buckets.
    // Host scheduling may serialize them, but bucket ownership and output do
    // not depend on the scheduler or on reported container CPU quotas.
    let workers = 8_usize.min(strata.len());
    let mut buckets = vec![Vec::new(); workers];
    for (index, stratum) in strata.into_iter().enumerate() {
        buckets[index % workers].push(stratum);
    }
    let mut handles = Vec::new();
    for bucket in buckets {
        let thresholds = thresholds.clone();
        handles.push(thread::spawn(move || {
            bucket
                .into_iter()
                .flat_map(|stratum| find_interiors(&stratum, &thresholds))
                .collect::<Vec<_>>()
        }));
    }
    let mut output = Vec::new();
    for handle in handles {
        match handle.join() {
            Ok(mut values) => output.append(&mut values),
            Err(_) => {
                eprintln!("interior worker panicked");
                return ExitCode::FAILURE;
            }
        }
    }
    output.sort_by(|left, right| {
        left.stratum_id
            .cmp(&right.stratum_id)
            .then(left.interval_id.cmp(&right.interval_id))
    });
    for interior in output {
        println!(
            "{}\t{}\t{}\t{}",
            interior.stratum_id,
            interior.interval_id,
            interior.amount,
            lower_hex(&interior.digest)
        );
    }
    ExitCode::SUCCESS
}

fn strata() -> Vec<Stratum> {
    let mut output = Vec::with_capacity(48);
    for period in [2025, 2026] {
        for household in 0..=3 {
            for dependents in 0..=2 {
                for residency in 0..=1 {
                    output.push(Stratum {
                        id: format!("S{:02}", output.len() + 1),
                        codes: [period, household, dependents, residency],
                    });
                }
            }
        }
    }
    output
}

fn find_interiors(stratum: &Stratum, thresholds: &[i64]) -> Vec<Interior> {
    let mut excluded = Vec::with_capacity(18);
    for threshold in thresholds {
        excluded.extend([threshold - 1, *threshold, threshold + 1]);
    }
    let mut bounds = Vec::with_capacity(8);
    bounds.push(AMOUNT_MIN);
    bounds.extend_from_slice(thresholds);
    bounds.push(AMOUNT_MAX + 1);
    let (input_prefix, input_suffix) = canonical_input_parts(stratum.codes);
    (0..7)
        .map(|index| {
            let interval_id = index + 1;
            let mut base = Sha256::new();
            base.update(DOMAIN);
            base.update([0]);
            base.update(stratum.id.as_bytes());
            base.update([0]);
            base.update(interval_id.to_string().as_bytes());
            base.update([0]);
            base.update(&input_prefix);
            let mut best: Option<(i64, [u8; 32])> = None;
            for amount in bounds[index]..bounds[index + 1] {
                if excluded.contains(&amount) {
                    continue;
                }
                let mut hasher = base.clone();
                hasher.update(amount.to_string().as_bytes());
                hasher.update(&input_suffix);
                let digest: [u8; 32] = hasher.finalize().into();
                if best.as_ref().is_none_or(|(_, current)| digest < *current) {
                    best = Some((amount, digest));
                }
            }
            let (amount, digest) = best.unwrap_or_else(|| {
                panic!("{} interval {} has no interior", stratum.id, interval_id)
            });
            Interior {
                stratum_id: stratum.id.clone(),
                interval_id,
                amount,
                digest,
            }
        })
        .collect()
}

fn canonical_input_parts(codes: [i64; 4]) -> (Vec<u8>, Vec<u8>) {
    let prefix = format!(
        "{{\n  \"input\": \"csk.checked-input/v1\",\n  \"value\": [\n    {},\n    {},\n    {},\n    {},\n    ",
        codes[0], codes[1], codes[2], codes[3]
    )
    .into_bytes();
    let suffix = b"\n  ]\n}\n".to_vec();
    let mut rendered = prefix.clone();
    rendered.extend_from_slice(b"0");
    rendered.extend_from_slice(&suffix);
    let expected = write_canonical(
        &JsonValue::object([
            (
                "input",
                JsonValue::String("csk.checked-input/v1".to_string()),
            ),
            (
                "value",
                JsonValue::Array(
                    codes
                        .into_iter()
                        .chain([0])
                        .map(JsonValue::Integer)
                        .collect(),
                ),
            ),
        ])
        .expect("checked input fields are unique"),
    )
    .expect("workload integers are safe");
    assert_eq!(rendered, expected, "canonical checked-input template drift");
    (prefix, suffix)
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

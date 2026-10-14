//! Wire types shared by agent and server. See ADR 0003.
//!
//! Agent batches are protobuf messages compressed with zstd. [`encode_batch`]
//! and [`decode_batch`] are the only framing the ingest path should use.

use prost::Message;
use std::io::Read;

pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/kestrel.v1.rs"));
}

pub mod remote {
    include!(concat!(env!("OUT_DIR"), "/kestrel.remote.rs"));
}

pub mod otel {
    include!(concat!(env!("OUT_DIR"), "/otel.metrics.v1.rs"));
}

/// Recommended cap on a decompressed batch. Callers may pass a tighter limit.
pub const DEFAULT_MAX_DECOMPRESSED: usize = 32 * 1024 * 1024;

/// Failure while decoding a compressed batch.
#[derive(Debug)]
pub enum ProtoError {
    /// The decompressed payload is larger than the caller-supplied maximum.
    TooLarge,
    /// zstd could not decode the frame.
    Decompress(String),
    /// The decompressed bytes are not a `Batch`.
    Decode(prost::DecodeError),
}

impl std::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => write!(f, "decompressed batch exceeds the configured maximum"),
            Self::Decompress(err) => write!(f, "zstd decode failed: {err}"),
            Self::Decode(err) => write!(f, "protobuf decode failed: {err}"),
        }
    }
}

impl std::error::Error for ProtoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(err) => Some(err),
            Self::TooLarge | Self::Decompress(_) => None,
        }
    }
}

/// One metric sample.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    pub name: String,
    pub labels: Vec<(String, String)>,
    pub value: f64,
    pub timestamp_ms: i64,
}

impl From<Sample> for v1::Sample {
    fn from(sample: Sample) -> Self {
        v1::Sample {
            name: sample.name,
            labels: sample
                .labels
                .into_iter()
                .map(|(name, value)| v1::Label { name, value })
                .collect(),
            value: sample.value,
            timestamp_ms: sample.timestamp_ms,
        }
    }
}

impl From<v1::Sample> for Sample {
    fn from(sample: v1::Sample) -> Self {
        Sample {
            name: sample.name,
            labels: sample
                .labels
                .into_iter()
                .map(|label| (label.name, label.value))
                .collect(),
            value: sample.value,
            timestamp_ms: sample.timestamp_ms,
        }
    }
}

/// Nagios-compatible check state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckState {
    Ok = 0,
    Warning = 1,
    Critical = 2,
    Unknown = 3,
}

impl CheckState {
    pub fn from_exit_code(code: i32) -> Self {
        match code {
            0 => Self::Ok,
            1 => Self::Warning,
            2 => Self::Critical,
            _ => Self::Unknown,
        }
    }
}

/// Encode `batch` as a zstd frame (level 3) of its protobuf form.
pub fn encode_batch(batch: &v1::Batch) -> Vec<u8> {
    let raw = batch.encode_to_vec();
    zstd::stream::encode_all(raw.as_slice(), 3).expect("zstd encode of an in-memory batch")
}

/// Decode a zstd-compressed protobuf batch.
///
/// `max` is the largest decompressed size that will be accepted. Pass
/// [`DEFAULT_MAX_DECOMPRESSED`] unless a caller has a tighter budget. Output
/// above `max` returns [`ProtoError::TooLarge`] without buffering the rest.
pub fn decode_batch(bytes: &[u8], max: usize) -> Result<v1::Batch, ProtoError> {
    let raw = decompress_limited(bytes, max)?;
    v1::Batch::decode(raw.as_slice()).map_err(ProtoError::Decode)
}

fn decompress_limited(bytes: &[u8], max: usize) -> Result<Vec<u8>, ProtoError> {
    let mut decoder = zstd::stream::read::Decoder::with_buffer(bytes)
        .map_err(|err| ProtoError::Decompress(err.to_string()))?;
    let mut out = Vec::new();
    let mut buf = [0u8; 8 * 1024];
    loop {
        let n = decoder
            .read(&mut buf)
            .map_err(|err| ProtoError::Decompress(err.to_string()))?;
        if n == 0 {
            break;
        }
        if out.len().saturating_add(n) > max {
            return Err(ProtoError::TooLarge);
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_batch() -> v1::Batch {
        v1::Batch {
            agent_id: "agent-1".to_string(),
            seq: 7,
            samples: vec![v1::Sample {
                name: "kestrel_memory_used_bytes".to_string(),
                labels: vec![v1::Label {
                    name: "host".to_string(),
                    value: "web-1".to_string(),
                }],
                value: 1024.0,
                timestamp_ms: 1_700_000_000_000,
            }],
            checks: vec![v1::CheckResult {
                check_id: "disk".to_string(),
                state: CheckState::Warning as i32,
                output: "disk 85%".to_string(),
                perfdata: "used=85%;90;95;0;100".to_string(),
                timestamp_ms: 1_700_000_000_000,
            }],
            logs: vec![v1::LogEvent {
                source: "/var/log/syslog".to_string(),
                line: "kestrel started".to_string(),
                timestamp_ms: 1_700_000_000_001,
                labels: vec![],
            }],
            inventory: Some(v1::Inventory {
                filesystems: vec![v1::Filesystem {
                    mount: "/".to_string(),
                    device: "/dev/sda1".to_string(),
                    fs_type: "ext4".to_string(),
                }],
                interfaces: vec![v1::NetInterface {
                    name: "eth0".to_string(),
                    mac: "02:00:00:00:00:01".to_string(),
                    addresses: vec!["10.0.0.5".to_string()],
                }],
                listen_ports: vec![v1::ListenPort {
                    address: "0.0.0.0".to_string(),
                    port: 22,
                    protocol: "tcp".to_string(),
                }],
                services: vec![v1::Service {
                    name: "kestrel-agent".to_string(),
                    manager: "systemd".to_string(),
                    state: "active".to_string(),
                }],
            }),
        }
    }

    #[test]
    fn exit_codes_map() {
        assert_eq!(CheckState::from_exit_code(2), CheckState::Critical);
        assert_eq!(CheckState::from_exit_code(9), CheckState::Unknown);
    }

    #[test]
    fn round_trip_batch() {
        let batch = sample_batch();
        let bytes = encode_batch(&batch);
        assert_eq!(&bytes[..4], &[0x28, 0xB5, 0x2F, 0xFD]);
        let decoded = decode_batch(&bytes, DEFAULT_MAX_DECOMPRESSED).unwrap();
        assert_eq!(decoded, batch);
    }

    #[test]
    fn sample_converts_both_ways() {
        let rust = Sample {
            name: "kestrel_cpu_usage_ratio".to_string(),
            labels: vec![("cpu".to_string(), "total".to_string())],
            value: 0.25,
            timestamp_ms: 42,
        };
        let proto = v1::Sample::from(rust.clone());
        let back = Sample::from(proto);
        assert_eq!(back, rust);
    }

    #[test]
    fn rejects_zstd_bomb() {
        let huge = vec![0u8; 2 * 1024 * 1024];
        let compressed = zstd::stream::encode_all(huge.as_slice(), 3).unwrap();
        assert!(compressed.len() < 64 * 1024);
        let err = decode_batch(&compressed, 64 * 1024).unwrap_err();
        assert!(matches!(err, ProtoError::TooLarge));
    }

    #[test]
    fn unknown_fields_are_tolerated() {
        let batch = v1::Batch {
            agent_id: "agent-1".to_string(),
            seq: 3,
            ..Default::default()
        };
        let mut raw = batch.encode_to_vec();
        // Field 15, wire type 0 (varint), value 1. The tag fits in one byte:
        // (15 << 3) | 0 = 120. Unknown fields must be skipped.
        raw.push(120);
        raw.push(1);
        let compressed = zstd::stream::encode_all(raw.as_slice(), 3).unwrap();
        let decoded = decode_batch(&compressed, DEFAULT_MAX_DECOMPRESSED).unwrap();
        assert_eq!(decoded.agent_id, "agent-1");
        assert_eq!(decoded.seq, 3);
        assert!(decoded.samples.is_empty());
    }

    #[test]
    fn corrupt_frame_is_an_error() {
        let err = decode_batch(b"not-zstd", DEFAULT_MAX_DECOMPRESSED).unwrap_err();
        assert!(matches!(err, ProtoError::Decompress(_)));
    }
}

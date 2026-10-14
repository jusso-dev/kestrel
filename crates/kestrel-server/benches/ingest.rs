//! Decode cost for a 1,000-sample batch.
//!
//! This measures local protobuf and zstd work. It is not the 4 vCPU ingest
//! benchmark; that run is recorded in `docs/VALIDATION.md`.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use kestrel_proto::v1::{self, Batch};
use kestrel_proto::{decode_batch, DEFAULT_MAX_DECOMPRESSED};

fn batch(samples: usize) -> Batch {
    let mut samples_out = Vec::with_capacity(samples);
    for index in 0..samples {
        samples_out.push(v1::Sample {
            name: "kestrel_cpu_usage_ratio".to_string(),
            labels: vec![v1::Label {
                name: "cpu".to_string(),
                value: "total".to_string(),
            }],
            value: index as f64,
            timestamp_ms: 1_700_000_000_000 + index as i64,
        });
    }
    Batch {
        agent_id: "bench".to_string(),
        seq: 1,
        samples: samples_out,
        checks: Vec::new(),
        logs: Vec::new(),
        inventory: None,
    }
}

fn decode_one_thousand(c: &mut Criterion) {
    let bytes = kestrel_proto::encode_batch(&batch(1000));
    c.bench_function("decode_1000_sample_batch", |bencher| {
        bencher.iter(|| {
            decode_batch(black_box(&bytes), DEFAULT_MAX_DECOMPRESSED).unwrap();
        });
    });
}

criterion_group!(benches, decode_one_thousand);
criterion_main!(benches);

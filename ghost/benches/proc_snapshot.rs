//! Baseline for the /proc poller tick cost (RFC 0004).
//! Parses the bench process's own /proc tree per iteration — stable
//! enough across hosts to anchor a regression gate.

use criterion::{criterion_group, criterion_main, Criterion};
use ghost::proc::ProcSnapshot;

fn bench_snapshot(c: &mut Criterion) {
    let pid = std::process::id();
    c.bench_function("proc_snapshot_self", |b| {
        b.iter(|| {
            let _ = ProcSnapshot::collect(pid);
        })
    });
}

criterion_group!(benches, bench_snapshot);
criterion_main!(benches);

//! Baseline for the per-tick cost of the analyzer engine (RFC 0004).
//!
//! Exercises `AnalyzerEngine::tick` over a warmed-up state with the
//! full 260-rule registry attached. The baseline is read into CI's
//! regression gate (`cargo criterion --baseline main`).

use criterion::{criterion_group, criterion_main, Criterion};
use ghost::{
    analyze::{config::AnalyzerConfig, engine::AnalyzerEngine, AnalyzerState, Mode},
    state::AppState,
};

fn bench_tick(c: &mut Criterion) {
    let mut cfg = AnalyzerConfig::built_in();
    cfg.default_mode = Mode::Noisy;
    let mut eng = AnalyzerEngine::new(cfg);
    let mut st = AppState::new(1, "nginx".into());
    st.watch.cpu_history.push_back(92.0);
    let mut out = AnalyzerState::default();
    // warm history ring
    for _ in 0..32 {
        eng.tick(&st, &mut out);
    }
    c.bench_function("analyze_tick_warm", |b| {
        b.iter(|| {
            eng.tick(&st, &mut out);
        })
    });
}

criterion_group!(benches, bench_tick);
criterion_main!(benches);

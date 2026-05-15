use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ironcontext_core::{Manifest, Report};

fn bench_scan(c: &mut Criterion) {
    let bytes = include_bytes!("../../../fixtures/large_manifest.json");
    c.bench_function("scan large_manifest (100 tools)", |b| {
        b.iter(|| {
            let m = Manifest::from_slice(black_box(bytes)).unwrap();
            let _r = Report::build_security(&m);
        });
    });
}

criterion_group!(benches, bench_scan);
criterion_main!(benches);

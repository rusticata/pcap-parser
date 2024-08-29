use criterion::{criterion_group, criterion_main, Criterion};
use pcap_parser::parse_pcap;
use std::fs;

fn bench_parse_pcap(c: &mut Criterion) {
    let bytes = fs::read("assets/ntp.pcap").unwrap();
    c.bench_function("parse_pcap ntp", |b| b.iter(|| parse_pcap(&bytes)));
}

criterion_group!(benches, bench_parse_pcap);
criterion_main!(benches);

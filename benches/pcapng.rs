use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use pcap_parser::{parse_pcapng, traits::PcapReaderIterator, PcapError, PcapNGReader};
use std::fs;

fn bench_parse_pcapng(c: &mut Criterion) {
    let bytes = fs::read("assets/wireshark_samples-test.pcapng").unwrap();
    c.bench_function("parse_pcapng wireshark_samples-test", |b| {
        b.iter(|| parse_pcapng(&bytes))
    });
}

fn do_reader_pcapng(bytes: &[u8], buffer_size: usize) {
    let mut num_blocks = 0;
    let mut reader = PcapNGReader::new(buffer_size, bytes).expect("could not create reader");
    loop {
        match reader.next() {
            Ok((offset, _block)) => {
                num_blocks += 1;
                reader.consume_noshift(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader.refill().unwrap();
            }
            Err(e) => panic!("unexpected error {:?}", e),
        }
    }
    assert_eq!(num_blocks, 5902);
}

fn bench_reader_pcapng(c: &mut Criterion) {
    let bytes = fs::read("assets/wireshark_samples-test.pcapng").unwrap();
    c.bench_function("reader_pcapng wireshark_samples-test", |b| {
        b.iter(|| do_reader_pcapng(&bytes, 65536))
    });
}

fn bench_reader_pcapng_buffer_size(c: &mut Criterion) {
    let bytes = fs::read("assets/wireshark_samples-test.pcapng").unwrap();
    let mut group = c.benchmark_group("reader_pcapng buffer_size");
    const KB16: usize = 16384;
    for buffer_size in [KB16, KB16 * 2, KB16 * 4, KB16 * 8, KB16 * 16].iter() {
        group.throughput(Throughput::Bytes(*buffer_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(buffer_size),
            buffer_size,
            |b, &size| b.iter(|| do_reader_pcapng(&bytes, size)),
        );
    }
}

criterion_group!(
    benches,
    bench_parse_pcapng,
    bench_reader_pcapng,
    bench_reader_pcapng_buffer_size
);
criterion_main!(benches);

// Run:
//   cargo bench --bench profile_pcapng -- --profile-time=5
//
//
// Use one the following to display the results:
//   ~/go/bin/pprof -svg ./target/criterion/profile_reader_pcapng\ test001-le/profile/profile.pb
//      + use firefox to open file `profile001.svg`
// Or
//   ~/go/bin/pprof -http "0.0.0.0:8081" ./target/criterion/profile_reader_pcapng\ wireshark_samples-test/profile/profile.pb
//      + connect to 127.0.0.1:8081

use criterion::{criterion_group, criterion_main, Criterion};
use pcap_parser::{traits::PcapReaderIterator, PcapError, PcapNGReader};
use pprof::criterion::{Output, PProfProfiler};
use std::fs;

fn do_reader_pcapng(bytes: &[u8]) {
    let mut num_blocks = 0;
    let mut reader = PcapNGReader::new(65536, bytes).expect("could not create reader");
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

fn profile_reader_pcapng(c: &mut Criterion) {
    let bytes = fs::read("assets/wireshark_samples-test.pcapng").unwrap();
    c.bench_function("profile_reader_pcapng wireshark_samples-test", |b| {
        b.iter(|| do_reader_pcapng(&bytes))
    });
}

fn profiled() -> Criterion {
    //Criterion::default().with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)))
    Criterion::default().with_profiler(PProfProfiler::new(100, Output::Protobuf))
}

criterion_group! {
    name = benches;
    config = profiled();
    targets = profile_reader_pcapng
}
criterion_main!(benches);

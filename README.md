# PCAP parser

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![Build
Status](https://travis-ci.org/rusticata/pcap-parser.svg?branch=master)](https://travis-ci.org/rusticata/pcap-parser)
[![Crates.io Version](https://img.shields.io/crates/v/pcap-parser.svg)](https://crates.io/crates/pcap-parser)

<!-- cargo-sync-readme start -->

# PCAP and PCAPNG parsers

This crate contains several parsers for PCAP and PCAPNG files.

Compared to other similar projects, it is designed to offer a complete support of the many
possible formats (legacy pcap, pcapng, little or big-endian, etc.) and features (pcanpng files
with multiple sections, interfaces, and endianness) while using only safe code and without
copying data (zero-copy).

The code is available on [Github](https://github.com/rusticata/pcap-parser)
and is part of the [Rusticata](https://github.com/rusticata) project.

# Example: generic parsing

The following code shows how to parse a file either in PCAP or PCAPNG format.

```rust
use pcap_parser::*;
use nom::IResult;
use std::fs::File;
use std::io::Read;

let mut file = File::open(path).unwrap();
let mut buffer = Vec::new();
file.read_to_end(&mut buffer).unwrap();
let mut num_blocks = 0;
// try pcap first
match PcapCapture::from_file(&buffer) {
    Ok(capture) => {
        println!("Format: PCAP");
        for _block in capture.iter() {
            num_blocks += 1;
        }
        return;
    },
    _ => ()
}
// otherwise try pcapng
match PcapNGCapture::from_file(&buffer) {
    Ok(capture) => {
        println!("Format: PCAPNG");
        // most pcaps have one section, with one interface
        //
        // global iterator - provides a unified iterator over all
        // sections and interfaces. It will usually work only if there
        // is one section with one interface
        // otherwise, the next iteration code is better
        for _block in capture.iter() {
            // num_blocks += 1;
        }
        // The following code iterates all sections,
        // and for each section all packets.
        // Note that the link type can be different for each data block!
        println!("Num sections: {}", capture.sections.len());
        for (snum,section) in capture.sections.iter().enumerate() {
            println!("Section {}:", snum);
            // ...
            for _packet in section.iter() {
                num_blocks += 1;
            }
        }
    },
    _ => ()
}
```

The above code requires the file to be entirely loaded into memory.

# Example: streaming parsers

The following code shows how to parse a file either in PCAP or PCAPNG format, using a
[PcapNGReader](struct.LegacyPcapReader.html) streaming parser.

```rust
use pcap_parser::*;
use pcap_parser::traits::PcapReaderIterator;
use nom::ErrorKind;
use std::fs::File;
use std::io::Read;

let mut file = File::open(path).unwrap();
let mut num_blocks = 0;
let mut reader = PcapNGReader::new(65536, file).expect("PcapNGReader");
loop {
    match reader.next() {
        Ok((offset, _block)) => {
            println!("got new block");
            num_blocks += 1;
            reader.consume(offset);
        },
        Err(ErrorKind::Eof) => break,
        Err(e) => panic!("error while reading: {:?}", e),
    }
}
println!("num_blocks: {}", num_blocks);
```

See [pcap-tools](https://github.com/rusticata/pcap-tools) for more examples.

<!-- cargo-sync-readme end -->

## Changes

### 0.6.0

- Complete rewrite of the crate (breaks API)

### 0.5.1

- Fix computation of timestamp for high-resolution pcap-ng


## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.


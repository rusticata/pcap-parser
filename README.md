# PCAP parser

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![Build
Status](https://travis-ci.org/rusticata/pcap-parser.svg?branch=master)](https://travis-ci.org/rusticata/pcap-parser)
[![Crates.io Version](https://img.shields.io/crates/v/pcap-parser.svg)](https://crates.io/crates/pcap-parser)

<!-- cargo-sync-readme start -->

# PCAP and PCAPNG parsers

This crate contains several parsers for PCAP and PCAPNG files.

The code is available on [Github](https://github.com/rusticata/pcap-parser)
and is part of the [Rusticata](https://github.com/rusticata) project.

# Example: generic parsing

The following code shows how to parse a file either in PCAP or PCAPNG format.

```rust,no_run
use pcap_parser::*;
use nom::IResult;
use std::fs::File;
use std::io::Read;

let mut file = File::open(path).unwrap();
let mut buffer = Vec::new();
file.read_to_end(&mut buffer).unwrap();
let mut num_packets = 0;
// try pcap first
match PcapCapture::from_file(&buffer) {
    Ok(capture) => {
        println!("Format: PCAP");
        for _packet in capture.iter_packets() {
            num_packets += 1;
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
        for _packet in capture.iter_packets() {
            // num_packets += 1;
        }
        // The following code iterates all sections, for each section
        // all interfaces, and for each interface all packets.
        // Note that the link type can be different for each interface!
        println!("Num sections: {}", capture.sections.len());
        for (snum,section) in capture.sections.iter().enumerate() {
            println!("Section {}:", snum);
            for (inum,interface) in section.interfaces.iter().enumerate() {
                println!("    Interface {}:", inum);
                println!("        Linktype: {:?}", interface.header.linktype);
                // ...
                for _packet in section.iter_packets() {
                    num_packets += 1;
                }
            }
        }
    },
    _ => ()
}
```

The above code requires the file to be entirely loaded into memory. Other functions
in this crate allows for writing streaming parsers.
See [pcap-tools](https://github.com/rusticata/pcap-tools) for examples.

<!-- cargo-sync-readme end -->

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


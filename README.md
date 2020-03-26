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

# The pcap format(s)

The [PCAP] format (files usually ending with `.pcap` extension) is rather
trivial. The [PCAPNG] format (usually `.pcapng` extension) is much more complex: it
can be composed of multiple sections, each with multiple interfaces, having
different capture lengths, time precision and even endianness!

These formats are more containers than data formats: packets contain data,
formatted according to its interface linktype. There are *many* possible
linktypes, defined in the [linktypes registry]. Support for parsing some of
them is provided using the `data` feature (disabled by default).

This crate provides an abstraction over these different formats.

[PCAP]: https://wiki.wireshark.org/Development/LibpcapFileFormat
[PCAPNG]: https://pcapng.github.io/pcapng/
[linktypes registry]: https://www.tcpdump.org/linktypes.html

# Parsing a file

`pcap-parser` provides several ways of parsing pcap data. Choosing the right
one is mostly driven by resources: if the input file is small, the
`parse_pcap` and `parse_pcapng` functions can be used directly.

Fine-grained functions are also available, to parse specifically some block
types for example. They are listed in the `pcap` and `pcapng` modules.

If the input is larger and cannot fit into memory, then streaming parsers
are available. They work by iterating on blocks, and so do not require to map
the entire input. They cannot seek to a specific block, however.

*Note: due to PCAPNG limitations, it is not possible to directly seek in
a file to get a packet and handle it: the caller has to iterate though the
file and store (at least) the interface descriptions for the current
section, in order of appearance.*

## Example: streaming parsers

The following code shows how to parse a file in the pcap-ng format, using a
`PcapNGReader` streaming parser.

```rust
use pcap_parser::*;
use pcap_parser::traits::PcapReaderIterator;
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
        Err(PcapError::Eof) => break,
        Err(PcapError::Incomplete) => {
            reader.refill().unwrap();
        },
        Err(e) => panic!("error while reading: {:?}", e),
    }
}
println!("num_blocks: {}", num_blocks);
```
See `PcapNGReader` for a complete example, including handling of
linktype and accessing packet data.

For legacy pcap files, use similar code with the
`LegacyPcapReader` streaming parser.

See [pcap-tools](https://github.com/rusticata/pcap-tools),
[pcap-parse](https://github.com/rusticata/pcap-parse) and
[integration
tests](https://github.com/rusticata/pcap-parser/tree/master/tests)
for more examples.

## Example: generic streaming parsing

To create a pcap reader for input in either PCAP or PCAPNG format, use the
`create_reader` function.

# Serialization

Support for serialization (*i.e.* generating binary data) is available by
enabling the `serialize` feature.
Most structures gain the `to_vec()` method (provided by the `ToVec` trait).

Note: support is still experimental, though working. API may change in the
future.

<!-- cargo-sync-readme end -->

## Changes

### 0.8.4

- Add method to access data of the PcapReaderIterator buffer
- Fix all clippy warnings

### 0.8.3

- Avoid integer overflow in `parse_name_record` edge case

### 0.8.2

- Remove byteorder crate, use functions from std
- Return Eof if refill failed (avoid infinite loop)

### 0.8.1

- Upgrade to cookie-factory 0.3.0

### 0.8.0

- Add basic support for serialization (little-endian only)
- Add basic support for Wireshark exported PDUs
- Add traits Clone and Debug to PacketData
- Move data parsing functions to a subdirectory

### 0.7.1

- Fix wrong EOF detection
- Fix handling of incomplete reads (in example)

### 0.7.0

- Upgrade to nom 5
  - Breaking API changes, mainly for error types

### 0.6.1

- Make LegacyPcapBlock a regular structure with parser, and add serialization

### 0.6.0

- Complete rewrite of the crate (breaks API)
- Add streaming parser iterators
- Replace Packet with Blocks
  - Allows handling of non-data blocks
  - Handles correctly timestamps and resolution
  - Remove incorrect or deprecated code
- Better parsing of all variants (BE/LE, block types, etc.)
- Better (and panic-free) functions to extract block contents
- Set edition to 2018
- Better documentation

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


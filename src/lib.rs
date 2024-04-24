//! [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
//! [![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
//! [![Crates.io Version](https://img.shields.io/crates/v/pcap-parser.svg)](https://crates.io/crates/pcap-parser)
//! [![docs.rs](https://docs.rs/pcap-parser/badge.svg)](https://docs.rs/pcap-parser)
//! [![Github CI](https://github.com/rusticata/pcap-parser/workflows/Continuous%20integration/badge.svg)](https://github.com/rusticata/pcap-parser/actions)
//! [![Minimum rustc version](https://img.shields.io/badge/rustc-1.63.0+-lightgray.svg)](#rust-version-requirements)
//!
//! # PCAP and PCAPNG parsers
//!
//! This crate contains several parsers for PCAP and PCAPNG files.
//!
//! Compared to other similar projects, it is designed to offer a complete support of the many
//! possible formats (legacy pcap, pcapng, little or big-endian, etc.) and features (pcapng files
//! with multiple sections, interfaces, and endianness) while using only safe code and without
//! copying data (zero-copy).
//!
//! The code is available on [Github](https://github.com/rusticata/pcap-parser)
//! and is part of the [Rusticata](https://github.com/rusticata) project.
//!
//! # The pcap format(s)
//!
//! The [PCAP] format (files usually ending with `.pcap` extension) is rather
//! trivial. The [PCAPNG] format (usually `.pcapng` extension) is much more complex: it
//! can be composed of multiple sections, each with multiple interfaces, having
//! different capture lengths, time precision and even endianness!
//!
//! These formats are more containers than data formats: packets contain data,
//! formatted according to its interface linktype. There are *many* possible
//! linktypes, defined in the [linktypes registry]. Support for parsing some of
//! them is provided using the `data` feature (disabled by default).
//!
//! This crate provides an abstraction over these different formats.
//!
//! [PCAP]: https://wiki.wireshark.org/Development/LibpcapFileFormat
//! [PCAPNG]: https://pcapng.github.io/pcapng/
//! [linktypes registry]: https://www.tcpdump.org/linktypes.html
//!
//! # Parsing a file
//!
//! `pcap-parser` provides several ways of parsing pcap data. Choosing the right
//! one is mostly driven by resources: if the input file is small, the
//! `parse_pcap` and `parse_pcapng` functions can be used directly.
//!
//! Fine-grained functions are also available, to parse specifically some block
//! types for example. They are listed in the `pcap` and `pcapng` modules.
//!
//! If the input is larger and cannot fit into memory, then streaming parsers
//! are available. They work by iterating on blocks, and so do not require to map
//! the entire input. They cannot seek to a specific block, however.
//!
//! *Note: due to PCAPNG limitations, it is not possible to directly seek in
//! a file to get a packet and handle it: the caller has to iterate though the
//! file and store (at least) the interface descriptions for the current
//! section, in order of appearance.*
//!
//! ## Example: streaming parsers
//!
//! The following code shows how to parse a file in the pcap-ng format, using a
//! [`PcapNGReader`] streaming parser.
//! This reader provides a convenient abstraction over the file format, and takes
//! care of the endianness.
//!
//! ```rust
//! use pcap_parser::*;
//! use pcap_parser::traits::PcapReaderIterator;
//! use std::fs::File;
//!
//! # let path = "assets/test001-le.pcapng";
//! let file = File::open(path).unwrap();
//! let mut num_blocks = 0;
//! let mut reader = PcapNGReader::new(65536, file).expect("PcapNGReader");
//! loop {
//!     match reader.next() {
//!         Ok((offset, _block)) => {
//!             println!("got new block");
//!             num_blocks += 1;
//!             reader.consume(offset);
//!         },
//!         Err(PcapError::Eof) => break,
//!         Err(PcapError::Incomplete(_)) => {
//!             reader.refill().unwrap();
//!         },
//!         Err(e) => panic!("error while reading: {:?}", e),
//!     }
//! }
//! println!("num_blocks: {}", num_blocks);
//! ```
//! See [`PcapNGReader`] for a complete example,
//! including handling of linktype and accessing packet data.
//!
//! See also the [`pcapng`] module for more details about the new capture file format.
//!
//! For legacy pcap files, use similar code with the
//! [`LegacyPcapReader`] streaming parser.
//!
//! See [pcap-analyzer](https://github.com/rusticata/pcap-analyzer), in particular the
//! [libpcap-tools](https://github.com/rusticata/pcap-analyzer/tree/master/libpcap-tools) and
//! [pcap-info](https://github.com/rusticata/pcap-analyzer/tree/master/pcap-info) modules
//! for more examples.
//!
//! ## Example: generic streaming parsing
//!
//! To create a pcap reader for input in either PCAP or PCAPNG format, use the
//! [`create_reader`] function.
//!
//! # Serialization
//!
//! Support for serialization (*i.e.* generating binary data) is available by
//! enabling the `serialize` feature.
//! Most structures gain the `to_vec()` method (provided by the `ToVec` trait).
//!
//! Note: support is still experimental, though working. API may change in the
//! future.

#![deny(/*missing_docs,*/
        unstable_features,
        unused_import_braces, unused_qualifications)]
#![deny(unsafe_code)]
#![allow(clippy::upper_case_acronyms)]
// pragmas for doc
#![deny(rustdoc::broken_intra_doc_links)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(test(
    no_crate_inject,
    attr(deny(warnings/*, rust_2018_idioms*/), allow(dead_code, unused_variables))
))]

mod utils;
pub use utils::{Data, MutableData};

mod blocks;
mod capture;
mod endianness;
mod error;
mod linktype;
pub use blocks::*;
pub use capture::*;
pub use error::*;
pub use linktype::*;

pub mod pcap;
pub mod pcapng;
pub use pcap::*;
pub use pcapng::*;

pub mod traits;

#[cfg(feature = "serialize")]
#[cfg_attr(docsrs, doc(cfg(feature = "serialize")))]
mod serialize;
#[cfg_attr(docsrs, doc(cfg(feature = "serialize")))]
#[cfg(feature = "serialize")]
pub use serialize::ToVec;

#[cfg(feature = "data")]
#[cfg_attr(docsrs, doc(cfg(feature = "data")))]
pub mod data;

// re-exports
pub use nom;

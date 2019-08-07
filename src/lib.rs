//! # PCAP and PCAPNG parsers
//!
//! This crate contains several parsers for PCAP and PCAPNG files.
//!
//! Compared to other similar projects, it is designed to offer a complete support of the many
//! possible formats (legacy pcap, pcapng, little or big-endian, etc.) and features (pcanpng files
//! with multiple sections, interfaces, and endianness) while using only safe code and without
//! copying data (zero-copy).
//!
//! The code is available on [Github](https://github.com/rusticata/pcap-parser)
//! and is part of the [Rusticata](https://github.com/rusticata) project.
//!
//! # Example: streaming parsers
//!
//! The following code shows how to parse a file in the pcap-ng format, using a
//! [PcapNGReader](struct.PcapNGReader.html) streaming parser.
//!
//! ```rust
//! # extern crate nom;
//! # extern crate pcap_parser;
//! use pcap_parser::*;
//! use pcap_parser::traits::PcapReaderIterator;
//! use std::fs::File;
//! use std::io::Read;
//!
//! # fn main() {
//! # let path = "assets/test001-le.pcapng";
//! let mut file = File::open(path).unwrap();
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
//!         Err(e) => panic!("error while reading: {:?}", e),
//!     }
//! }
//! println!("num_blocks: {}", num_blocks);
//! # }
//! ```
//! See [PcapNGReader](struct.PcapNGReader.html) for a complete example, including handling of
//! linktype and accessing packet data.
//!
//! For legacy pcap files, use similar code with the
//! [LegacyPcapReader](struct.LegacyPcapReader.html) streaming parser.
//!
//! See [pcap-tools](https://github.com/rusticata/pcap-tools) and
//! [pcap-parse](https://github.com/rusticata/pcap-parse) for more examples.
//!
//! # Example: generic streaming parsing
//!
//! To create a pcap reader for input in either PCAP or PCAPNG format, use the
//! [create_reader](fn.create_reader.html) function.

extern crate byteorder;

#[macro_use]
extern crate nom;

#[macro_use]
extern crate cookie_factory;

#[macro_use]
extern crate rusticata_macros;

mod utils;
pub use utils::{Data, MutableData};

mod blocks;
mod error;
mod linktype;
pub use blocks::*;
pub use error::*;
pub use linktype::*;

pub mod pcap;
pub mod pcapng;
pub use pcap::*;
pub use pcapng::*;

pub mod traits;

mod capture;
mod capture_pcap;
mod capture_pcapng;
pub use capture::*;
pub use capture_pcap::*;
pub use capture_pcapng::*;

#[cfg(feature = "data")]
pub mod data;

#[cfg(test)]
#[macro_use]
extern crate hex_literal;

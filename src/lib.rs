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
//! # Example: generic parsing
//!
//! The following code shows how to parse a file either in PCAP or PCAPNG format.
//!
//! ```rust
//! # extern crate nom;
//! # extern crate pcap_parser;
//! use pcap_parser::*;
//! use nom::IResult;
//! use std::fs::File;
//! use std::io::Read;
//!
//! # fn main() {
//! # let path = "assets/test001-le.pcapng";
//! let mut file = File::open(path).unwrap();
//! let mut buffer = Vec::new();
//! file.read_to_end(&mut buffer).unwrap();
//! let mut num_blocks = 0;
//! // try pcap first
//! match PcapCapture::from_file(&buffer) {
//!     Ok(capture) => {
//!         println!("Format: PCAP");
//!         for _block in capture.iter() {
//!             num_blocks += 1;
//!         }
//!         return;
//!     },
//!     _ => ()
//! }
//! // otherwise try pcapng
//! match PcapNGCapture::from_file(&buffer) {
//!     Ok(capture) => {
//!         println!("Format: PCAPNG");
//!         // most pcaps have one section, with one interface
//!         //
//!         // global iterator - provides a unified iterator over all
//!         // sections and interfaces. It will usually work only if there
//!         // is one section with one interface
//!         // otherwise, the next iteration code is better
//!         for _block in capture.iter() {
//!             // num_blocks += 1;
//!         }
//!         // The following code iterates all sections,
//!         // and for each section all packets.
//!         // Note that the link type can be different for each data block!
//!         println!("Num sections: {}", capture.sections.len());
//!         for (snum,section) in capture.sections.iter().enumerate() {
//!             println!("Section {}:", snum);
//!             // ...
//!             for _packet in section.iter() {
//!                 num_blocks += 1;
//!             }
//!         }
//!     },
//!     _ => ()
//! }
//! # }
//! ```
//!
//! The above code requires the file to be entirely loaded into memory.
//!
//! # Example: streaming parsers
//!
//! The following code shows how to parse a file either in PCAP or PCAPNG format,
//! using a [`BufReader`](https://doc.rust-lang.org/std/io/struct.BufReader.html) for buffered I/O.
//!
//! ```rust
//! # extern crate nom;
//! # extern crate pcap_parser;
//! use pcap_parser::*;
//! use pcap_parser::traits::PcapReaderIterator;
//! use nom::{ErrorKind, IResult};
//! use std::fs::File;
//! use std::io::{BufReader, Read};
//!
//! # fn main() {
//! # let path = "assets/test001-le.pcapng";
//! let mut file = File::open(path).unwrap();
//! let buffered = BufReader::new(file);
//! let mut num_blocks = 0;
//! let mut reader = PcapNGReader::new(buffered).expect("PcapNGReader");
//! loop {
//!     match reader.next() {
//!         Ok((offset, _block)) => {
//!             println!("got new block");
//!             num_blocks += 1;
//!             reader.consume(offset);
//!         },
//!         Err(ErrorKind::Eof) => break,
//!         Err(e) => panic!("error while reading: {:?}", e),
//!     }
//! }
//! println!("num_blocks: {}", num_blocks);
//! # }
//! ```
//!
//! To control to size of the reading buffer, see
//! [`BufReader::with_capacity`](https://doc.rust-lang.org/std/io/struct.BufReader.html#method.with_capacity).
//!
//! See [pcap-tools](https://github.com/rusticata/pcap-tools) for more examples.

extern crate byteorder;

#[macro_use]
extern crate nom;

#[macro_use]
extern crate cookie_factory;

#[macro_use]
extern crate rusticata_macros;

mod utils;
pub use utils::{Data, MutableData};

mod packet;
pub use packet::*;

pub mod pcap;
pub use pcap::*;
pub mod pcapng;
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

#[cfg(feature = "data")]
mod pcap_nflog;

#[cfg(test)]
#[macro_use]
extern crate hex_literal;

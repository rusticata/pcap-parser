# Change Log

## [Unreleased][unreleased]

### Added

### Changed/Fixed

## 0.9.4

### Added

- Add trait PartialEq to PcapError

### Changed/Fixed

- Improve error handling in create_reader (if input is empty or incomplete)
- Set MSRV to 1.44
- Update consume() documentation, it does not refill buffer (Closes #9)

## 0.9.3

### Added

- Add support for nanosecond-resolution legacy PCAP files

## 0.9.2

### Added

- Add Error trait to PcapError
- Edition 2018: remove all "extern crate" statements
- QA: warn if using unstable features, forbid unsafe code

## 0.9.1

### Added

- Check magic constants when reading DSB and SJE blocks
- Add `ToVec` implementation for SJE, DCB and Block

## 0.9.0

### Added

- Add `Default` trait to `Linktype`
- Add `NameRecordType` constants
- pcap-ng: add method to get the (normalized) magic of blocks
- Add support for Decryption Secrets Block (DSB)
- Add support for Systemd Journal Export Block (SJE)

### Changed/Fixed

- Improve documentation (remove relative links, broken outside docs.rs)

## 0.8.4

- Add method to access data of the PcapReaderIterator buffer
- Fix all clippy warnings

## 0.8.3

- Avoid integer overflow in `parse_name_record` edge case

## 0.8.2

- Remove byteorder crate, use functions from std
- Return Eof if refill failed (avoid infinite loop)

## 0.8.1

- Upgrade to cookie-factory 0.3.0

## 0.8.0

- Add basic support for serialization (little-endian only)
- Add basic support for Wireshark exported PDUs
- Add traits Clone and Debug to PacketData
- Move data parsing functions to a subdirectory

## 0.7.1

- Fix wrong EOF detection
- Fix handling of incomplete reads (in example)

## 0.7.0

- Upgrade to nom 5
  - Breaking API changes, mainly for error types

## 0.6.1

- Make LegacyPcapBlock a regular structure with parser, and add serialization

## 0.6.0

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

## 0.5.1

- Fix computation of timestamp for high-resolution pcap-ng


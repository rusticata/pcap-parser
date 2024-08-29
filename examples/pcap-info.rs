use pcap_parser::*;
use std::env;
use std::error::Error;
use std::fs::File;

fn main() {
    for arg in env::args().skip(1) {
        print_pcap_info(&arg).unwrap();
    }
}

fn print_pcap_info(arg: &str) -> Result<(), Box<dyn Error>> {
    println!("Name: {}", arg);

    let file = File::open(arg)?;
    let file_size = file.metadata()?.len();
    println!("\tfile size: {}", file_size);

    let mut reader = create_reader(10 * 1024, file)?;

    let first_block = reader.next();

    match first_block {
        Ok((_, PcapBlockOwned::LegacyHeader(header))) => {
            println!("\tformat: legacy Pcap file");
            println!(
                "\tversion: {}.{}",
                header.version_major, header.version_minor
            );
            println!("\tData Link Type: {}", header.network);
        }
        Ok((_, PcapBlockOwned::NG(block))) => {
            println!("\tformat: Pcap-NG file");
            // first block should be a SectionHeader
            if let Block::SectionHeader(sh) = block {
                println!("\t\tVersion: {}.{}", sh.major_version, sh.minor_version);
                let shb_hardware = sh.shb_hardware();
                println!(
                    "\t\tshb_hardware: {}",
                    shb_hardware.transpose()?.unwrap_or("<invalid>")
                );
            } else {
                return Err("pcapng: block is not a section header".into());
            }
        }
        _ => return Err("Unexpected first block, or wrong file format".into()),
    }

    // count blocks in file
    let mut num_blocks = 1;

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
            Err(e) => panic!("Unexpected error: {}", e),
        }
    }

    println!("\tnum_blocks: {}", num_blocks);

    Ok(())
}
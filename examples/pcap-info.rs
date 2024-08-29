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

    // Note that we do not call `consume()` here, so the next call to `.next()`
    // will return the same block
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
            if !matches!(block, Block::SectionHeader(_)) {
                return Err("pcapng: first block is not a section header".into());
            }
        }
        _ => return Err("Unexpected first block, or wrong file format".into()),
    }

    // count blocks in file
    let mut num_blocks = 0;

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                print_block_info(&block);
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

fn print_block_info(block: &PcapBlockOwned) {
    if let PcapBlockOwned::NG(b) = block {
        print_block_info_ng(b)
    }
}

fn print_block_info_ng(block: &Block) {
    match block {
        Block::SectionHeader(shb) => {
            println!("\t\tNew Section");
            println!("\t\t\tVersion: {}.{}", shb.major_version, shb.minor_version);
            if let Some(option) = shb.shb_hardware() {
                println!("\t\t\tshb_hardware: {}", option.unwrap_or("<invalid>"));
            }
            if let Some(option) = shb.shb_os() {
                println!("\t\t\tshb_os: {}", option.unwrap_or("<invalid>"));
            }
            if let Some(option) = shb.shb_userappl() {
                println!("\t\t\tshb_userappl: {}", option.unwrap_or("<invalid>"));
            }
        }
        Block::InterfaceDescription(idb) => {
            println!("\t\tNew interface");
            if let Some(option) = idb.if_name() {
                println!("\t\t\tif_name: {}", option.unwrap_or("<invalid>"));
            }
            if let Some(option) = idb.if_description() {
                println!("\t\t\tif_description: {}", option.unwrap_or("<invalid>"));
            }
            if let Some(option) = idb.if_os() {
                println!("\t\t\tif_os: {}", option.unwrap_or("<invalid>"));
            }
            if let Some(option) = idb.if_tsresol() {
                println!("\t\t\tif_tsresol: {}", option.unwrap_or(0));
            }
            if let Some(option) = idb.if_filter() {
                println!("\t\t\tif_filter: {}", option.unwrap_or("<invalid>"));
            }
            if let Some(option) = idb.if_tsoffset() {
                println!("\t\t\tif_tsoffset: {}", option.unwrap_or(0));
            }
        }
        _ => (),
    }
}

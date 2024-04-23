use nom::{
    combinator::complete,
    error::{make_error, ErrorKind},
    multi::{many0, many1},
    Err, IResult,
};

use crate::{PcapBlock, PcapError};

use super::*;

/// A Section (including all blocks) from a PcapNG file
pub struct Section<'a> {
    /// The list of blocks
    pub blocks: Vec<Block<'a>>,
    /// True if encoding is big-endian
    pub big_endian: bool,
}

impl<'a> Section<'a> {
    /// Returns the section header
    pub fn header(&self) -> Option<&SectionHeaderBlock> {
        if let Some(Block::SectionHeader(ref b)) = self.blocks.first() {
            Some(b)
        } else {
            None
        }
    }

    /// Returns an iterator over the section blocks
    pub fn iter(&'a self) -> SectionBlockIterator<'a> {
        SectionBlockIterator {
            section: self,
            index_block: 0,
        }
    }

    /// Returns an iterator over the interface description blocks
    pub fn iter_interfaces(&'a self) -> InterfaceBlockIterator<'a> {
        InterfaceBlockIterator {
            section: self,
            index_block: 0,
        }
    }
}

// Non-consuming iterator over blocks of a Section
pub struct SectionBlockIterator<'a> {
    section: &'a Section<'a>,
    index_block: usize,
}

impl<'a> Iterator for SectionBlockIterator<'a> {
    type Item = PcapBlock<'a>;

    fn next(&mut self) -> Option<PcapBlock<'a>> {
        let block = self.section.blocks.get(self.index_block);
        self.index_block += 1;
        block.map(PcapBlock::from)
    }
}

// Non-consuming iterator over interface description blocks of a Section
pub struct InterfaceBlockIterator<'a> {
    section: &'a Section<'a>,
    index_block: usize,
}

impl<'a> Iterator for InterfaceBlockIterator<'a> {
    type Item = &'a InterfaceDescriptionBlock<'a>;

    fn next(&mut self) -> Option<&'a InterfaceDescriptionBlock<'a>> {
        if self.index_block >= self.section.blocks.len() {
            return None;
        }
        for block in &self.section.blocks[self.index_block..] {
            self.index_block += 1;
            if let Block::InterfaceDescription(ref idb) = block {
                return Some(idb);
            }
        }
        None
    }
}

/// Parse any block from a section (little-endian)
pub fn parse_section_content_block_le(i: &[u8]) -> IResult<&[u8], Block, PcapError<&[u8]>> {
    let (rem, block) = parse_block_le(i)?;
    match block {
        Block::SectionHeader(_) => Err(Err::Error(make_error(i, ErrorKind::Tag))),
        _ => Ok((rem, block)),
    }
}

/// Parse any block from a section (big-endian)
pub fn parse_section_content_block_be(i: &[u8]) -> IResult<&[u8], Block, PcapError<&[u8]>> {
    let (rem, block) = parse_block_be(i)?;
    match block {
        Block::SectionHeader(_) => Err(Err::Error(make_error(i, ErrorKind::Tag))),
        _ => Ok((rem, block)),
    }
}

/// Parse one section (little or big endian)
pub fn parse_section(i: &[u8]) -> IResult<&[u8], Section, PcapError<&[u8]>> {
    let (rem, shb) = parse_sectionheaderblock(i)?;
    let big_endian = shb.big_endian();
    let (rem, mut b) = if big_endian {
        many0(complete(parse_section_content_block_be))(rem)?
    } else {
        many0(complete(parse_section_content_block_le))(rem)?
    };
    let mut blocks = Vec::with_capacity(b.len() + 1);
    blocks.push(Block::SectionHeader(shb));
    blocks.append(&mut b);
    let section = Section { blocks, big_endian };
    Ok((rem, section))
}

/// Parse multiple sections (little or big endian)
#[inline]
pub fn parse_sections(i: &[u8]) -> IResult<&[u8], Vec<Section>, PcapError<&[u8]>> {
    many1(complete(parse_section))(i)
}

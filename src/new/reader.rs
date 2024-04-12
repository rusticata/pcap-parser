use crate::PcapError;

use super::blocks::PcapBlockOwned;

pub type BlockResult<'a> = Result<(usize, PcapBlockOwned<&'a [u8]>), PcapError<&'a [u8]>>;

/// Streaming Iterator over pcap files
///
/// Implementors of this trait are usually based on a circular buffer, which means memory
/// usage is constant, and that it can be used to parse huge files or infinite streams.
/// However, this also means some care must be taken so no reference (for ex a pcap block) is
/// kept on the buffer before changing the buffer content.
///
/// Each call to `next` will return the next block,
/// and must be followed by call to `consume` to avoid reading the same data.
/// `consume` takes care of shifting data in the buffer if required, but does not refill it.
///
/// It is possible to read multiple blocks before consuming data.
/// Call `consume_noshift` instead of `consume`. To refill the buffer, first ensures that you do
/// not keep any reference over internal data (blocks or slices), and call `refill`.
///
/// To determine when a refill is needed, either test `next()` for an incomplete read. You can also
/// use `position` to implement a heuristic refill (for ex, when `position > capacity / 2`.
///
/// **The blocks already read, and underlying data, must be discarded before calling
/// `consume` or `refill`.** It is the caller's responsibility to call functions in the correct
/// order.
pub trait PcapReaderIterator {
    /// Get the next pcap block, if possible. Returns the number of bytes read and the block.
    ///
    /// The returned object is valid until `consume` or `refill` is called.
    fn next(&mut self) -> BlockResult;
    /// Consume data, and shift buffer if needed.
    ///
    /// If the position gets past the buffer's half, this will move the remaining data to the
    /// beginning of the buffer.
    ///
    /// **The blocks already read, and underlying data, must be discarded before calling
    /// this function.**
    fn consume(&mut self, offset: usize);
    /// Consume date, but do not change the buffer. Blocks already read are still valid.
    fn consume_noshift(&mut self, offset: usize);
    /// Get the number of consumed bytes
    fn consumed(&self) -> usize;
    /// Refill the internal buffer, shifting it if necessary.
    ///
    /// **The blocks already read, and underlying data, must be discarded before calling
    /// this function.**
    fn refill(&mut self) -> Result<(), PcapError<&[u8]>>;
    /// Get the position in the internal buffer. Can be used to determine if `refill` is required.
    fn position(&self) -> usize;
    /// Grow size of the internal buffer.
    fn grow(&mut self, new_size: usize) -> bool;
    /// Returns a slice with all the available data
    fn data(&self) -> &[u8];
    /// Returns true if underlying reader is exhausted
    ///
    /// Note that exhausted reader only means that next `refill` will not
    /// add any data, but there can still be data not consumed in the current buffer.
    fn reader_exhausted(&self) -> bool;
}

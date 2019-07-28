use std::convert::{AsMut, AsRef};
use std::ops;
use std::ops::{Deref, DerefMut};

/// A container for owned or borrowed data
pub enum Data<'a> {
    Owned(Vec<u8>),
    Borrowed(&'a [u8]),
}

/// A container for owned or borrowed mutable data
pub enum MutableData<'a> {
    Owned(Vec<u8>),
    Borrowed(&'a mut [u8]),
}

impl<'a> Data<'a> {
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        match self {
            &Data::Owned(ref o) => o.deref(),
            &Data::Borrowed(ref b) => b,
        }
    }
    #[inline]
    pub fn len(&self) -> usize {
        match self {
            &Data::Owned(ref o) => o.len(),
            &Data::Borrowed(ref b) => b.len(),
        }
    }
}

impl<'a> MutableData<'a> {
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        match self {
            &MutableData::Owned(ref o) => o.deref(),
            &MutableData::Borrowed(ref b) => b,
        }
    }
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            &mut MutableData::Owned(ref mut o) => o.deref_mut(),
            &mut MutableData::Borrowed(ref mut b) => b,
        }
    }
    #[inline]
    pub fn len(&self) -> usize {
        match self {
            &MutableData::Owned(ref o) => o.len(),
            &MutableData::Borrowed(ref b) => b.len(),
        }
    }
    /// Get an immutable version of the data
    pub fn to_immutable(self) -> Data<'a> {
        match self {
            MutableData::Owned(data) => Data::Owned(data),
            MutableData::Borrowed(data) => Data::Borrowed(data),
        }
    }
}

/* AsRef */

impl<'a> AsRef<[u8]> for Data<'a> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<'a> AsRef<[u8]> for MutableData<'a> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<'a> AsMut<[u8]> for MutableData<'a> {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

/* Index */

macro_rules! impl_index {
    ($t:ident, $index_t:ty, $output_t:ty) => {
        impl<'p> ops::Index<$index_t> for $t<'p> {
            type Output = $output_t;
            #[inline]
            fn index(&self, index: $index_t) -> &$output_t {
                &self.as_slice().index(index)
            }
        }
    };
}

macro_rules! impl_index_mut {
    ($t:ident, $index_t:ty, $output_t:ty) => {
        impl<'p> ops::IndexMut<$index_t> for $t<'p> {
            #[inline]
            fn index_mut(&mut self, index: $index_t) -> &mut $output_t {
                self.as_mut_slice().index_mut(index)
            }
        }
    };
}

impl_index!(Data, usize, u8);
impl_index!(Data, ops::Range<usize>, [u8]);
impl_index!(Data, ops::RangeTo<usize>, [u8]);
impl_index!(Data, ops::RangeFrom<usize>, [u8]);
impl_index!(Data, ops::RangeFull, [u8]);
impl_index!(Data, ops::RangeInclusive<usize>, [u8]);
impl_index!(Data, ops::RangeToInclusive<usize>, [u8]);

impl_index!(MutableData, usize, u8);
impl_index!(MutableData, ops::Range<usize>, [u8]);
impl_index!(MutableData, ops::RangeTo<usize>, [u8]);
impl_index!(MutableData, ops::RangeFrom<usize>, [u8]);
impl_index!(MutableData, ops::RangeFull, [u8]);
impl_index!(MutableData, ops::RangeInclusive<usize>, [u8]);
impl_index!(MutableData, ops::RangeToInclusive<usize>, [u8]);

impl_index_mut!(MutableData, usize, u8);
impl_index_mut!(MutableData, ops::Range<usize>, [u8]);
impl_index_mut!(MutableData, ops::RangeTo<usize>, [u8]);
impl_index_mut!(MutableData, ops::RangeFrom<usize>, [u8]);
impl_index_mut!(MutableData, ops::RangeFull, [u8]);
impl_index_mut!(MutableData, ops::RangeInclusive<usize>, [u8]);
impl_index_mut!(MutableData, ops::RangeToInclusive<usize>, [u8]);

/* ******************* */

#[doc(hidden)]
#[macro_export]
macro_rules! read_u32_e {
    ($data:expr, $endian:expr) => {
        if $endian {
            let data = $data;
            (data[0] as u32) << 24
                | (data[1] as u32) << 16
                | (data[2] as u32) << 8
                | (data[3] as u32)
        } else {
            let data = $data;
            (data[3] as u32) << 24
                | (data[2] as u32) << 16
                | (data[1] as u32) << 8
                | (data[0] as u32)
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! write_u32_e {
    ($data:expr, $val:expr, $endian:expr) => {
        let data = $data;
        let v = $val;
        let v1: u8 = ((v >> 24) & 0xff) as u8;
        let v2: u8 = ((v >> 16) & 0xff) as u8;
        let v3: u8 = ((v >> 8) & 0xff) as u8;
        let v4: u8 = ((v) & 0xff) as u8;
        if $endian {
            data[0] = v1;
            data[1] = v2;
            data[2] = v3;
            data[3] = v4;
        } else {
            data[0] = v4;
            data[1] = v3;
            data[2] = v2;
            data[3] = v1;
        }
    };
}

/// Align slice to the next multiple of n bytes
/// Valid only if n is a power of 2
#[doc(hidden)]
#[macro_export]
macro_rules! align_n2 {
    ($x:expr, $n:expr) => {
        ($x + ($n - 1)) & !($n - 1)
    };
}

/// Align slice to the next multiple of 4 bytes
#[doc(hidden)]
#[macro_export]
macro_rules! align32 {
    ($x:expr) => {
        align_n2!($x, 4)
    };
}

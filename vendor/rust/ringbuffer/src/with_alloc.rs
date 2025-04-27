use core::ops::{Index, IndexMut};

use crate::ringbuffer_trait::{RingBuffer, RingBufferExt, RingBufferRead, RingBufferWrite};

extern crate alloc;
// We need vecs so depend on alloc
use alloc::vec::Vec;
use core::iter::FromIterator;
use core::mem;
use core::mem::MaybeUninit;

/// The `AllocRingBuffer` is a `RingBufferExt` which is based on a Vec. This means it allocates at runtime
/// on the heap, and therefore needs the [`alloc`] crate. This struct and therefore the dependency on
/// alloc can be disabled by disabling the `alloc` (default) feature.
///
/// # Example
/// ```
/// use ringbuffer::{AllocRingBuffer, RingBuffer, RingBufferExt, RingBufferWrite};
///
/// let mut buffer = AllocRingBuffer::with_capacity(2);
///
/// // First entry of the buffer is now 5.
/// buffer.push(5);
///
/// // The last item we pushed is 5
/// assert_eq!(buffer.get(-1), Some(&5));
///
/// // Second entry is now 42.
/// buffer.push(42);
///
/// assert_eq!(buffer.peek(), Some(&5));
/// assert!(buffer.is_full());
///
/// // Because capacity is reached the next push will be the first item of the buffer.
/// buffer.push(1);
/// assert_eq!(buffer.to_vec(), vec![42, 1]);
/// ```
#[derive(Debug)]
pub struct AllocRingBuffer<T> {
    buf: Vec<MaybeUninit<T>>,
    capacity: usize,
    readptr: usize,
    writeptr: usize,
}

impl<T> Drop for AllocRingBuffer<T> {
    fn drop(&mut self) {
        self.drain().for_each(drop);
    }
}

impl<T: Clone> Clone for AllocRingBuffer<T> {
    fn clone(&self) -> Self {
        let mut new = Self::with_capacity(self.capacity);
        self.iter().cloned().for_each(|i| new.push(i));
        new
    }
}
impl<T: PartialEq> PartialEq for AllocRingBuffer<T> {
    fn eq(&self, other: &Self) -> bool {
        self.capacity == other.capacity
            && self.len() == other.len()
            && self.iter().zip(other.iter()).all(|(a, b)| a == b)
    }
}

impl<T: Eq + PartialEq> Eq for AllocRingBuffer<T> {}

/// The capacity of a `RingBuffer` created by new or default (`1024`).
// must be a power of 2
pub const RINGBUFFER_DEFAULT_CAPACITY: usize = 1024;

unsafe impl<T> RingBufferExt<T> for AllocRingBuffer<T> {
    impl_ringbuffer_ext!(
        get_unchecked,
        get_unchecked_mut,
        readptr,
        writeptr,
        crate::mask
    );

    #[inline]
    fn fill_with<F: FnMut() -> T>(&mut self, mut f: F) {
        self.clear();

        self.readptr = 0;
        self.writeptr = self.capacity;
        self.buf.fill_with(|| MaybeUninit::new(f()));
        while self.buf.len() < self.capacity {
            self.buf.push(MaybeUninit::new(f()));
        }
    }
}

impl<T> RingBufferRead<T> for AllocRingBuffer<T> {
    fn dequeue(&mut self) -> Option<T> {
        if self.is_empty() {
            None
        } else {
            let index = crate::mask(self.capacity, self.readptr);
            let res = mem::replace(&mut self.buf[index], MaybeUninit::uninit());
            self.readptr += 1;

            // Safety: the fact that we got this maybeuninit from the buffer (with mask) means that
            // it's initialized. If it wasn't the is_empty call would have caught it. Values
            // are always initialized when inserted so this is safe.
            unsafe { Some(res.assume_init()) }
        }
    }

    impl_ringbuffer_read!();
}

impl<T> Extend<T> for AllocRingBuffer<T> {
    fn extend<A: IntoIterator<Item = T>>(&mut self, iter: A) {
        let iter = iter.into_iter();

        for i in iter {
            self.push(i);
        }
    }
}

impl<T> RingBufferWrite<T> for AllocRingBuffer<T> {
    #[inline]
    fn push(&mut self, value: T) {
        if self.is_full() {
            let previous_value = mem::replace(
                &mut self.buf[crate::mask(self.capacity, self.readptr)],
                MaybeUninit::uninit(),
            );
            // make sure we drop whatever is being overwritten
            // SAFETY: the buffer is full, so this must be initialized
            //       : also, index has been masked
            // make sure we drop because it won't happen automatically
            unsafe {
                drop(previous_value.assume_init());
            }

            self.readptr += 1;
        }

        let index = crate::mask(self.capacity, self.writeptr);

        if index >= self.buf.len() {
            // initializing the maybeuninit when values are inserted/pushed
            self.buf.push(MaybeUninit::new(value));
        } else {
            // initializing the maybeuninit when values are inserted/pushed
            self.buf[index] = MaybeUninit::new(value);
        }

        self.writeptr += 1;
    }
}

impl<T> RingBuffer<T> for AllocRingBuffer<T> {
    #[inline]
    unsafe fn ptr_capacity(rb: *const Self) -> usize {
        (*rb).capacity
    }

    impl_ringbuffer!(readptr, writeptr);
}

impl<T> AllocRingBuffer<T> {
    /// Creates a `AllocRingBuffer` with a certain capacity. This capacity is fixed.
    /// for this ringbuffer to work, cap must be a power of two and greater than zero.
    #[inline]
    pub fn with_capacity_unchecked(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
            capacity: cap,
            readptr: 0,
            writeptr: 0,
        }
    }

    /// Creates a `AllocRingBuffer` with a certain capacity. The actual capacity is the input to the
    /// function raised to the power of two (effectively the input is the log2 of the actual capacity)
    #[inline]
    pub fn with_capacity_power_of_2(cap_power_of_two: usize) -> Self {
        Self::with_capacity_unchecked(1 << cap_power_of_two)
    }

    #[inline]
    /// Creates a `AllocRingBuffer` with a certain capacity. The capacity must be a power of two.
    /// # Panics
    /// Panics when capacity is zero or not a power of two
    pub fn with_capacity(cap: usize) -> Self {
        assert_ne!(cap, 0, "Capacity must be greater than 0");
        assert!(cap.is_power_of_two(), "Capacity must be a power of two");

        Self::with_capacity_unchecked(cap)
    }

    /// Creates an `AllocRingBuffer` with a capacity of [`RINGBUFFER_DEFAULT_CAPACITY`].
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Get a reference from the buffer without checking it is initialized.
/// Caller must be sure the index is in bounds, or this will panic.
#[inline]
unsafe fn get_unchecked<'a, T>(rb: *const AllocRingBuffer<T>, index: usize) -> &'a T {
    let p = &(*rb).buf[index];
    // Safety: caller makes sure the index is in bounds for the ringbuffer.
    // All in bounds values in the ringbuffer are initialized
    p.assume_init_ref()
}

/// Get a mut reference from the buffer without checking it is initialized.
/// Caller must be sure the index is in bounds, or this will panic.
#[inline]
unsafe fn get_unchecked_mut<T>(rb: *mut AllocRingBuffer<T>, index: usize) -> *mut T {
    let p = (*rb).buf.as_mut_ptr().add(index);

    // Safety: caller makes sure the index is in bounds for the ringbuffer.
    // All in bounds values in the ringbuffer are initialized
    p.cast()
}

impl<RB> FromIterator<RB> for AllocRingBuffer<RB> {
    fn from_iter<T: IntoIterator<Item = RB>>(iter: T) -> Self {
        let mut res = Self::default();
        for i in iter {
            res.push(i);
        }

        res
    }
}

impl<T> Default for AllocRingBuffer<T> {
    /// Creates a buffer with a capacity of [`crate::RINGBUFFER_DEFAULT_CAPACITY`].
    #[inline]
    fn default() -> Self {
        Self {
            buf: Vec::with_capacity(RINGBUFFER_DEFAULT_CAPACITY),
            capacity: RINGBUFFER_DEFAULT_CAPACITY,
            readptr: 0,
            writeptr: 0,
        }
    }
}

impl<T> Index<isize> for AllocRingBuffer<T> {
    type Output = T;

    fn index(&self, index: isize) -> &Self::Output {
        self.get(index).expect("index out of bounds")
    }
}

impl<T> IndexMut<isize> for AllocRingBuffer<T> {
    fn index_mut(&mut self, index: isize) -> &mut Self::Output {
        self.get_mut(index).expect("index out of bounds")
    }
}

#[cfg(test)]
mod tests {
    use super::alloc::vec::Vec;
    use crate::{
        AllocRingBuffer, RingBuffer, RingBufferExt, RingBufferWrite, RINGBUFFER_DEFAULT_CAPACITY,
    };

    #[test]
    fn test_default() {
        let b: AllocRingBuffer<u32> = AllocRingBuffer::default();
        assert_eq!(RINGBUFFER_DEFAULT_CAPACITY, b.capacity());
        assert_eq!(RINGBUFFER_DEFAULT_CAPACITY, b.buf.capacity());
        assert_eq!(b.capacity, b.capacity());
        assert_eq!(b.buf.len(), b.len());
        assert_eq!(0, b.writeptr);
        assert_eq!(0, b.readptr);
        assert!(b.is_empty());
        assert!(b.buf.is_empty());
        assert_eq!(0, b.iter().count());
        assert_eq!(
            Vec::<u32>::with_capacity(RINGBUFFER_DEFAULT_CAPACITY),
            b.to_vec()
        );
    }

    #[test]
    fn test_default_capacity_constant() {
        // This is to prevent accidentally changing it.
        assert_eq!(RINGBUFFER_DEFAULT_CAPACITY, 1024)
    }

    #[test]
    fn test_with_capacity_power_of_two() {
        let b = AllocRingBuffer::<i32>::with_capacity_power_of_2(2);
        assert_eq!(b.capacity, 4);
    }

    #[test]
    #[should_panic]
    fn test_with_capacity_no_power_of_two() {
        let _ = AllocRingBuffer::<i32>::with_capacity(10);
    }

    #[test]
    #[should_panic]
    fn test_index_zero_length() {
        let b = AllocRingBuffer::<i32>::with_capacity(2);
        let _ = b[2];
    }

    #[test]
    fn test_extend() {
        let mut buf = AllocRingBuffer::<u8>::with_capacity(4);
        (0..4).for_each(|_| buf.push(0));

        let new_data = [0, 1, 2];
        buf.extend(new_data);

        let expected = [0, 0, 1, 2];

        for i in 0..4 {
            let actual = buf[i as isize];
            let expected = expected[i];
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn test_extend_with_overflow() {
        let mut buf = AllocRingBuffer::<u8>::with_capacity(8);
        (0..8).for_each(|_| buf.push(0));

        let new_data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        buf.extend(new_data);

        let expected = [2, 3, 4, 5, 6, 7, 8, 9];

        for i in 0..8 {
            let actual = buf[i as isize];
            let expected = expected[i];
            assert_eq!(actual, expected);
        }
    }
}

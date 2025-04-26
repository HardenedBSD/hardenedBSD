use crate::{RingBuffer, RingBufferExt, RingBufferRead, RingBufferWrite};
use core::iter::FromIterator;
use core::mem;
use core::mem::MaybeUninit;
use core::ops::{Index, IndexMut};

/// The `ConstGenericRingBuffer` struct is a `RingBuffer` implementation which does not require `alloc` but
/// uses const generics instead.
///
/// [`ConstGenericRingBuffer`] allocates the ringbuffer on the stack, and the size must be known at
/// compile time through const-generics.
///
/// # Example
/// ```
/// use ringbuffer::{ConstGenericRingBuffer, RingBuffer, RingBufferExt, RingBufferWrite};
///
/// let mut buffer = ConstGenericRingBuffer::<_, 2>::new();
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
pub struct ConstGenericRingBuffer<T, const CAP: usize> {
    buf: [MaybeUninit<T>; CAP],
    readptr: usize,
    writeptr: usize,
}

impl<T, const CAP: usize> Drop for ConstGenericRingBuffer<T, CAP> {
    fn drop(&mut self) {
        self.drain().for_each(drop);
    }
}

impl<T: Clone, const CAP: usize> Clone for ConstGenericRingBuffer<T, CAP> {
    fn clone(&self) -> Self {
        let mut new = ConstGenericRingBuffer::<T, CAP>::new();
        self.iter().cloned().for_each(|i| new.push(i));
        new
    }
}

// We need to manually implement PartialEq because MaybeUninit isn't PartialEq
impl<T: PartialEq, const CAP: usize> PartialEq for ConstGenericRingBuffer<T, CAP> {
    fn eq(&self, other: &Self) -> bool {
        if self.len() == other.len() {
            for (a, b) in self.iter().zip(other.iter()) {
                if a != b {
                    return false;
                }
            }
            true
        } else {
            false
        }
    }
}

impl<T: PartialEq, const CAP: usize> Eq for ConstGenericRingBuffer<T, CAP> {}

impl<T, const CAP: usize> ConstGenericRingBuffer<T, CAP> {
    /// Creates a const generic ringbuffer, size is passed as a const generic.
    #[inline]
    pub const fn new() -> Self {
        assert!(CAP != 0, "Capacity is not allowed to be zero");
        assert!(CAP.is_power_of_two(), "Capacity must be a power of two");

        Self {
            buf: unsafe { MaybeUninit::uninit().assume_init() },
            writeptr: 0,
            readptr: 0,
        }
    }
}

/// Get a reference from the buffer without checking it is initialized
/// Caller MUST be sure this index is initialized, or undefined behavior will happen
unsafe fn get_unchecked<'a, T, const N: usize>(
    rb: *const ConstGenericRingBuffer<T, N>,
    index: usize,
) -> &'a T {
    (*rb).buf[index]
        .as_ptr()
        .as_ref()
        .expect("const array ptr shouldn't be null!")
}

/// Get a mutable reference from the buffer without checking it is initialized
/// Caller MUST be sure this index is initialized, or undefined behavior will happen
unsafe fn get_unchecked_mut<T, const N: usize>(
    rb: *mut ConstGenericRingBuffer<T, N>,
    index: usize,
) -> *mut T {
    (*rb).buf[index]
        .as_mut_ptr()
        .as_mut()
        .expect("const array ptr shouldn't be null!")
}

impl<T, const CAP: usize> RingBufferRead<T> for ConstGenericRingBuffer<T, CAP> {
    fn dequeue(&mut self) -> Option<T> {
        if self.is_empty() {
            None
        } else {
            let index = crate::mask(CAP, self.readptr);
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

impl<T, const CAP: usize> Extend<T> for ConstGenericRingBuffer<T, CAP> {
    fn extend<A: IntoIterator<Item = T>>(&mut self, iter: A) {
        let iter = iter.into_iter();

        for i in iter {
            self.push(i);
        }
    }
}

impl<T, const CAP: usize> RingBufferWrite<T> for ConstGenericRingBuffer<T, CAP> {
    #[inline]
    fn push(&mut self, value: T) {
        if self.is_full() {
            let previous_value = mem::replace(
                &mut self.buf[crate::mask(CAP, self.readptr)],
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
        let index = crate::mask(CAP, self.writeptr);
        self.buf[index] = MaybeUninit::new(value);
        self.writeptr += 1;
    }
}

unsafe impl<T, const CAP: usize> RingBufferExt<T> for ConstGenericRingBuffer<T, CAP> {
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
        self.writeptr = CAP;
        self.buf.fill_with(|| MaybeUninit::new(f()));
    }
}

impl<T, const CAP: usize> RingBuffer<T> for ConstGenericRingBuffer<T, CAP> {
    #[inline]
    #[cfg(not(tarpaulin_include))]
    unsafe fn ptr_capacity(_: *const Self) -> usize {
        CAP
    }

    impl_ringbuffer!(readptr, writeptr);
}

impl<T, const CAP: usize> Default for ConstGenericRingBuffer<T, CAP> {
    /// Creates a buffer with a capacity specified through the Cap type parameter.
    /// # Panics
    /// Panics if `CAP` is 0 or not a power of two
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<RB, const CAP: usize> FromIterator<RB> for ConstGenericRingBuffer<RB, CAP> {
    fn from_iter<T: IntoIterator<Item = RB>>(iter: T) -> Self {
        let mut res = Self::default();
        for i in iter {
            res.push(i);
        }

        res
    }
}

impl<T, const CAP: usize> Index<isize> for ConstGenericRingBuffer<T, CAP> {
    type Output = T;

    fn index(&self, index: isize) -> &Self::Output {
        self.get(index).expect("index out of bounds")
    }
}

impl<T, const CAP: usize> IndexMut<isize> for ConstGenericRingBuffer<T, CAP> {
    fn index_mut(&mut self, index: isize) -> &mut Self::Output {
        self.get_mut(index).expect("index out of bounds")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic]
    fn test_no_empty() {
        let _ = ConstGenericRingBuffer::<u32, 0>::new();
    }

    #[test]
    #[should_panic]
    fn test_with_capacity_no_power_of_two() {
        let _ = ConstGenericRingBuffer::<i32, 10>::new();
    }

    #[test]
    #[should_panic]
    fn test_index_zero_length() {
        let b = ConstGenericRingBuffer::<i32, 2>::new();
        let _ = b[2];
    }

    #[test]
    fn test_extend() {
        let mut buf = ConstGenericRingBuffer::<u8, 4>::new();
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
        let mut buf = ConstGenericRingBuffer::<u8, 8>::new();
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

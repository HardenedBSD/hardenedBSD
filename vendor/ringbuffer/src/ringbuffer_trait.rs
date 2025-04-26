use core::ops::{Index, IndexMut};

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::iter::FromIterator;

/// `RingBuffer` is a trait defining the standard interface for all `RingBuffer`
/// implementations ([`AllocRingBuffer`](crate::AllocRingBuffer), [`ConstGenericRingBuffer`](crate::ConstGenericRingBuffer))
///
/// This trait is not object safe, so can't be used dynamically. However it is possible to
/// define a generic function over types implementing `RingBuffer`.
///
/// Most actual functionality of ringbuffers is contained in the extension traits [`RingBufferExt`], [`RingBufferRead`] and [`RingBufferWrite`]
pub trait RingBuffer<T>: Sized {
    /// Returns the length of the internal buffer.
    /// This length grows up to the capacity and then stops growing.
    /// This is because when the length is reached, new items are appended at the start.
    fn len(&self) -> usize {
        // Safety: self is a RingBuffer
        unsafe { Self::ptr_len(self) }
    }

    /// Raw pointer version of len
    /// Safety: ONLY SAFE WHEN self is a *mut to to an implementor of RingBuffer
    #[doc(hidden)]
    unsafe fn ptr_len(rb: *const Self) -> usize;

    /// Returns true if the buffer is entirely empty.
    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns true when the length of the ringbuffer equals the capacity. This happens whenever
    /// more elements than capacity have been pushed to the buffer.
    #[inline]
    fn is_full(&self) -> bool {
        self.len() == self.capacity()
    }

    /// Returns the capacity of the buffer.
    fn capacity(&self) -> usize {
        // Safety: self is a RingBuffer
        unsafe { Self::ptr_capacity(self) }
    }

    /// Raw pointer version of capacity.
    /// Safety: ONLY SAFE WHEN self is a *mut to to an implementor of RingBuffer
    #[doc(hidden)]
    unsafe fn ptr_capacity(rb: *const Self) -> usize;
}

/// Defines behaviour for ringbuffers which allow for writing to the end of them (as a queue).
/// For arbitrary buffer access however, [`RingBufferExt`] is necessary.
pub trait RingBufferWrite<T>: RingBuffer<T> + Extend<T> {
    /// Pushes a value onto the buffer. Cycles around if capacity is reached.
    fn push(&mut self, value: T);

    /// alias for [`push`](RingBufferWrite::push), forming a more natural counterpart to [`dequeue`](RingBufferRead::dequeue)
    fn enqueue(&mut self, value: T) {
        self.push(value)
    }
}

/// Defines behaviour for ringbuffers which allow for reading from the start of them (as a queue).
/// For arbitrary buffer access however, [`RingBufferExt`] is necessary.
pub trait RingBufferRead<T>: RingBuffer<T> {
    /// dequeues the top item off the ringbuffer, and moves this item out.
    fn dequeue(&mut self) -> Option<T>;

    /// dequeues the top item off the queue, but does not return it. Instead it is dropped.
    /// If the ringbuffer is empty, this function is a nop.
    fn skip(&mut self);

    /// Returns an iterator over the elements in the ringbuffer,
    /// dequeueing elements as they are iterated over.
    ///
    /// ```
    /// use ringbuffer::{AllocRingBuffer, RingBufferWrite, RingBufferRead, RingBuffer};
    ///
    /// let mut rb = AllocRingBuffer::with_capacity(16);
    /// for i in 0..8 {
    ///     rb.push(i);
    /// }
    ///
    /// assert_eq!(rb.len(), 8);
    ///
    /// for i in rb.drain() {
    ///     // prints the numbers 0 through 8
    ///     println!("{}", i);
    /// }
    ///
    /// // No elements remain
    /// assert_eq!(rb.len(), 0);
    ///
    /// ```
    fn drain(&mut self) -> RingBufferDrainingIterator<T, Self> {
        RingBufferDrainingIterator::new(self)
    }
}

/// Defines behaviour for ringbuffers which allow them to be used as a general purpose buffer.
/// With this trait, arbitrary access of elements in the buffer is possible.
///
/// # Safety
/// Implementing this implies that the ringbuffer upholds some safety
/// guarantees, such as returning a different value from `get_mut` any
/// for every different index passed in. See the exact requirements
/// in the safety comment on the next function of the mutable Iterator
/// implementation, since these safety guarantees are necessary for
/// [`iter_mut`] to work
pub unsafe trait RingBufferExt<T>:
    RingBuffer<T>
    + RingBufferRead<T>
    + RingBufferWrite<T>
    + Index<isize, Output = T>
    + IndexMut<isize>
    + FromIterator<T>
{
    /// Sets every element in the ringbuffer to the value returned by f.
    fn fill_with<F: FnMut() -> T>(&mut self, f: F);

    /// Sets every element in the ringbuffer to it's default value
    fn fill_default(&mut self)
    where
        T: Default,
    {
        self.fill_with(Default::default);
    }

    /// Sets every element in the ringbuffer to `value`
    fn fill(&mut self, value: T)
    where
        T: Clone,
    {
        self.fill_with(|| value.clone());
    }

    /// Empties the buffer entirely. Sets the length to 0 but keeps the capacity allocated.
    fn clear(&mut self);

    /// Gets a value relative to the current index. 0 is the next index to be written to with push.
    /// -1 and down are the last elements pushed and 0 and up are the items that were pushed the longest ago.
    fn get(&self, index: isize) -> Option<&T>;

    /// Gets a value relative to the current index mutably. 0 is the next index to be written to with push.
    /// -1 and down are the last elements pushed and 0 and up are the items that were pushed the longest ago.
    #[inline]
    fn get_mut(&mut self, index: isize) -> Option<&mut T> {
        // Safety: self is a RingBuffer
        unsafe { Self::ptr_get_mut(self, index).map(|i| &mut *i) }
    }

    /// same as [`get_mut`](RingBufferExt::get_mut) but on raw pointers.
    /// Safety: ONLY SAFE WHEN self is a *mut to to an implementor of RingBufferExt
    #[doc(hidden)]
    unsafe fn ptr_get_mut(rb: *mut Self, index: isize) -> Option<*mut T>;

    /// Gets a value relative to the start of the array (rarely useful, usually you want [`Self::get`])
    fn get_absolute(&self, index: usize) -> Option<&T>;

    /// Gets a value mutably relative to the start of the array (rarely useful, usually you want [`Self::get_mut`])
    fn get_absolute_mut(&mut self, index: usize) -> Option<&mut T>;

    /// Returns the value at the current index.
    /// This is the value that will be overwritten by the next push and also the value pushed
    /// the longest ago. (alias of [`Self::front`])
    #[inline]
    fn peek(&self) -> Option<&T> {
        self.front()
    }

    /// Returns the value at the front of the queue.
    /// This is the value that will be overwritten by the next push and also the value pushed
    /// the longest ago.
    /// (alias of peek)
    #[inline]
    fn front(&self) -> Option<&T> {
        self.get(0)
    }

    /// Returns a mutable reference to the value at the back of the queue.
    /// This is the value that will be overwritten by the next push.
    /// (alias of peek)
    #[inline]
    fn front_mut(&mut self) -> Option<&mut T> {
        self.get_mut(0)
    }

    /// Returns the value at the back of the queue.
    /// This is the item that was pushed most recently.
    #[inline]
    fn back(&self) -> Option<&T> {
        self.get(-1)
    }

    /// Returns a mutable reference to the value at the back of the queue.
    /// This is the item that was pushed most recently.
    #[inline]
    fn back_mut(&mut self) -> Option<&mut T> {
        self.get_mut(-1)
    }

    /// Creates a mutable iterator over the buffer starting from the item pushed the longest ago,
    /// and ending at the element most recently pushed.
    #[inline]
    fn iter_mut(&mut self) -> RingBufferMutIterator<T, Self> {
        RingBufferMutIterator::new(self)
    }

    /// Creates an iterator over the buffer starting from the item pushed the longest ago,
    /// and ending at the element most recently pushed.
    #[inline]
    fn iter(&self) -> RingBufferIterator<T, Self> {
        RingBufferIterator::new(self)
    }

    /// Converts the buffer to a vector. This Copies all elements in the ringbuffer.
    #[cfg(feature = "alloc")]
    fn to_vec(&self) -> Vec<T>
    where
        T: Clone,
    {
        self.iter().cloned().collect()
    }

    /// Returns true if elem is in the ringbuffer.
    fn contains(&self, elem: &T) -> bool
    where
        T: PartialEq,
    {
        self.iter().any(|i| i == elem)
    }
}

mod iter {
    use crate::{RingBufferExt, RingBufferRead};
    use core::iter::FusedIterator;
    use core::marker::PhantomData;
    use core::ptr::NonNull;

    /// `RingBufferIterator` holds a reference to a `RingBufferExt` and iterates over it. `index` is the
    /// current iterator position.
    pub struct RingBufferIterator<'rb, T, RB: RingBufferExt<T>> {
        obj: &'rb RB,
        len: usize,
        index: usize,
        phantom: PhantomData<T>,
    }

    impl<'rb, T, RB: RingBufferExt<T>> RingBufferIterator<'rb, T, RB> {
        #[inline]
        pub fn new(obj: &'rb RB) -> Self {
            Self {
                obj,
                len: obj.len(),
                index: 0,
                phantom: PhantomData::default(),
            }
        }
    }

    impl<'rb, T: 'rb, RB: RingBufferExt<T>> Iterator for RingBufferIterator<'rb, T, RB> {
        type Item = &'rb T;

        #[inline]
        fn next(&mut self) -> Option<Self::Item> {
            if self.index < self.len {
                let res = self.obj.get(self.index as isize);
                self.index += 1;
                res
            } else {
                None
            }
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (self.len, Some(self.len))
        }
    }

    impl<'rb, T: 'rb, RB: RingBufferExt<T>> FusedIterator for RingBufferIterator<'rb, T, RB> {}

    impl<'rb, T: 'rb, RB: RingBufferExt<T>> ExactSizeIterator for RingBufferIterator<'rb, T, RB> {}

    impl<'rb, T: 'rb, RB: RingBufferExt<T>> DoubleEndedIterator for RingBufferIterator<'rb, T, RB> {
        #[inline]
        fn next_back(&mut self) -> Option<Self::Item> {
            if self.len > 0 && self.index < self.len {
                let res = self.obj.get((self.len - 1) as isize);
                self.len -= 1;
                res
            } else {
                None
            }
        }
    }

    /// `RingBufferMutIterator` holds a reference to a `RingBufferExt` and iterates over it. `index` is the
    /// current iterator position.
    ///
    /// WARNING: NEVER ACCESS THE `obj` FIELD OUTSIDE OF NEXT. It's private on purpose, and
    /// can technically be accessed in the same module. However, this breaks the safety of `next()`
    pub struct RingBufferMutIterator<'rb, T, RB: RingBufferExt<T>> {
        obj: NonNull<RB>,
        index: usize,
        len: usize,
        phantom: PhantomData<&'rb mut T>,
    }

    impl<'rb, T, RB: RingBufferExt<T>> RingBufferMutIterator<'rb, T, RB> {
        pub fn new(obj: &'rb mut RB) -> Self {
            Self {
                len: obj.len(),
                obj: NonNull::from(obj),
                index: 0,
                phantom: PhantomData::default(),
            }
        }
    }

    impl<'rb, T: 'rb, RB: RingBufferExt<T> + 'rb> FusedIterator for RingBufferMutIterator<'rb, T, RB> {}

    impl<'rb, T: 'rb, RB: RingBufferExt<T> + 'rb> ExactSizeIterator
        for RingBufferMutIterator<'rb, T, RB>
    {
    }

    impl<'rb, T: 'rb, RB: RingBufferExt<T> + 'rb> DoubleEndedIterator
        for RingBufferMutIterator<'rb, T, RB>
    {
        #[inline]
        fn next_back(&mut self) -> Option<Self::Item> {
            if self.len > 0 && self.index < self.len {
                self.len -= 1;
                let res = unsafe { RB::ptr_get_mut(self.obj.as_ptr(), self.len as isize) };
                res.map(|i| unsafe { &mut *i })
            } else {
                None
            }
        }
    }

    impl<'rb, T, RB: RingBufferExt<T> + 'rb> Iterator for RingBufferMutIterator<'rb, T, RB> {
        type Item = &'rb mut T;

        fn next(&mut self) -> Option<Self::Item> {
            if self.index < self.len {
                let res = unsafe { RB::ptr_get_mut(self.obj.as_ptr(), self.index as isize) };
                self.index += 1;
                // Safety: ptr_get_mut always returns a valid pointer
                res.map(|i| unsafe { &mut *i })
            } else {
                None
            }
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (self.len, Some(self.len))
        }
    }

    /// `RingBufferMutIterator` holds a reference to a `RingBufferRead` and iterates over it. `index` is the
    /// current iterator position.
    pub struct RingBufferDrainingIterator<'rb, T, RB: RingBufferRead<T>> {
        obj: &'rb mut RB,
        phantom: PhantomData<T>,
    }

    impl<'rb, T, RB: RingBufferRead<T>> RingBufferDrainingIterator<'rb, T, RB> {
        #[inline]
        pub fn new(obj: &'rb mut RB) -> Self {
            Self {
                obj,
                phantom: PhantomData::default(),
            }
        }
    }

    impl<'rb, T, RB: RingBufferRead<T>> Iterator for RingBufferDrainingIterator<'rb, T, RB> {
        type Item = T;

        fn next(&mut self) -> Option<T> {
            self.obj.dequeue()
        }
    }
}

pub use iter::{RingBufferDrainingIterator, RingBufferIterator, RingBufferMutIterator};

/// Implement various functions on implementors of [`RingBufferRead`].
/// This is to avoid duplicate code.
macro_rules! impl_ringbuffer_read {
    () => {
        #[inline]
        fn skip(&mut self) {
            let _ = self.dequeue().map(drop);
        }
    };
}

/// Implement various functions on implementors of [`RingBuffer`].
/// This is to avoid duplicate code.
macro_rules! impl_ringbuffer {
    ($readptr: ident, $writeptr: ident) => {
        #[inline]
        unsafe fn ptr_len(rb: *const Self) -> usize {
            (*rb).$writeptr - (*rb).$readptr
        }
    };
}

/// Implement various functions on implementors of [`RingBufferExt`].
/// This is to avoid duplicate code.
macro_rules! impl_ringbuffer_ext {
    ($get_unchecked: ident, $get_unchecked_mut: ident, $readptr: ident, $writeptr: ident, $mask: expr) => {
        #[inline]
        fn get(&self, index: isize) -> Option<&T> {
            use core::ops::Not;
            self.is_empty().not().then(move || {
                let index_from_readptr = if index >= 0 {
                    index
                } else {
                    self.len() as isize + index
                };

                let normalized_index =
                    self.$readptr as isize + index_from_readptr.rem_euclid(self.len() as isize);

                unsafe {
                    // SAFETY: index has been modulo-ed to be within range
                    // to be within bounds
                    $get_unchecked(
                        self,
                        $crate::mask(self.capacity(), normalized_index as usize),
                    )
                }
            })
        }

        #[inline]
        unsafe fn ptr_get_mut<'a>(rb: *mut Self, index: isize) -> Option<*mut T> {
            (Self::ptr_len(rb) != 0).then(move || {
                let index_from_readptr = if index >= 0 {
                    index
                } else {
                    Self::ptr_len(rb) as isize + index
                };

                let normalized_index = (*rb).$readptr as isize
                    + index_from_readptr.rem_euclid(Self::ptr_len(rb) as isize);

                unsafe {
                    // SAFETY: index has been modulo-ed to be within range
                    // to be within bounds
                    $get_unchecked_mut(
                        rb,
                        $crate::mask(Self::ptr_capacity(rb), normalized_index as usize),
                    )
                }
            })
        }

        #[inline]
        fn get_absolute(&self, index: usize) -> Option<&T> {
            let read = $mask(self.capacity(), self.$readptr);
            let write = $mask(self.capacity(), self.$writeptr);
            (index >= read && index < write).then(|| unsafe {
                // SAFETY: index has been checked against $mask to be within bounds
                $get_unchecked(self, index)
            })
        }

        #[inline]
        fn get_absolute_mut(&mut self, index: usize) -> Option<&mut T> {
            (index >= $mask(self.capacity(), self.$readptr)
                && index < $mask(self.capacity(), self.$writeptr))
            .then(move || unsafe {
                // SAFETY: index has been checked against $mask to be within bounds
                &mut *$get_unchecked_mut(self, index)
            })
        }

        #[inline]
        fn clear(&mut self) {
            for i in self.drain() {
                drop(i);
            }

            self.$readptr = 0;
            self.$writeptr = 0;
        }
    };
}

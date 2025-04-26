use std::{iter, num::NonZeroUsize};

pub trait IteratorExt: Iterator {
    fn deinterleave<T>(self, n: NonZeroUsize) -> Vec<T>
    where
        T: Default + Extend<<Self as Iterator>::Item>,
        Self: Sized,
    {
        let mut containers = Vec::with_capacity(n.into());
        for _ in 0..n.into() {
            // Too bad there's no standard trait that defines with_capacity, or
            // we could use that here with Iterator::size_hint.
            containers.push(T::default());
        }
        for (i, item) in self.enumerate() {
            containers[i % n].extend(iter::once(item));
        }
        containers
    }
}

impl<T> IteratorExt for T where T: Iterator {}

#[cfg(test)]
mod t {
    // NB: we can eliminate nonzero if this issue is ever accepted:
    // https://github.com/rust-lang/rust/issues/69329
    use nonzero_ext::nonzero;

    use super::*;

    #[test]
    fn deinterleave_1_0() {
        let r: Vec<Vec<i32>> =
            iter::empty::<i32>().deinterleave(nonzero!(1usize));
        assert_eq!(r, vec![vec![]]);
    }

    #[test]
    fn deinterleave_1_1() {
        let r: Vec<Vec<i32>> = iter::once(0i32).deinterleave(nonzero!(1usize));
        assert_eq!(r, vec![vec![0]]);
    }

    #[test]
    fn deinterleave_1_2() {
        let r: Vec<Vec<i32>> = [0, 1].iter().deinterleave(nonzero!(1usize));
        assert_eq!(r, vec![vec![0, 1]]);
    }

    #[test]
    fn deinterleave_2_2() {
        let r: Vec<Vec<i32>> = [0, 1].iter().deinterleave(nonzero!(2usize));
        assert_eq!(r, vec![vec![0], vec![1]]);
    }

    #[test]
    fn deinterleave_2_3() {
        let r: Vec<Vec<i32>> = [0, 1, 2].iter().deinterleave(nonzero!(2usize));
        assert_eq!(r, vec![vec![0, 2], vec![1]]);
    }

    #[test]
    fn deinterleave_2_4() {
        let r: Vec<Vec<i32>> =
            [0, 1, 2, 3].iter().deinterleave(nonzero!(2usize));
        assert_eq!(r, vec![vec![0, 2], vec![1, 3]]);
    }

    #[test]
    fn deinterleave_hashset() {
        use std::collections::HashSet;

        let r: Vec<HashSet<i32>> =
            [0, 1, 2, 3].iter().deinterleave(nonzero!(2usize));
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].len(), 2);
        assert!(r[0].contains(&0));
        assert!(r[0].contains(&2));
        assert_eq!(r[1].len(), 2);
        assert!(r[1].contains(&1));
        assert!(r[1].contains(&3));
    }
}

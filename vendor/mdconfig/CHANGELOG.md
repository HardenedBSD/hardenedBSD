## [0.2.0] - 2024-06-08

### Changed

- Changed how detach works.  Previously, detaching an `Md` no drop would not
  use the force flag, and would panic if the OS returned `EBUSY`.  Detaching
  with the force flag could only be done with `Md::destroy`.  But that was too
  failure-prone.  The problem is that a newly created `md` device will be
  asynchronously tasted by many other geom classes.  Any of those tasters can
  prevent it from being non-forcefully detached.  Since this library is
  frequently used for short-lived test programs, such failures are quite
  common.  The new behavior is the opposite: during drop the `md` device will
  be forcefully detached.  The only way to attempt a non-forceful detach is
  with `Md::try_destroy`.  This eliminates panics during drop as a result of
  `EBUSY`.
  ([#6](https://github.com/mdconfig/divbuf/pull/3))

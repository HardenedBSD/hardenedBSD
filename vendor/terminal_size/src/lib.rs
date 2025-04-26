//! A simple utility for getting the size of a terminal.
//!
//! Supports both Linux, MacOS, and Windows.
//!
//!  This crate requires a minimum rust version of 1.48.0 (2020-11-19)
//!
//! # Example
//!
//! ```
//! use terminal_size::{Width, Height, terminal_size};
//!
//! let size = terminal_size();
//! if let Some((Width(w), Height(h))) = size {
//!     println!("Your terminal is {} cols wide and {} lines tall", w, h);
//! } else {
//!     println!("Unable to get terminal size");
//! }
//! ```
//!

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Width(pub u16);
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Height(pub u16);

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use crate::unix::{terminal_size, terminal_size_using_fd};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use crate::windows::{terminal_size, terminal_size_using_handle};

#[cfg(not(any(unix, windows)))]
pub fn terminal_size() -> Option<(Width, Height)> {
    None
}

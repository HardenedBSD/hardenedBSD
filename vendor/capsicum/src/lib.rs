// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
#![warn(missing_docs)]

//! ## Entering capability mode
//!
//! ```
//!  use capsicum::{enter, sandboxed};
//!  use std::fs::File;
//!  use std::io::Read;
//!
//!  let mut ok_file = File::open("/etc/passwd").unwrap();
//!  let mut s = String::new();
//!
//!  enter().expect("enter failed!");
//!  assert!(sandboxed(), "application is not sandboxed!");
//!
//!  match File::create("/tmp/cant_touch_this") {
//!      Ok(_) => panic!("application is not properly sandboxed!"),
//!      Err(e) => println!("properly sandboxed: {:?}", e)
//!  }
//!
//!  match ok_file.read_to_string(&mut s) {
//!      Ok(_) => println!("This is okay since we opened the descriptor before sandboxing"),
//!      Err(_) => panic!("application is not properly sandboxed!")
//!  }
//! ```
//!
//! ## Limit capability rights to files
//!
//! ```
//! use capsicum::{CapRights, Right, FileRights};
//! use std::fs::File;
//! use std::io::Read;
//! let mut ok_file = File::open("/etc/passwd").unwrap();
//! let mut s = String::new();
//!
//! FileRights::new()
//!     .allow(Right::Seek)
//!     .allow(Right::Read)
//!     .limit(&ok_file).unwrap();
//!
//! assert!(ok_file.read_to_string(&mut s).is_ok());
//! ```
//!
//! ## Opening new files in a subdirectory after entering capability mode
//!
//! ```
//!  use std::fs::File;
//!  use std::io::Read;
//!
//!  // Before entering capability mode, we can open files in the global namespace.
//!  let aa = cap_std::ambient_authority();
//!  let etc = cap_std::fs::Dir::open_ambient_dir("/etc", aa).unwrap();
//!
//!  capsicum::enter().expect("enter failed!");
//!
//!  // Now, we can no longer access the global file system namespace.
//!  let aa = cap_std::ambient_authority();
//!  cap_std::fs::Dir::open_ambient_dir("/etc", aa).unwrap_err();
//!  std::fs::File::open("/etc/passwd").unwrap_err();
//!
//!  // But we can still open children of our already-open directory
//!  let passwd = etc.open("passwd").unwrap();
//! ```
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "casper")]
#[cfg_attr(docsrs, doc(cfg(feature = "casper")))]
pub mod casper;
mod common;
mod fcntl;
mod ioctl;
mod process;
mod right;
/// Deprecated utilities
pub mod util;

#[allow(deprecated)]
pub use fcntl::FcntlsBuilder;
pub use fcntl::{Fcntl, FcntlRights};
pub use ioctl::{IoctlRights, IoctlsBuilder};
pub use process::{enter, get_mode, sandboxed};
#[allow(deprecated)]
pub use right::RightsBuilder;
pub use right::{FileRights, Right};

pub use crate::common::CapRights;

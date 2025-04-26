// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{io, os::unix::io::AsFd};

/// A set of capabilities that may be restricted on file descriptors.
pub trait CapRights: Sized {
    /// Reduce the process's allowed rights to a file descriptor.
    ///
    /// When a file descriptor is first created, it is assigned all possible capability rights.
    /// Those rights may be reduced (but never expanded), by this method.
    fn limit<F: AsFd>(&self, f: &F) -> io::Result<()>;
}

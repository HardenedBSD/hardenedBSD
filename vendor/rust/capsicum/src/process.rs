// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::io;

/// Actually enter capability mode.
///
/// After this point the process will no longer be allowed to access global namespaces.
pub fn enter() -> io::Result<()> {
    if unsafe { libc::cap_enter() } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Returns true if the process is in a capability mode.
pub fn sandboxed() -> bool {
    unsafe { libc::cap_sandboxed() }
}

/// Returns true if the process is in a capability mode.
///
/// # Errors
///
/// * `ENOSYS` - The kernel was compiled without capability support.
pub fn get_mode() -> io::Result<bool> {
    let mut mode = 0;
    unsafe {
        if libc::cap_getmode(&mut mode) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(mode != 0)
}

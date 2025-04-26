#![forbid(unsafe_code)]
#![deny(missing_docs)]
use crate::errors::ExporterError;
use tracing::debug;
use uzers::Users;

// Checks that we're running as root.
pub fn is_running_as_root<U: Users>(users: &mut U) -> Result<(), ExporterError> {
    debug!("Ensuring that we're running as root");

    match users.get_effective_uid() {
        0 => Ok(()),
        _ => Err(ExporterError::NotRunningAsRoot),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uzers::mock::{
        Group,
        MockUsers,
        User,
    };
    use uzers::os::unix::UserExt;

    #[test]
    fn is_running_as_root_ok() {
        let mut users = MockUsers::with_current_uid(0);
        let user = User::new(0, "root", 0).with_home_dir("/root");
        users.add_user(user);
        users.add_group(Group::new(0, "root"));

        let is_root = is_running_as_root(&mut users);

        assert!(is_root.is_ok());
    }

    #[test]
    fn is_running_as_non_root() {
        let mut users = MockUsers::with_current_uid(10000);
        let user = User::new(10000, "ferris", 10000).with_home_dir("/ferris");
        users.add_user(user);
        users.add_group(Group::new(10000, "ferris"));

        let is_root = is_running_as_root(&mut users);

        assert!(is_root.is_err());
    }
}

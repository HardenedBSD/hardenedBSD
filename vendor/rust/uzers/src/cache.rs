//! Caches for users and groups provided by the OS.
//!
//! Because the users table changes so infrequently, it's common for
//! short-running programs to cache the results instead of getting the most
//! up-to-date entries every time. This create offers two caching interfaces
//! that help reduce system calls: [`UsersCache`](cache/struct.UsersCache.html)
//! and [`UsersSnapshot`](cache/struct.UsersSnapshot.html). `UsersCache` is a
//! lazy cache, storing answers as they arrive from the OS. `UsersSnapshot` is
//! an eager cache, querying all data at once when constructed.
//!
//! `UsersCache` has a smaller memory and performance overhead, while
//! `UsersSnapshot` offers better consistency and allows iterating over users
//! and groups.
//!
//! ## Caching, multiple threads, and mutability
//!
//! The `UsersCache` type is caught between a rock and a hard place when it
//! comes to providing references to users and groups.
//!
//! Instead of returning a fresh `User` struct each time, for example, it will
//! return a reference to the version it currently has in its cache. So you can
//! ask for User #501 twice, and you’ll get a reference to the same value both
//! time. Its methods are *idempotent* -- calling one multiple times has the
//! same effect as calling one once.
//!
//! This works fine in theory, but in practice, the cache has to update its own
//! state somehow: it contains several `HashMap`s that hold the result of user
//! and group lookups. Rust provides mutability in two ways:
//!
//! 1. Have its methods take `&mut self`, instead of `&self`, allowing the
//!    internal maps to be mutated (“inherited mutability”)
//! 2. Wrap the internal maps in a `RefCell`, allowing them to be modified
//!    (“interior mutability”).
//!
//! Unfortunately, Rust is also very protective of references to a mutable
//! value. In this case, switching to `&mut self` would only allow for one user
//! to be read at a time!
//!
//! ```no_run
//! use uzers::{Users, Groups, UsersCache};
//!
//! let mut cache = UsersCache::new();
//!
//! let uid   = cache.get_current_uid();                          // OK...
//! let user  = cache.get_user_by_uid(uid).unwrap();              // OK...
//! let group = cache.get_group_by_gid(user.primary_group_id());  // No!
//! ```
//!
//! When we get the `user`, it returns an optional reference (which we unwrap)
//! to the user’s entry in the cache. This is a reference to something contained
//! in a mutable value. Then, when we want to get the user’s primary group, it
//! will return *another* reference to the same mutable value. This is something
//! that Rust explicitly disallows!
//!
//! The compiler wasn’t on our side with Option 1, so let’s try Option 2:
//! changing the methods back to `&self` instead of `&mut self`, and using
//! `RefCell`s internally. However, Rust is smarter than this, and knows that
//! we’re just trying the same trick as earlier. A simplified implementation of
//! a user cache lookup would look something like this:
//!
//! ```text
//! fn get_user_by_uid(&self, uid: uid_t) -> Option<&User> {
//!     let users = self.users.borrow_mut();
//!     users.get(uid)
//! }
//! ```
//!
//! Rust won’t allow us to return a reference like this because the `Ref` of the
//! `RefCell` just gets dropped at the end of the method, meaning that our
//! reference does not live long enough.
//!
//! So instead of doing any of that, we use `Arc` everywhere in order to get
//! around all the lifetime restrictions. Returning reference-counted users and
//! groups mean that we don’t have to worry about further uses of the cache, as
//! the values themselves don’t count as being stored *in* the cache anymore. So
//! it can be queried multiple times or go out of scope and the values it
//! produces are not affected.

use libc::{gid_t, uid_t};
use std::cell::{Cell, RefCell};
use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::hash::Hash;
use std::ops::Deref;
use std::sync::Arc;

use base::{all_groups, all_users, Group, User};
use traits::{AllGroups, AllUsers, Groups, Users};

/// A producer of user and group instances that caches every result.
///
/// This cache is **only additive**: it’s not possible to drop it, or erase
/// selected entries, as when the database may have been modified, it’s best to
/// start entirely afresh. So to accomplish this, just start using a new
/// `UsersCache`.
///
/// ## Example
///
/// ```no_run
/// use std::sync::Arc;
/// use uzers::{Users, UsersCache};
///
/// let mut cache = UsersCache::new();
/// let user      = cache.get_user_by_uid(502).expect("User not found");
/// let same_user = cache.get_user_by_uid(502).unwrap();
///
/// // The two returned values point to the same User
/// assert!(Arc::ptr_eq(&user, &same_user));
/// ```
///
/// ## See also
///
/// [`all_users`] and [`all_groups`] cannot be safely exposed in `UsersCache`,
/// and lazy caching may introduce inconsistencies; see [`UsersSnapshot`] for
/// an alternative.
///
/// For thread safety considerations, see the
/// [`users::cache` module documentation](index.html#caching-multiple-threads-and-mutability).
#[derive(Default)]
pub struct UsersCache {
    users: RefCell<IdNameMap<uid_t, Arc<OsStr>, Arc<User>>>,
    groups: RefCell<IdNameMap<gid_t, Arc<OsStr>, Arc<Group>>>,

    uid: Cell<Option<uid_t>>,
    gid: Cell<Option<gid_t>>,
    euid: Cell<Option<uid_t>>,
    egid: Cell<Option<gid_t>>,
}

/// A kinda-bi-directional `HashMap` that associates keys to values, and
/// then strings back to keys.
///
/// It doesn’t go the full route and offer *values*-to-keys lookup, because we
/// only want to search based on usernames and group names. There wouldn’t be
/// much point offering a “User to uid” map, as the uid is present in the
/// `User` struct!
struct IdNameMap<I, N, V>
where
    I: Eq + Hash + Copy,
    N: Eq + Hash,
{
    forward: HashMap<I, Option<V>>,
    backward: HashMap<N, Option<I>>,
}

impl<I, N, V> IdNameMap<I, N, V>
where
    I: Eq + Hash + Copy,
    N: Eq + Hash,
{
    /// Creates a new entry.
    fn insert(&mut self, id: I, name: N, value: V) {
        self.forward.insert(id, Some(value));
        self.backward.insert(name, Some(id));
    }
}

// Cannot use `#[derive(Default)]` for `IdNameMap` because [`HashMap`] requires
// some of its types to implement [`Default`].
impl<I, N, V> Default for IdNameMap<I, N, V>
where
    I: Eq + Hash + Copy,
    N: Eq + Hash,
{
    fn default() -> Self {
        Self {
            forward: HashMap::new(),
            backward: HashMap::new(),
        }
    }
}

impl UsersCache {
    /// Creates a new empty cache.
    ///
    /// # Examples
    ///
    /// ```
    /// use uzers::cache::UsersCache;
    ///
    /// let cache = UsersCache::new();
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new cache preloaded with all users present on the system.
    ///
    /// This is a legacy method for code where `UsersCache` is required.
    /// Consider replacing this method with [`UsersSnapshot::new`] whereever
    /// possible to improve performance and consistency.
    ///
    /// Only information about *existing* users and groups is preloaded.
    /// Consequently, the following requests will still result in system calls:
    /// - current UID/GID,
    /// - effective UID/GID,
    /// - users and groups that were not preloaded.
    ///
    /// # Safety
    ///
    /// This is `unsafe` because we cannot prevent data races if two caches
    /// were attempted to be initialised on different threads at the same time.
    /// For more information, see the [`all_users` documentation](../fn.all_users.html).
    ///
    /// # Examples
    ///
    /// ```
    /// use uzers::cache::UsersCache;
    ///
    /// let cache = unsafe { UsersCache::with_all_users() };
    /// ```
    ///
    /// # See also
    ///
    /// [`UsersSnapshot::new`]
    #[deprecated(since = "0.11.4", note = "consider using `UsersSnapshot::new` instead")]
    pub unsafe fn with_all_users() -> Self {
        let cache = Self::new();

        for user in all_users() {
            let uid = user.uid();
            let user_arc = Arc::new(user);
            cache.users.borrow_mut().insert(
                uid,
                Arc::clone(&user_arc.name_arc),
                Arc::clone(&user_arc),
            );
        }

        cache
    }
}

// TODO: stop using ‘Arc::from’ with entry API
// The ‘get_*_by_name’ functions below create a new Arc before even testing if
// the user exists in the cache, essentially creating an unnecessary Arc.
// https://internals.rust-lang.org/t/pre-rfc-abandonning-morals-in-the-name-of-performance-the-raw-entry-api/7043/51
// https://github.com/rust-lang/rfcs/pull/1769

impl Users for UsersCache {
    fn get_user_by_uid(&self, uid: uid_t) -> Option<Arc<User>> {
        let mut users = self.users.borrow_mut();

        let entry = match users.forward.entry(uid) {
            Vacant(e) => e,
            Occupied(e) => return e.get().clone(),
        };

        if let Some(user) = super::get_user_by_uid(uid) {
            let newsername = Arc::clone(&user.name_arc);
            let user_arc = Arc::new(user);

            entry.insert(Some(Arc::clone(&user_arc)));
            users.backward.insert(newsername, Some(uid));

            Some(user_arc)
        } else {
            entry.insert(None);
            None
        }
    }

    fn get_user_by_name<S: AsRef<OsStr> + ?Sized>(&self, username: &S) -> Option<Arc<User>> {
        let mut users = self.users.borrow_mut();

        let entry = match users.backward.entry(Arc::from(username.as_ref())) {
            Vacant(e) => e,
            Occupied(e) => return (*e.get()).and_then(|uid| users.forward[&uid].clone()),
        };

        if let Some(user) = super::get_user_by_name(username) {
            let uid = user.uid();
            let user_arc = Arc::new(user);

            entry.insert(Some(uid));
            users.forward.insert(uid, Some(Arc::clone(&user_arc)));

            Some(user_arc)
        } else {
            entry.insert(None);
            None
        }
    }

    fn get_current_uid(&self) -> uid_t {
        self.uid.get().unwrap_or_else(|| {
            let uid = super::get_current_uid();
            self.uid.set(Some(uid));
            uid
        })
    }

    fn get_current_username(&self) -> Option<Arc<OsStr>> {
        let uid = self.get_current_uid();
        self.get_user_by_uid(uid).map(|u| Arc::clone(&u.name_arc))
    }

    fn get_effective_uid(&self) -> uid_t {
        self.euid.get().unwrap_or_else(|| {
            let uid = super::get_effective_uid();
            self.euid.set(Some(uid));
            uid
        })
    }

    fn get_effective_username(&self) -> Option<Arc<OsStr>> {
        let uid = self.get_effective_uid();
        self.get_user_by_uid(uid).map(|u| Arc::clone(&u.name_arc))
    }
}

impl Groups for UsersCache {
    fn get_group_by_gid(&self, gid: gid_t) -> Option<Arc<Group>> {
        let mut groups = self.groups.borrow_mut();

        let entry = match groups.forward.entry(gid) {
            Vacant(e) => e,
            Occupied(e) => return e.get().clone(),
        };

        if let Some(group) = super::get_group_by_gid(gid) {
            let new_group_name = Arc::clone(&group.name_arc);
            let group_arc = Arc::new(group);

            entry.insert(Some(Arc::clone(&group_arc)));
            groups.backward.insert(new_group_name, Some(gid));

            Some(group_arc)
        } else {
            entry.insert(None);
            None
        }
    }

    fn get_group_by_name<S: AsRef<OsStr> + ?Sized>(&self, group_name: &S) -> Option<Arc<Group>> {
        let mut groups = self.groups.borrow_mut();

        let entry = match groups.backward.entry(Arc::from(group_name.as_ref())) {
            Vacant(e) => e,
            Occupied(e) => {
                return (*e.get()).and_then(|gid| groups.forward[&gid].as_ref().cloned())
            }
        };

        if let Some(group) = super::get_group_by_name(group_name) {
            let group_arc = Arc::new(group.clone());
            let gid = group.gid();

            entry.insert(Some(gid));
            groups.forward.insert(gid, Some(Arc::clone(&group_arc)));

            Some(group_arc)
        } else {
            entry.insert(None);
            None
        }
    }

    fn get_current_gid(&self) -> gid_t {
        self.gid.get().unwrap_or_else(|| {
            let gid = super::get_current_gid();
            self.gid.set(Some(gid));
            gid
        })
    }

    fn get_current_groupname(&self) -> Option<Arc<OsStr>> {
        let gid = self.get_current_gid();
        self.get_group_by_gid(gid).map(|g| Arc::clone(&g.name_arc))
    }

    fn get_effective_gid(&self) -> gid_t {
        self.egid.get().unwrap_or_else(|| {
            let gid = super::get_effective_gid();
            self.egid.set(Some(gid));
            gid
        })
    }

    fn get_effective_groupname(&self) -> Option<Arc<OsStr>> {
        let gid = self.get_effective_gid();
        self.get_group_by_gid(gid).map(|g| Arc::clone(&g.name_arc))
    }
}

/// A container of user and group instances.
///
/// Included users and groups are determined by the method used to construct
/// the snapshot:
/// - [`UsersSnapshot::new()`] includes all system users and groups,
/// - [`UsersSnapshot::only_users()`] filters users and includes only their
///   primary groups,
/// - [`UsersSnapshot::filtered()`] filters users and groups separately.
///
/// This cache is **immutable**: it's not possible to alter or refresh it in any
/// way after creation. Create a new `UsersSnapshot` to see changes in the
/// underlying system database.
///
/// ## Examples
///
/// ```no_run
/// use std::sync::Arc;
/// use uzers::{Users, UsersSnapshot};
///
/// let cache     = unsafe { UsersSnapshot::new() };
/// let user      = cache.get_user_by_uid(502).expect("User not found");
/// let same_user = cache.get_user_by_uid(502).unwrap();
///
/// // The two returned values point to the same User
/// assert!(Arc::ptr_eq(&user, &same_user));
/// ```
///
/// ```no_run
/// use uzers::{AllUsers, UsersSnapshot};
///
/// // Exclude MacOS system users
/// let cache = unsafe { UsersSnapshot::only_users(|u| u.uid() >= 500) };
///
/// // Users and groups can be iterated
/// let user_count = cache.get_all_users().count();
/// ```
///
/// ## See also
///
/// Unless iteration is required, [`UsersCache`] is likely safer, easier and
/// faster.
///
/// For thread safety considerations, see the
/// [`users::cache` module documentation](index.html#caching-multiple-threads-and-mutability).
#[derive(Default)]
pub struct UsersSnapshot {
    users: IdNameMap<uid_t, Arc<OsStr>, Arc<User>>,
    groups: IdNameMap<uid_t, Arc<OsStr>, Arc<Group>>,

    uid: uid_t,
    gid: gid_t,
    euid: uid_t,
    egid: gid_t,
}

impl UsersSnapshot {
    /// Creates a new snapshot containing provided users and groups.
    pub(crate) fn from<U, G>(
        users: U,
        groups: G,
        current_uid: uid_t,
        current_gid: gid_t,
        effective_uid: uid_t,
        effective_gid: gid_t,
    ) -> Self
    where
        U: Iterator<Item = User>,
        G: Iterator<Item = Group>,
    {
        let mut user_map = IdNameMap::default();

        for user in users {
            user_map.insert(user.uid(), Arc::clone(&user.name_arc), Arc::from(user));
        }

        let mut group_map = IdNameMap::default();

        for group in groups {
            group_map.insert(group.gid(), Arc::clone(&group.name_arc), Arc::from(group));
        }

        Self {
            users: user_map,
            groups: group_map,
            uid: current_uid,
            gid: current_gid,
            euid: effective_uid,
            egid: effective_gid,
        }
    }

    /// Creates a new snapshot containing all system users and groups that pass
    /// the filter.
    ///
    /// # Safety
    ///
    /// This is `unsafe` because we cannot prevent data races if two caches
    /// were attempted to be initialised on different threads at the same time.
    /// For more information, see the [`all_users` documentation](../fn.all_users.html).
    ///
    /// Note that this method uses both [`all_users`] and [`all_groups`].
    ///
    /// # Examples
    ///
    /// ```
    /// use uzers::cache::UsersSnapshot;
    ///
    /// // Exclude Linux system users, include all groups
    /// let snapshot = unsafe {
    ///     UsersSnapshot::filtered(|u| u.uid() >= 1000, |_| true)
    /// };
    /// ```
    ///
    /// # See also
    ///
    /// - [`UsersSnapshot::only_users()`] - if only primary groups of users are
    ///   needed
    /// - [`UsersSnapshot::new()`] - if no filtering is needed
    pub unsafe fn filtered<U, G>(user_filter: U, group_filter: G) -> Self
    where
        U: FnMut(&User) -> bool,
        G: FnMut(&Group) -> bool,
    {
        Self::from(
            all_users().filter(user_filter),
            all_groups().filter(group_filter),
            super::get_current_uid(),
            super::get_current_gid(),
            super::get_effective_uid(),
            super::get_effective_gid(),
        )
    }

    /// Creates a new snapshot containing all system users that pass the filter
    /// and their primary groups.
    ///
    /// Note that some primary groups may be missing on the system.
    ///
    /// # Safety
    ///
    /// This is `unsafe` because we cannot prevent data races if two caches
    /// were attempted to be initialised on different threads at the same time.
    /// For more information, see the [`all_users` documentation](../fn.all_users.html).
    ///
    /// Note that this method uses both [`all_users`] and [`all_groups`].
    ///
    /// # Examples
    ///
    /// ```
    /// use uzers::cache::UsersSnapshot;
    ///
    /// // Include Linux system users and their primary groups
    /// let snapshot = unsafe { UsersSnapshot::only_users(|u| u.uid() < 1000) };
    /// ```
    ///
    /// # See also
    ///
    /// - [`UsersSnapshot::filtered()`] - for more elaborate group filtering
    /// - [`UsersSnapshot::new()`] - if no filtering is needed
    pub unsafe fn only_users<F>(user_filter: F) -> Self
    where
        F: FnMut(&User) -> bool,
    {
        let users = all_users().filter(user_filter).collect::<Vec<_>>();
        let primary_groups = users
            .iter()
            .map(User::primary_group_id)
            .collect::<HashSet<_>>();
        let groups = all_groups()
            .filter(|g| primary_groups.contains(&g.gid()))
            .collect::<Vec<_>>();

        Self::from(
            users.into_iter(),
            groups.into_iter(),
            super::get_current_uid(),
            super::get_current_gid(),
            super::get_effective_uid(),
            super::get_effective_gid(),
        )
    }

    /// Creates a new snapshot containing all system users and groups.
    ///
    /// # Safety
    ///
    /// This is `unsafe` because we cannot prevent data races if two caches
    /// were attempted to be initialised on different threads at the same time.
    /// For more information, see the [`all_users` documentation](../fn.all_users.html).
    ///
    /// Note that this method uses both [`all_users`] and [`all_groups`].
    ///
    /// # Examples
    ///
    /// ```
    /// use uzers::cache::UsersSnapshot;
    ///
    /// let snapshot = unsafe { UsersSnapshot::new() };
    /// ```
    ///
    /// # See also
    ///
    /// [`UsersSnapshot::only_users()`], [`UsersSnapshot::filtered()`] provide
    /// performance benefits if only some users and groups will be needed.
    pub unsafe fn new() -> Self {
        Self::filtered(|_| true, |_| true)
    }
}

impl AllUsers for UsersSnapshot {
    type UserIter<'a> = std::iter::FilterMap<
        std::collections::hash_map::Values<'a, uid_t, Option<Arc<User>>>,
        for<'b> fn(&'b Option<Arc<User>>) -> Option<&'b User>,
    >;

    fn get_all_users(&self) -> Self::UserIter<'_> {
        fn get_user(x: &Option<Arc<User>>) -> Option<&User> {
            x.as_ref().map(Arc::deref)
        }

        self.users.forward.values().filter_map(get_user)
    }
}

impl Users for UsersSnapshot {
    fn get_user_by_uid(&self, uid: uid_t) -> Option<Arc<User>> {
        self.users.forward.get(&uid)?.as_ref().cloned()
    }

    fn get_user_by_name<S: AsRef<OsStr> + ?Sized>(&self, username: &S) -> Option<Arc<User>> {
        let name_arc = Arc::from(username.as_ref());
        let uid = self.users.backward.get(&name_arc)?.as_ref()?;
        self.get_user_by_uid(*uid)
    }

    fn get_current_uid(&self) -> uid_t {
        self.uid
    }

    fn get_current_username(&self) -> Option<Arc<OsStr>> {
        self.get_user_by_uid(self.uid)
            .map(|u| Arc::clone(&u.name_arc))
    }

    fn get_effective_uid(&self) -> uid_t {
        self.euid
    }

    fn get_effective_username(&self) -> Option<Arc<OsStr>> {
        self.get_user_by_uid(self.euid)
            .map(|u| Arc::clone(&u.name_arc))
    }
}

impl AllGroups for UsersSnapshot {
    type GroupIter<'a> = std::iter::FilterMap<
        std::collections::hash_map::Values<'a, gid_t, Option<Arc<Group>>>,
        for<'b> fn(&'b Option<Arc<Group>>) -> Option<&'b Group>,
    >;

    fn get_all_groups(&self) -> Self::GroupIter<'_> {
        fn get_group(x: &Option<Arc<Group>>) -> Option<&Group> {
            x.as_ref().map(Arc::deref)
        }

        self.groups.forward.values().filter_map(get_group)
    }
}

impl Groups for UsersSnapshot {
    fn get_group_by_gid(&self, gid: gid_t) -> Option<Arc<Group>> {
        self.groups.forward.get(&gid)?.as_ref().cloned()
    }

    fn get_group_by_name<S: AsRef<OsStr> + ?Sized>(&self, group_name: &S) -> Option<Arc<Group>> {
        let name_arc = Arc::from(group_name.as_ref());
        let gid = self.groups.backward.get(&name_arc)?.as_ref()?;
        self.get_group_by_gid(*gid)
    }

    fn get_current_gid(&self) -> gid_t {
        self.gid
    }

    fn get_current_groupname(&self) -> Option<Arc<OsStr>> {
        self.get_group_by_gid(self.gid)
            .map(|g| Arc::clone(&g.name_arc))
    }

    fn get_effective_gid(&self) -> gid_t {
        self.egid
    }

    fn get_effective_groupname(&self) -> Option<Arc<OsStr>> {
        self.get_group_by_gid(self.egid)
            .map(|g| Arc::clone(&g.name_arc))
    }
}

extern crate uzers;

use uzers::mock::MockUsers;
use uzers::{AllGroups, Group, Groups, UsersCache, UsersSnapshot};

fn iter_aware<G: Groups + AllGroups>(g: &G) {
    println!("All groups:");
    for group in g.get_all_groups() {
        println!("- {group:?}");
    }

    no_iter(g);
}

fn no_iter<G: Groups>(g: &G) {
    let me = g.get_current_groupname();
    let root = g.get_group_by_gid(0);
    println!("My group is {me:?}, gid 0 is {root:?}");
}

fn main() {
    env_logger::init();

    // UsersCache can only be used with `no_iter`
    println!("\n--- UsersCache ---");
    no_iter(&UsersCache::new());

    // UsersSnapshot can be used with both `no_iter` and `iter_aware`
    println!("\n--- UsersSnapshot: all groups ---");
    no_iter(unsafe { &UsersSnapshot::new() });
    println!("\n--- UsersSnapshot: primary groups of some system users ---");
    iter_aware(unsafe { &UsersSnapshot::only_users(|u| u.uid() < 10) });

    // MockUsers can be used with both `no_iter` and `iter_aware`
    println!("\n--- MockUsers ---");
    let mut mock = MockUsers::with_current_uid(1000);
    mock.add_group(Group::new(1000, "fred"));
    mock.add_group(Group::new(0, "r00t"));
    iter_aware(&mock);
}

extern crate uzers;

#[cfg(feature = "test-integration")]
mod integration {
    #[test]
    fn test_group_by_name() {
        let group = uzers::get_group_by_name("bosses");

        assert_eq!(group.is_some(), true);

        let group = group.unwrap();

        assert_eq!(group.gid(), 42);
        assert_eq!(group.name(), "bosses");
    }
}

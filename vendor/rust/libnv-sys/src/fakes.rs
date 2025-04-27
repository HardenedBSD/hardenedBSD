//! Fake definitions good enough to cross-build docs
//!
//! docs.rs does all of its builds on Linux, so the usual build script fails.
//! As a workaround, we skip the usual build script when doing cross-builds, and
//! define these stubs instead.

// This symbol is sufficient to build libnv's docs
pub type nvlist_t = *const i32;

// However, building downstream crates' docs requires these additional symbols
pub type FreeBSD_nvlist_t = nvlist_t;
extern "C" {
    pub fn nvlist_clone(_: *const FreeBSD_nvlist_t) -> *mut FreeBSD_nvlist_t;
    pub fn nvlist_create(_: ::std::os::raw::c_int) -> *mut FreeBSD_nvlist_t;
    pub fn nvlist_destroy(_: *mut FreeBSD_nvlist_t);
    pub fn nvlist_free(_: *mut FreeBSD_nvlist_t, _: *const ::std::os::raw::c_char);
    pub fn nvlist_free_type(
        _: *mut FreeBSD_nvlist_t,
        _: *const ::std::os::raw::c_char,
        _: ::std::os::raw::c_int,
    );
    pub fn nvlist_size(_: *const FreeBSD_nvlist_t) -> usize;
    pub fn nvlist_dump(_: *const FreeBSD_nvlist_t, _: ::std::os::raw::c_int);
    pub fn nvlist_get_array_next(_: *const FreeBSD_nvlist_t) -> *const FreeBSD_nvlist_t;
    pub fn nvlist_exists_nvlist_array(
        _: *const FreeBSD_nvlist_t,
        _: *const ::std::os::raw::c_char,
    ) -> bool;
    pub fn nvlist_get_string_array(
        _: *const FreeBSD_nvlist_t,
        _: *const ::std::os::raw::c_char,
        _: *mut usize,
    ) -> *const *const ::std::os::raw::c_char;
    pub fn nvlist_exists_string_array(
        _: *const FreeBSD_nvlist_t,
        _: *const ::std::os::raw::c_char,
    ) -> bool;
    pub fn nvlist_get_number_array(
        _: *const FreeBSD_nvlist_t,
        _: *const ::std::os::raw::c_char,
        _: *mut usize,
    ) -> *const u64;
    pub fn nvlist_exists_number_array(
        _: *const FreeBSD_nvlist_t,
        _: *const ::std::os::raw::c_char,
    ) -> bool;
    pub fn nvlist_get_bool_array(
        _: *const FreeBSD_nvlist_t,
        _: *const ::std::os::raw::c_char,
        _: *mut usize,
    ) -> *const bool;
    pub fn nvlist_exists_bool_array(
        _: *const FreeBSD_nvlist_t,
        _: *const ::std::os::raw::c_char,
    ) -> bool;

    pub fn nvlist_get_nvlist_array(
        _: *const FreeBSD_nvlist_t,
        _: *const ::std::os::raw::c_char,
        _: *mut usize,
    ) -> *const *const FreeBSD_nvlist_t;
    pub fn nvlist_get_nvlist(
        _: *const FreeBSD_nvlist_t,
        _: *const ::std::os::raw::c_char,
    ) -> *const FreeBSD_nvlist_t;
    pub fn nvlist_exists_nvlist(
        _: *const FreeBSD_nvlist_t,
        _: *const ::std::os::raw::c_char,
    ) -> bool;
    pub fn nvlist_get_string(
        _: *const FreeBSD_nvlist_t,
        _: *const ::std::os::raw::c_char,
    ) -> *const ::std::os::raw::c_char;
    pub fn nvlist_exists_string(
        _: *const FreeBSD_nvlist_t,
        _: *const ::std::os::raw::c_char,
    ) -> bool;
    pub fn nvlist_exists_number(
        _: *const FreeBSD_nvlist_t,
        _: *const ::std::os::raw::c_char,
    ) -> bool;

    pub fn nvlist_get_number(_: *const FreeBSD_nvlist_t, _: *const ::std::os::raw::c_char) -> u64;
    pub fn nvlist_get_bool(_: *const FreeBSD_nvlist_t, _: *const ::std::os::raw::c_char) -> bool;
    pub fn nvlist_exists_bool(_: *const FreeBSD_nvlist_t, _: *const ::std::os::raw::c_char)
        -> bool;
    pub fn nvlist_get_binary(
        _: *const FreeBSD_nvlist_t,
        _: *const ::std::os::raw::c_char,
        _: *mut usize,
    ) -> *const ::std::os::raw::c_void;
    pub fn nvlist_exists_type(
        _: *const FreeBSD_nvlist_t,
        _: *const ::std::os::raw::c_char,
        _: ::std::os::raw::c_int,
    ) -> bool;
    pub fn nvlist_exists(_: *const FreeBSD_nvlist_t, _: *const ::std::os::raw::c_char) -> bool;
    pub fn nvlist_add_nvlist_array(
        _: *mut FreeBSD_nvlist_t,
        _: *const ::std::os::raw::c_char,
        _: *const *const FreeBSD_nvlist_t,
        _: usize,
    );
    pub fn nvlist_add_string_array(
        _: *mut FreeBSD_nvlist_t,
        _: *const ::std::os::raw::c_char,
        _: *const *const ::std::os::raw::c_char,
        _: usize,
    );
    pub fn nvlist_add_bool_array(
        _: *mut FreeBSD_nvlist_t,
        _: *const ::std::os::raw::c_char,
        _: *const bool,
        _: usize,
    );
    pub fn nvlist_add_binary(
        _: *mut FreeBSD_nvlist_t,
        _: *const ::std::os::raw::c_char,
        _: *const ::std::os::raw::c_void,
        _: usize,
    );
    pub fn nvlist_add_string(
        _: *mut FreeBSD_nvlist_t,
        _: *const ::std::os::raw::c_char,
        _: *const ::std::os::raw::c_char,
    );
    pub fn nvlist_add_bool(_: *mut FreeBSD_nvlist_t, _: *const ::std::os::raw::c_char, _: bool);
    pub fn nvlist_add_null(_: *mut FreeBSD_nvlist_t, _: *const ::std::os::raw::c_char);
    pub fn nvlist_add_number(_: *mut FreeBSD_nvlist_t, _: *const ::std::os::raw::c_char, _: u64);

    pub fn nvlist_add_number_array(
        _: *mut FreeBSD_nvlist_t,
        _: *const ::std::os::raw::c_char,
        _: *const u64,
        _: usize,
    );
    pub fn nvlist_add_nvlist(
        _: *mut FreeBSD_nvlist_t,
        _: *const ::std::os::raw::c_char,
        _: *const FreeBSD_nvlist_t,
    );
    pub fn nvlist_set_error(_: *mut FreeBSD_nvlist_t, _: ::std::os::raw::c_int);
    pub fn nvlist_error(_: *const FreeBSD_nvlist_t) -> ::std::os::raw::c_int;
    pub fn nvlist_flags(_: *const FreeBSD_nvlist_t) -> ::std::os::raw::c_int;
    pub fn nvlist_empty(_: *const FreeBSD_nvlist_t) -> bool;
}

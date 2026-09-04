//! Audited native boundary for one bounded `getpwnam_r` lookup.

use std::ffi::{CStr, c_char, c_int};

pub(super) const STATUS_OK: c_int = 0;
pub(super) const STATUS_INVALID_INPUT: c_int = 1;
pub(super) const STATUS_LOOKUP_FAILED: c_int = 2;
pub(super) const STATUS_NOT_FOUND: c_int = 3;
pub(super) const STATUS_NON_CANONICAL: c_int = 4;
pub(super) const STATUS_ROOT: c_int = 5;
pub(super) const STATUS_UNREPRESENTABLE: c_int = 6;
pub(super) const STATUS_INVALID_RESULT: c_int = 7;

unsafe extern "C" {
    fn t1_nss_account_resolve(username: *const c_char, user_id: *mut u32) -> c_int;
}

pub(super) fn resolve(username: &CStr) -> (c_int, u32) {
    let mut user_id = 0;
    // SAFETY: `username` is NUL-terminated and live for the complete call;
    // `user_id` is initialized writable output. The C boundary performs one
    // synchronous lookup and retains neither pointer.
    let status = unsafe { t1_nss_account_resolve(username.as_ptr(), &raw mut user_id) };
    (status, user_id)
}

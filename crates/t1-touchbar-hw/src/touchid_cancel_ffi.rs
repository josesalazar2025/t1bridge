use std::ffi::c_int;

unsafe extern "C" {
    fn t1_touchid_cancel() -> c_int;
}

pub(super) fn cancel() -> c_int {
    // SAFETY: This argument-free native boundary owns the complete fixed
    // cancellation transaction and returns only a scalar result category.
    unsafe { t1_touchid_cancel() }
}

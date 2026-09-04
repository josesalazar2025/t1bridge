use std::ffi::c_int;

#[repr(C)]
pub(super) struct RawServiceLifecycle {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn t1_service_notify_ready_once() -> c_int;
    fn t1_service_lifecycle_install(output: *mut *mut RawServiceLifecycle) -> c_int;
    fn t1_service_lifecycle_cancelled(lifecycle: *const RawServiceLifecycle) -> c_int;
    fn t1_service_lifecycle_notify_ready(lifecycle: *mut RawServiceLifecycle) -> c_int;
    fn t1_service_lifecycle_destroy(lifecycle: *mut RawServiceLifecycle) -> c_int;
}

pub(super) fn notify_ready_once() -> c_int {
    // SAFETY: sd_notify consumes only its process environment and fixed data.
    unsafe { t1_service_notify_ready_once() }
}

pub(super) fn install() -> (c_int, *mut RawServiceLifecycle) {
    let mut lifecycle = std::ptr::null_mut();
    // SAFETY: `lifecycle` is writable for one pointer. On success the native
    // boundary returns one uniquely owned process-lifecycle handle.
    let status = unsafe { t1_service_lifecycle_install(&raw mut lifecycle) };
    (status, lifecycle)
}

pub(super) fn cancelled(lifecycle: *const RawServiceLifecycle) -> bool {
    // SAFETY: the safe owner keeps the native handle live for this call.
    unsafe { t1_service_lifecycle_cancelled(lifecycle) != 0 }
}

pub(super) fn notify_ready(lifecycle: *mut RawServiceLifecycle) -> c_int {
    // SAFETY: the safe owner keeps its unique handle live. Native readiness is
    // process-global and may succeed at most once.
    unsafe { t1_service_lifecycle_notify_ready(lifecycle) }
}

pub(super) fn destroy(lifecycle: *mut RawServiceLifecycle) -> c_int {
    // SAFETY: the safe owner transfers the unique handle exactly once.
    unsafe { t1_service_lifecycle_destroy(lifecycle) }
}

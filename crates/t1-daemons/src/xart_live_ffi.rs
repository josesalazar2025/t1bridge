use std::ffi::{CStr, c_char, c_int};
use std::os::fd::{FromRawFd, OwnedFd};

#[derive(Clone, Copy)]
#[repr(C)]
struct RawPeerObservation {
    listener_interface_index: u32,
    peer_scope_id: u32,
    peer_port: u16,
    peer_address: [u8; 16],
}

unsafe extern "C" {
    fn t1_ncm_ready_prepare_for_interface(expected_interface: *const c_char) -> c_int;
    fn t1_xart_interface_discover(interface_index: *mut u32) -> c_int;
    fn t1_xart_listener_open(listener_descriptor: *mut c_int, interface_index: *mut u32) -> c_int;
    fn t1_xart_listener_accept(
        listener_descriptor: c_int,
        connection_descriptor: *mut c_int,
        observation: *mut RawPeerObservation,
    ) -> c_int;
}

pub(super) fn prepare_ncm_link(expected_interface: &CStr) -> Result<(), c_int> {
    // SAFETY: The pointer is NUL-terminated and remains valid for this call.
    // Native code uses the name only to bind the device-triggered instance to
    // the independently validated kernel index; it does not retain it.
    let status = unsafe { t1_ncm_ready_prepare_for_interface(expected_interface.as_ptr()) };
    if status == 0 { Ok(()) } else { Err(status) }
}

pub(super) fn discover_interface() -> Result<u32, c_int> {
    let mut interface_index = 0;
    // SAFETY: The output points to an initialized writable value. The native
    // function opens no resource and returns only a validated kernel index.
    let status = unsafe { t1_xart_interface_discover(&raw mut interface_index) };
    if status != 0 {
        return Err(status);
    }
    if interface_index == 0 {
        return Err(-1);
    }
    Ok(interface_index)
}

pub(super) struct OpenedListener {
    pub descriptor: OwnedFd,
    pub interface_index: u32,
}

pub(super) struct AcceptedConnection {
    pub descriptor: OwnedFd,
    pub listener_interface_index: u32,
    pub peer_scope_id: u32,
    pub peer_port: u16,
    pub peer_address: [u8; 16],
}

pub(super) fn open_listener() -> Result<OpenedListener, c_int> {
    let mut descriptor = -1;
    let mut interface_index = 0;
    // SAFETY: Both outputs point to initialized writable values. The native
    // contract transfers one descriptor only when it returns success.
    let status = unsafe { t1_xart_listener_open(&raw mut descriptor, &raw mut interface_index) };
    if status != 0 {
        return Err(status);
    }
    if descriptor < 0 {
        return Err(-1);
    }
    // SAFETY: Successful native open transfers unique ownership of descriptor.
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    if interface_index == 0 {
        return Err(-1);
    }
    Ok(OpenedListener {
        descriptor,
        interface_index,
    })
}

pub(super) fn accept(listener_descriptor: c_int) -> Result<AcceptedConnection, c_int> {
    let mut descriptor = -1;
    let mut observation = RawPeerObservation {
        listener_interface_index: 0,
        peer_scope_id: 0,
        peer_port: 0,
        peer_address: [0; 16],
    };
    // SAFETY: The outputs point to initialized writable values and the input
    // descriptor remains borrowed. Success transfers only the accepted fd.
    let status = unsafe {
        t1_xart_listener_accept(
            listener_descriptor,
            &raw mut descriptor,
            &raw mut observation,
        )
    };
    if status != 0 {
        return Err(status);
    }
    if descriptor < 0 {
        return Err(-1);
    }
    // SAFETY: Successful native accept transfers unique ownership of descriptor.
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    if observation.listener_interface_index == 0 {
        return Err(-1);
    }
    Ok(AcceptedConnection {
        descriptor,
        listener_interface_index: observation.listener_interface_index,
        peer_scope_id: observation.peer_scope_id,
        peer_port: observation.peer_port,
        peer_address: observation.peer_address,
    })
}

//! Privileged Touch Bar display, input, and typed key-synthesis service.

pub mod client_state;
pub mod digitizer;
pub mod frame_state;
pub mod input_state;
pub mod packet;
#[cfg(feature = "service")]
pub mod service;
#[cfg(feature = "service")]
mod touchid_cancel;
#[cfg(feature = "service")]
#[allow(unsafe_code)]
mod touchid_cancel_ffi;
pub mod wire;

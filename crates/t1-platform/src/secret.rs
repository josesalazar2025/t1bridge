//! Optimizer-resistant clearing for explicit caller-owned secret buffers.

use crate::ffi;

/// Overwrites every byte in one caller-owned secret buffer.
///
/// This clears only the supplied allocation. It cannot erase copies made by
/// the compiler or another component, and it does not protect a live process
/// from a privileged observer.
pub fn wipe(bytes: &mut [u8]) {
    ffi::wipe_secret(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overwrites_the_exact_mutable_slice() {
        let mut bytes = [0xa5_u8; 10];
        wipe(&mut bytes[2..8]);
        assert_eq!(&bytes[..2], &[0xa5; 2]);
        assert_eq!(&bytes[2..8], &[0; 6]);
        assert_eq!(&bytes[8..], &[0xa5; 2]);

        wipe(&mut []);
    }
}

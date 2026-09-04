//! XOR obfuscation for pointer-shaped bookkeeping that lives in memory for
//! the complete lifetime of an installed hook.

use std::sync::OnceLock;

/// Returns the process-wide obfuscation key.
///
/// The key comes from `getrandom` when available and always mixes at least
/// one address so a deterministic `getrandom` failure still yields a
/// process-specific nonzero value. This is scrambling against casual memory
/// scanning, not cryptography: the key itself is process-readable.
fn process_key() -> usize {
    static KEY: OnceLock<usize> = OnceLock::new();
    *KEY.get_or_init(|| {
        let mut buffer = [0_u8; std::mem::size_of::<usize>()];
        // SAFETY: the stack buffer is writable for the complete call and the
        // flags value zero is the documented no-flags form.
        let result = unsafe {
            syscalls::raw_syscall!(
                syscalls::Sysno::getrandom,
                buffer.as_mut_ptr() as usize,
                buffer.len(),
                0
            )
        };
        let random = usize::from_le_bytes(buffer);
        let stack = &result as *const _ as usize;
        let anchor = process_key as *const () as usize;
        random
            .wrapping_add(stack)
            .wrapping_add(anchor)
            .wrapping_mul(0x9E37_79B9)
            | 1
    })
}

/// Scrambles one pointer-shaped value for storage.
pub(crate) fn encode_usize(value: usize) -> usize {
    value ^ process_key()
}

/// Recovers one value stored by [`encode_usize`].
pub(crate) fn decode_usize(value: usize) -> usize {
    value ^ process_key()
}

/// Scrambles one byte slice for storage.
pub(crate) fn encode_bytes(bytes: &[u8]) -> Vec<u8> {
    xor_stream(bytes)
}

/// Recovers one byte slice stored by [`encode_bytes`].
pub(crate) fn decode_bytes(bytes: &[u8]) -> Vec<u8> {
    xor_stream(bytes)
}

/// Symmetrically switches one stored byte slice between encodings.
///
/// This is the allocation-free form used while a mutation is already holding
/// the only live copy of the decoded material.
pub(crate) fn toggle_bytes_encoding(bytes: &mut [u8]) {
    let key = process_key().to_le_bytes();
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte ^= key[index % key.len()] ^ index as u8;
    }
}

/// Overwrites a decoded buffer so erased material leaves no plaintext copy.
pub(crate) fn erase_bytes(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        // SAFETY: `write_volatile` prevents the compiler from eliding the
        // stores as dead writes to memory about to be dropped.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
}

fn xor_stream(bytes: &[u8]) -> Vec<u8> {
    let key = process_key().to_le_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    for (index, byte) in bytes.iter().enumerate() {
        output.push(byte ^ key[index % key.len()] ^ index as u8);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usize_round_trip_hides_the_original_value() {
        let value = usize::MAX;
        let encoded = encode_usize(value);
        assert_ne!(encoded, value);
        assert_eq!(decode_usize(encoded), value);
    }

    #[test]
    fn byte_round_trip_and_erase() {
        let value = b"trampoline original bytes".to_vec();
        let encoded = encode_bytes(&value);
        assert_ne!(encoded, value);
        let mut decoded = decode_bytes(&encoded);
        assert_eq!(decoded, value);
        erase_bytes(&mut decoded);
        assert!(decoded.iter().all(|byte| *byte == 0));
    }
}

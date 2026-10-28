//! Authoring helpers for Getter workloads that implement `getter.abi.v1`.
//!
//! A workload is a `cdylib` compiled for `wasm32-unknown-unknown`. It must
//! export `memory`, `getter_alloc`, and `getter_execute`, and it must import
//! nothing. This crate supplies the small amount of plumbing that every guest
//! needs: allocation of the input buffer, conversion of the input pointer into
//! a byte slice, and packing of the output pointer and length into the ABI's
//! single `u64` return value.
//!
//! Authors normally only write a handler and invoke
//! [`getter_workload!`]:
//!
//! ```
//! use getter_workload_sdk::getter_workload;
//!
//! fn handler(input: &[u8]) -> Vec<u8> {
//!     input.to_vec()
//! }
//!
//! getter_workload!(handler);
//! ```
//!
//! The generated functions deliberately leak their allocations. The ABI has
//! no deallocation entry point, so the host executes a task in a fresh module
//! instance (or otherwise discards the instance) after reading the output.

// The workload ABI is an `unsafe` FFI boundary. The host is responsible for
// the pointer and length it passes to `getter_execute`; Rust's safety checks
// cannot span that boundary. The rest of this crate is ordinary safe Rust, and
// every `unsafe` block below carries a safety comment. Allow the workspace's
// `unsafe_code` deny here with this explicit, narrow exception.
#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

use std::mem;
use std::vec::Vec;

/// The ABI identifier implemented by this SDK and required by Getter jobs.
pub const ABI_VERSION: &str = "getter.abi.v1";

/// Packs an output pointer and output length into the ABI return word.
///
/// The pointer occupies the high 32 bits and the length the low 32 bits.
#[must_use]
pub const fn pack_output(pointer: u32, length: u32) -> u64 {
    (pointer as u64) << 32 | (length as u64)
}

/// Splits an ABI return word into `(pointer, length)`.
#[must_use]
pub const fn unpack_output(packed: u64) -> (u32, u32) {
    ((packed >> 32) as u32, packed as u32)
}

/// Allocates `length` writable bytes for a task input and transfers ownership
/// to the host.
///
/// At least one byte is allocated even when `length` is zero so that the
/// returned pointer is always non-null. This is the implementation behind the
/// `getter_alloc` export. The allocation is intentionally never freed by the
/// guest; the host is expected to discard the module instance after executing
/// the task.
///
/// The returned pointer is only meaningful inside a 32-bit Wasm guest. Host
/// builds of this crate expose the function for tests and tooling, but the
/// pointer must not be truncated with [`alloc_input`] there.
#[must_use]
pub fn allocate_input(length: u32) -> *mut u8 {
    let capacity = (length as usize).max(1);
    let mut buffer = Vec::<u8>::with_capacity(capacity);
    let pointer = buffer.as_mut_ptr();
    // The host writes into the allocation and the guest reads it back during
    // `getter_execute`; ownership is deliberately leaked to keep it alive.
    mem::forget(buffer);
    pointer
}

/// Returns the Wasm32 address of a fresh input allocation of `length` bytes.
///
/// This is the `getter_alloc` ABI surface. Use [`allocate_input`] instead when
/// compiling for a 64-bit host.
#[must_use]
pub fn alloc_input(length: u32) -> u32 {
    // On wasm32 a pointer is 32 bits, so this conversion is lossless. The
    // macro only uses this function in a Wasm guest.
    allocate_input(length) as u32
}

/// Views `length` bytes at `pointer` as the raw task input.
///
/// # Safety
///
/// For `length > 0`, `pointer` must be a non-null pointer returned by
/// [`allocate_input`] (or otherwise point to at least `length` initialized,
/// readable bytes) and the memory must not be mutated for the lifetime `'a`.
/// Passing a null pointer with a non-zero length panics before any
/// dereference.
pub unsafe fn input_slice<'a>(pointer: u32, length: u32) -> &'a [u8] {
    // SAFETY: The caller upholds the validity and lifetime requirements
    // documented above. `slice_from_raw_parts` checks the null/zero-length
    // combination before constructing the slice.
    unsafe { slice_from_raw_parts(pointer as usize as *const u8, length as usize) }
}

/// Builds a byte slice from a raw pointer, treating a zero length as empty.
///
/// # Safety
///
/// For `length > 0`, `pointer` must be non-null, properly aligned for `u8`,
/// and valid for reads of `length` bytes for the lifetime `'a`.
pub(crate) unsafe fn slice_from_raw_parts<'a>(pointer: *const u8, length: usize) -> &'a [u8] {
    if length == 0 {
        return &[];
    }
    assert!(
        !pointer.is_null(),
        "getter ABI: null input pointer with non-zero input length"
    );
    // SAFETY: The caller guarantees that the pointer is valid for `length`
    // initialized bytes for the lifetime `'a`. `u8` has alignment 1.
    unsafe { std::slice::from_raw_parts(pointer, length) }
}

/// Expands the three `getter.abi.v1` exports around a handler.
///
/// The handler must have the type `fn(&[u8]) -> Vec<u8>`. It receives the raw
/// task input bytes and returns the raw output bytes. Panicking is allowed: a
/// panic in the guest becomes a Wasm trap, which the host records as a failed
/// attempt.
///
/// The expansion defines:
///
/// - `getter_alloc(u32) -> u32`, which names the input allocation exported as
///   [`alloc_input`].
/// - `getter_execute(u32, u32) -> u64`, which copies the handler's output
///   pointer and length into the ABI return word. The output allocation is
///   leaked for the host to read.
///
/// Both functions are exported with C linkage and no Rust name mangling. The
/// enclosing crate must be built as a `cdylib` for `wasm32-unknown-unknown`.
///
/// # Example
///
/// ```
/// use getter_workload_sdk::getter_workload;
///
/// fn handler(input: &[u8]) -> Vec<u8> {
///     format!("saw {} bytes", input.len()).into_bytes()
/// }
///
/// getter_workload!(handler);
/// ```
#[macro_export]
macro_rules! getter_workload {
    ($handler:path) => {
        /// Allocates a task input buffer and returns its Wasm32 address.
        #[allow(unsafe_code)]
        #[unsafe(no_mangle)]
        pub extern "C" fn getter_alloc(length: u32) -> u32 {
            $crate::alloc_input(length)
        }

        /// Runs the workload handler over the task input and returns the
        /// packed `(output_pointer << 32) | output_length`.
        #[allow(unsafe_code)]
        #[unsafe(no_mangle)]
        pub extern "C" fn getter_execute(input_pointer: u32, input_length: u32) -> u64 {
            // SAFETY: The host must allocate the input with `getter_alloc`,
            // initialize `input_length` bytes, and keep the buffer alive and
            // unmodified until this call returns. `getter.abi.v1` makes the
            // host responsible for that contract.
            let input = unsafe { $crate::input_slice(input_pointer, input_length) };

            let output: ::std::vec::Vec<u8> = $handler(input);
            let output_length = output.len();
            let output_pointer = output.as_ptr();

            // The ABI has no `getter_free`. Leaking the output keeps its
            // bytes readable by the host after this function returns; the
            // host reclaims the memory by dropping the module instance.
            ::core::mem::forget(output);

            // Wasm32 has 32-bit pointers and lengths, so neither cast loses
            // information for a valid guest output.
            $crate::pack_output(output_pointer as u32, output_length as u32)
        }
    };
}

#[cfg(test)]
mod tests {
    use super::{
        allocate_input, input_slice, pack_output, slice_from_raw_parts, unpack_output, ABI_VERSION,
    };

    #[test]
    fn abi_version_matches_the_fixed_contract() {
        assert_eq!(ABI_VERSION, "getter.abi.v1");
    }

    #[test]
    fn pack_output_places_pointer_high_and_length_low() {
        assert_eq!(pack_output(0, 0), 0);
        assert_eq!(pack_output(1, 0), 1_u64 << 32);
        assert_eq!(pack_output(0, 1), 1);
        assert_eq!(pack_output(0x1234_5678, 0x9abc_def0), 0x1234_5678_9abc_def0);
    }

    #[test]
    fn unpack_output_round_trips_boundaries() {
        for (pointer, length) in [(0, 0), (1, 1), (u32::MAX, u32::MAX), (0x8000_0000, 42)] {
            assert_eq!(
                unpack_output(pack_output(pointer, length)),
                (pointer, length)
            );
        }
    }

    #[test]
    fn allocation_is_writable_for_the_requested_length() {
        let length = 37_usize;
        let pointer = allocate_input(length as u32);
        assert!(!pointer.is_null());

        // SAFETY: `allocate_input` returned an allocation of at least `length`
        // bytes, and the loops below stay within that allocation.
        unsafe {
            for offset in 0..length {
                pointer.add(offset).write(offset as u8);
            }
            for offset in 0..length {
                assert_eq!(pointer.add(offset).read(), offset as u8);
            }
        }
    }

    #[test]
    fn zero_length_allocation_is_non_null_and_usable() {
        let pointer = allocate_input(0);
        assert!(!pointer.is_null());

        // SAFETY: `allocate_input` always allocates at least one byte, even
        // for a zero-length request.
        unsafe {
            pointer.write(0x7f);
            assert_eq!(pointer.read(), 0x7f);
        }
    }

    #[test]
    fn input_slice_treats_zero_length_as_empty() {
        // SAFETY: a zero-length input needs no valid memory behind the
        // pointer, so the null pointer is acceptable in this case.
        let input = unsafe { input_slice(0, 0) };
        assert!(input.is_empty());
    }

    #[test]
    #[should_panic(expected = "null input pointer with non-zero input length")]
    fn input_slice_rejects_null_pointer_for_non_zero_length() {
        // SAFETY: this call intentionally violates the contract. The helper
        // asserts before dereferencing, so no invalid access occurs.
        let _ = unsafe { input_slice(0, 1) };
    }

    #[test]
    fn slice_helper_reads_initialized_bytes() {
        let bytes = *b"getter";
        // SAFETY: `bytes` is a live array and the slice covers exactly its
        // initialized bytes for the duration of the assertion.
        let view = unsafe { slice_from_raw_parts(bytes.as_ptr(), bytes.len()) };
        assert_eq!(view, &bytes[..]);
    }
}

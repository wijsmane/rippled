use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use std::{panic, slice};

use risc0_ffi_methods::{RISC0_FFI_METHODS_GUEST_ELF, RISC0_FFI_METHODS_GUEST_ID};

#[repr(C)]
pub struct Risc0Bytes {
    pub ptr: *const u8,
    pub len: usize,
}

// input a Rust Vec<u8> and convert it into a Risc0Bytes structure that can be used in C++ 
fn vec_into_ffi_bytes(v: Vec<u8>) -> Risc0Bytes {
    let boxed: Box<[u8]> = v.into_boxed_slice(); // converting Vec<u8> to Box<u8> to ensure correct size 
                                                // (Vec has a capacity which can be greater than the length, but Box has no capacity)
    let len = boxed.len(); // store the len to create a Risc0Bytes
    let ptr = Box::into_raw(boxed) as *mut u8;   // convert boxed into a thin pointer that can be used by C++
    Risc0Bytes { ptr, len }
}

// free up the space that was allocated for the Risc0Bytes structure
#[no_mangle]
pub extern "C" fn risc0_free_bytes(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    unsafe {
        let slice = std::slice::from_raw_parts_mut(ptr, len); // rebuild the pointer &mut [u8]
        let _boxed: Box<[u8]> = Box::from_raw(slice); // recreate a Box<[u8]> to claim the ownership
    }
}

// prove a ZK statement using private witness: priv_bytes
//      right now, the proof is that these journal outputs are derived from the private inputs

// return receipt bytes
//   0  = success (proof generated)
//  -1  = null pointer / empty
//  -2  = internal error / panic / prove/verify failure
#[no_mangle]
pub extern "C" fn risc0_prove_zk_inputs(priv_ptr: *const u8, priv_len: usize) -> Risc0Bytes {
    let result = panic::catch_unwind(|| unsafe {
        // make sure inputs are there
        if priv_ptr.is_null() || priv_len == 0 {
            return Err(());
        }

        // convert raw pointers into slices
        let priv_slice = slice::from_raw_parts(priv_ptr, priv_len);

        let priv_bytes = priv_slice.to_vec();

        // build executor environment
        let mut builder = ExecutorEnv::builder();

        if builder.write(&priv_bytes).is_err() {
            return Err(());
        }

        let env = match builder.build() {
            Ok(env) => env,
            Err(_) => return Err(()),
        };

        let prover = default_prover();

        let prove_info = match prover.prove(env, RISC0_FFI_METHODS_GUEST_ELF) {
            Ok(info) => info,
            Err(_) => return Err(()),
        };

        let receipt_bytes = match bincode::serialize(&prove_info.receipt) {
            Ok(bytes) => bytes,
            Err(_) => return Err(()),
        };

        Ok(vec_into_ffi_bytes(receipt_bytes))
    });

    match result {
        Ok(Ok(bytes)) => bytes,
        _ => Risc0Bytes { ptr: std::ptr::null(), len: 0 },
    }
}

// verify recipet that was returned by risc0_prove_zk_inputs
//   0  = verified
//  -1  = null/empty
//  -2  = decode or verify failure
#[no_mangle]
pub extern "C" fn risc0_verify_receipt(receipt_ptr: *const u8, receipt_len: usize) -> i32 {
    let result = panic::catch_unwind(|| unsafe {
        if receipt_ptr.is_null() || receipt_len == 0 {
            return -1;
        }
        let receipt_slice = slice::from_raw_parts(receipt_ptr, receipt_len);

        let receipt: Receipt = match bincode::deserialize(receipt_slice) {
            Ok(r) => r,
            Err(_) => return -2,
        };

        if receipt.verify(RISC0_FFI_METHODS_GUEST_ID).is_err() {
            return -2;
        }
        0
    });

    match result {
        Ok(code) => code,
        Err(_) => -2,
    }
}

//get the public outputs
#[no_mangle]
pub extern "C" fn risc0_receipt_get_journal(receipt_ptr: *const u8,receipt_len: usize) -> Risc0Bytes {
    let result = std::panic::catch_unwind(|| unsafe {
        if receipt_ptr.is_null() || receipt_len == 0 {
            return Err(());
        }

        let receipt_slice = slice::from_raw_parts(receipt_ptr, receipt_len);

        let receipt: Receipt = match bincode::deserialize(receipt_slice) {
            Ok(r) => r,
            Err(_) => return Err(()),
        };

        let journal: Vec<u8> = match receipt.journal.decode() {
            Ok(v) => v,
            Err(_) => return Err(()),
        };

        Ok(vec_into_ffi_bytes(journal))
    });

    match result {
        Ok(Ok(bytes)) => bytes,
        _ => Risc0Bytes { ptr: std::ptr::null_mut(), len: 0 },
    }
}

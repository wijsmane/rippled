use risc0_zkvm::{default_prover, ExecutorEnv};
use std::{panic, slice};

use risc0_ffi_methods::{RISC0_FFI_METHODS_GUEST_ELF, RISC0_FFI_METHODS_GUEST_ID};

// prove a ZK statement using:
// - public inputs: pub_bytes
// - private witness: priv_bytes

// return:
//   0  = success (proof generated)
//  -1  = null pointer / empty
//  -2  = internal error / panic / prove/verify failure
#[no_mangle]
pub extern "C" fn risc0_prove_zk_inputs(pub_ptr: *const u8, pub_len: usize, priv_ptr: *const u8, priv_len: usize) -> i32 {
    let result = panic::catch_unwind(|| unsafe {
        // make sure inputs are there
        if pub_ptr.is_null() || priv_ptr.is_null() || pub_len == 0 || priv_len == 0 {
            return -1;
        }

        // convert raw pointers into slices
        let pub_slice = slice::from_raw_parts(pub_ptr, pub_len);
        let priv_slice = slice::from_raw_parts(priv_ptr, priv_len);

        let pub_bytes = pub_slice.to_vec();
        let priv_bytes = priv_slice.to_vec();

        // build executor environment
        let mut builder = ExecutorEnv::builder();

        if builder.write(&pub_bytes).is_err() {
            return -2;
        }

        if builder.write(&priv_bytes).is_err() {
            return -2;
        }

        let env = match builder.build() {
            Ok(env) => env,
            Err(_) => return -2,
        };

        let prover = default_prover();

        let prove_info = match prover.prove(env, RISC0_FFI_METHODS_GUEST_ELF) {
            Ok(info) => info,
            Err(_) => return -2,
        };

        if prove_info.receipt.verify(RISC0_FFI_METHODS_GUEST_ID).is_err()
        {
            return -2;
        }

        0 // success
    });

    match result {
        Ok(code) => code,
        Err(_) => -2, // panic occurred
    }
}

use std::os::raw::{c_char, c_int};
use std::ffi::CString;
use std::slice;
use std::ptr;
use risc0_zkvm::{ExecutorEnv, Receipt, Prover};

use risc0_ffi_methods::{RISC0_FFI_METHODS_GUEST_ELF, RISC0_FFI_METHODS_GUEST_ID};

static mut INITIALIZED: bool = false;

#[no_mangle]
pub extern "C" fn risc0_init() -> bool {
    unsafe {
        if INITIALIZED {
            return true;
        }
        INITIALIZED = true;
    }
    true
}

//some functions just to test
#[no_mangle]
pub extern "C" fn risc0_add(a: c_int, b: c_int) -> c_int {
    a + b
}

#[no_mangle]
pub extern "C" fn risc0_hello() -> *mut c_char {
    match CString::new("Hello from RISC0!") {
        Ok(s) => s.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn risc0_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

#[no_mangle]
pub extern "C" fn risc0_create_proof(
    input_data: *const u8,
    input_len: usize,
    proof_data: *mut *mut u8,
    proof_len: *mut usize,
) -> bool {
    if input_data.is_null() || proof_data.is_null() || proof_len.is_null() {
        eprintln!("[RISC0] Error: Null pointer passed to risc0_create_proof");
        return false;
    }

    let input_slice = unsafe { slice::from_raw_parts(input_data, input_len) };
    let input_vec = input_slice.to_vec();

    // build zkVM environment and give it the inputs
    let env = match ExecutorEnv::builder()
        .write(&input_vec)
        .unwrap()
        .build()
    {
        Ok(env) => env,
        Err(e) => {
            eprintln!("[RISC0] Error building executor environment: {:?}", e);
            return false;
        }
    };

    // use local prover to generate proofs
    use risc0_zkvm::LocalProver;
    let prover = LocalProver::new("local");

    // proves the inputs againt the elf (guest/src/main.rs)
    let prove_info = match prover.prove(env, RISC0_FFI_METHODS_GUEST_ELF) {
        Ok(info) => info,
        Err(e) => {
            eprintln!("[RISC0] Error generating proof: {:?}", e);
            return false;
        }
    };

    let receipt = prove_info.receipt;

    let serialized = match bincode::serialize(&receipt) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("[RISC0] Error serializing receipt: {:?}", e);
            return false;
        }
    };

    let len = serialized.len();
    let boxed = serialized.into_boxed_slice();

    unsafe {
        *proof_data = Box::into_raw(boxed) as *mut u8;
        *proof_len = len;
    }

    eprintln!("[RISC0] Proof generated successfully, size: {} bytes", len);
    true
}

#[no_mangle]
pub extern "C" fn risc0_verify_proof(
    proof_data: *const u8,
    proof_len: usize,
) -> bool {
    if proof_data.is_null() {
        eprintln!("[RISC0] Error: Null pointer passed to risc0_verify_proof");
        return false;
    }

    let proof_slice = unsafe { slice::from_raw_parts(proof_data, proof_len) };

    let receipt: Receipt = match bincode::deserialize(proof_slice) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[RISC0] Error deserializing receipt: {:?}", e);
            return false;
        }
    };

    match receipt.verify(RISC0_FFI_METHODS_GUEST_ID) {
        Ok(_) => {
            eprintln!("[RISC0] Proof verified successfully");
            true
        }
        Err(e) => {
            eprintln!("[RISC0] Proof verification failed: {:?}", e);
            false
        }
    }
}

#[no_mangle]
pub extern "C" fn risc0_free_proof(proof_data: *mut u8, proof_len: usize) {
    if !proof_data.is_null() && proof_len > 0 {
        unsafe {
            let _ = Vec::from_raw_parts(proof_data, proof_len, proof_len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = risc0_add(2, 2);
        assert_eq!(result, 4);
    }
}

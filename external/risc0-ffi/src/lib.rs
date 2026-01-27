//host code for use in C++

use risc0_zkvm::{default_prover, ExecutorEnv};
use sha2::{Digest, Sha512};
use std::{panic, slice};

use risc0_ffi_methods::{RISC0_FFI_METHODS_GUEST_ELF, RISC0_FFI_METHODS_GUEST_ID};

//just testing proof 

// sha512Half function to compute the first 32 bytes of the SHA-512 hash
fn sha512_half(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result[..32]);
    out
}

/* prove that the given XRPL transaction blob has the given tx hash

 return:
   0  = success (proof generated & verified)
 - 1  = null pointer
  -2  = panic or internal error */
#[no_mangle]
pub extern "C" fn risc0_prove_tx(tx_ptr: *const u8, tx_len: usize) -> i32 {
    let result = panic::catch_unwind(|| unsafe {
        if tx_ptr.is_null() || tx_len == 0 {
            return Err(-1);
        }

        // Turn raw pointer into slice
        let tx_blob_slice: &[u8] = slice::from_raw_parts(tx_ptr, tx_len);
        // Make it an owned Vec<u8> so it's Sized and Serializable
        let tx_blob: Vec<u8> = tx_blob_slice.to_vec();

        // Compute expected_tx_hash = sha512Half("TXN\0" || tx_blob)
        const TX_PREFIX: [u8; 4] = [0x54, 0x58, 0x4E, 0x00]; // "TXN\0"

        let mut hash_input = Vec::with_capacity(TX_PREFIX.len() + tx_blob.len());
        hash_input.extend_from_slice(&TX_PREFIX);
        hash_input.extend_from_slice(&tx_blob);

        let expected_tx_hash = sha512_half(&hash_input);

        // build env in same order to match guest
        let mut builder = ExecutorEnv::builder();
        builder.write(&tx_blob).map_err(|_| -2)?;           // tx_blob first env::read() in guest
        builder.write(&expected_tx_hash).map_err(|_| -2)?;  // expected_tx_hash second
        let env = builder.build().map_err(|_| -2)?;

        let prover = default_prover();

        // Run prover with guest ELF
        let prove_info = prover
            .prove(env, RISC0_FFI_METHODS_GUEST_ELF)
            .map_err(|_| -2)?;

        // Verify the receipt with image ID
        prove_info.receipt.verify(RISC0_FFI_METHODS_GUEST_ID).map_err(|_| -2)?;

        Ok(0)
    });

    match result {
        Ok(Ok(code)) => code,
        Ok(Err(code)) => code,
        Err(_) => -2,
    }
}

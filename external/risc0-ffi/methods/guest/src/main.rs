#![no_main]

use risc0_zkvm::guest::env;
use sha2::{Digest, Sha512};

risc0_zkvm::guest::entry!(main);

/* this is the guest program - add logic to check if transaction is valid (this is the code that will be proven)
    read tx data env::read()
    commit result env::commit()
*/

// XRPL uses sha512Half for txID: SHA-512, then first 32 bytes
fn sha512_half(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    let result = hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&result[..32]);
    out
}

// prove that a given transaction blob (private input) actually hashes to the (publicly) claimed XRPL transaction ID
fn main() {
    // private input: serialized tx
    let tx_blob: Vec<u8> = env::read();

    // public input: expected transaction hash
    let expected_tx_hash: [u8; 32] = env::read();

    //compute the txID = sha512Half(HashPrefix::transactionID || tx_blob)
    // HashPrefix::transactionID is "TXN\0" -> 0x54 0x58 0x4E 0x00
    const TX_PREFIX: [u8; 4] = [0x54, 0x58, 0x4E, 0x00];

    let mut data = Vec::with_capacity(TX_PREFIX.len() + tx_blob.len());
    data.extend_from_slice(&TX_PREFIX);
    data.extend_from_slice(&tx_blob);

    let tx_hash = sha512_half(&data);

    // make sure computed hash equals public one
    assert_eq!(tx_hash, expected_tx_hash);

    // commit hash to journal (public output) so the host can see what was computed
    env::commit(&tx_hash);
}

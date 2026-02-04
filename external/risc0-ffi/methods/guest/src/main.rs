#![no_main]

use risc0_zkvm::guest::env;
use sha2::{Digest, Sha512};

risc0_zkvm::guest::entry!(main);

/* this is the guest program - logic to check if transaction is valid (this is the code that will be proven)
    read input tx data env::read()
    commit public outputs env::commit() (anyone can read these, not just verifier)
*/

// sha512half helper
fn sha512_half_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    for p in parts {
        hasher.update(p);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

fn compute_commitment(value_be: &[u8; 8], rho: &[u8; 32], r: &[u8; 32], a_pk: &[u8; 32]) -> [u8; 32] {
    sha512_half_parts(&[
        &[0x01],
        value_be,
        rho,
        r,
        a_pk,
    ])
}

// nullifier = sha512Half( 0x02 || a_sk(32) || rho(32) )
fn compute_nullifier(a_sk: &[u8; 32], rho: &[u8; 32]) -> [u8; 32] {
    sha512_half_parts(&[
        &[0x02],
        a_sk,
        rho,
    ])
}

fn main() {
    // read from host
    let priv_bytes: Vec<u8> = env::read();

    // private = value(8) || rho(32) || r(32) || a_pk(32) || a_sk(32)
    assert_eq!(priv_bytes.len(), 136);

    //split to get all the inputs
    let amount: [u8; 8] = priv_bytes[0..8].try_into().unwrap(); //8 for amount
    let rho: [u8; 32]     = priv_bytes[8..40].try_into().unwrap(); //32 for uniqueness randomizer
    let r: [u8; 32]       = priv_bytes[40..72].try_into().unwrap(); //32 for commitment randomness
    let a_pk: [u8; 32]    = priv_bytes[72..104].try_into().unwrap(); //32 for paying key   
    let a_sk: [u8; 32]    = priv_bytes[104..136].try_into().unwrap(); //32 for spending key

    // compute
    let cm = compute_commitment(&amount, &rho, &r, &a_pk);
    let nf = compute_nullifier(&a_sk, &rho);

    // commit the commitment and nullifier to the journal so they can be put into the transaction data
    let mut j = Vec::with_capacity(64);
    j.extend_from_slice(&cm);
    j.extend_from_slice(&nf);
    env::commit(&j);
    
}

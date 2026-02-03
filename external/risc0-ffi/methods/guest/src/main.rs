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
    // read in the same order that the host writes
    let pub_bytes: Vec<u8> = env::read();
    let priv_bytes: Vec<u8> = env::read();

    // public = commitment(32) || nullifier(32)
    assert_eq!(pub_bytes.len(), 64);

    // split the public bytes to get the computed commitment and nullifier that will be checked
    let pub_commitment: [u8; 32] = pub_bytes[0..32].try_into().unwrap();
    let pub_nullifier:  [u8; 32] = pub_bytes[32..64].try_into().unwrap();

    // private = value(8) || rho(32) || r(32) || a_pk(32) || a_sk(32)
    assert_eq!(priv_bytes.len(), 136);

    //split to get all the inputs
    let amount: [u8; 8] = priv_bytes[0..8].try_into().unwrap(); //8 for amount
    let rho: [u8; 32]     = priv_bytes[8..40].try_into().unwrap(); //32 for uniqueness randomizer
    let r: [u8; 32]       = priv_bytes[40..72].try_into().unwrap(); //32 for commitment randomness
    let a_pk: [u8; 32]    = priv_bytes[72..104].try_into().unwrap(); //32 for paying key   
    let a_sk: [u8; 32]    = priv_bytes[104..136].try_into().unwrap(); //32 for spending key

    //recompute
    let cm = compute_commitment(&value_be, &rho, &r, &a_pk);
    let nf = compute_nullifier(&a_sk, &rho);

    assert_eq!(cm, pub_commitment);
    assert_eq!(nf, pub_nullifier);

    // commit the public commitment and nullifier to the journal so others can use to verify
    env::commit(&pub_commitment);
    env::commit(&pub_nullifier);

}

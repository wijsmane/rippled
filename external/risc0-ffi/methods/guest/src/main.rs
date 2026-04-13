#![no_main]

use risc0_zkvm::guest::env;
use sha2::{Digest, Sha512};

risc0_zkvm::guest::entry!(main);

/* this is the guest program - logic to compute cm/nf (this is the code that will be proven)
    read input tx data env::read()
    commit public outputs env::commit() (anyone can read these, not just verifier)
*/

const MODE_DEPOSIT: u8 = 1;
const MODE_SPEND: u8 = 2;

// sha256 helper
fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for p in parts {
        hasher.update(p);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

// commitment = sha256( 0x01 || amount(8) || rho(32) || r(32) || a_pk(32) )
fn compute_commitment(
    amount: &[u8; 8],
    rho: &[u8; 32],
    r: &[u8; 32],
    a_pk: &[u8; 32],
) -> [u8; 32] {
    sha256_parts(&[
        &[0x01][..],
        amount.as_slice(),
        rho.as_slice(),
        r.as_slice(),
        a_pk.as_slice(),
    ])
}

// nullifier = sha256( 0x02 || a_sk(32) || rho(32) )
fn compute_nullifier(a_sk: &[u8; 32], rho: &[u8; 32]) -> [u8; 32] {
    sha256_parts(&[
        &[0x02][..],
        a_sk.as_slice(),
        rho.as_slice(),
    ])
}

fn main() {
    let input: Vec<u8> = env::read();
    assert!(!input.is_empty(), "empty witness");

    let mode = input[0];

    match mode {
        MODE_DEPOSIT => {
            assert_eq!(input.len(), 105, "bad deposit witness length");

            let amount: [u8; 8] = input[1..9].try_into().unwrap();
            let rho: [u8; 32] = input[9..41].try_into().unwrap();
            let r: [u8; 32] = input[41..73].try_into().unwrap();
            let a_pk: [u8; 32] = input[73..105].try_into().unwrap();

            let cm = compute_commitment(&amount, &rho, &r, &a_pk);

            let mut j = Vec::with_capacity(1 + 32);
            j.push(MODE_DEPOSIT);
            j.extend_from_slice(&cm);
            env::commit(&j);
        }

        MODE_SPEND => {
            assert_eq!(input.len(), 137, "bad spend witness length");

            let amount: [u8; 8] = input[1..9].try_into().unwrap();
            let rho: [u8; 32] = input[9..41].try_into().unwrap();
            let r: [u8; 32] = input[41..73].try_into().unwrap();
            let a_pk: [u8; 32] = input[73..105].try_into().unwrap();
            let a_sk: [u8; 32] = input[105..137].try_into().unwrap();

            let cm_old = compute_commitment(&amount, &rho, &r, &a_pk);
            let nf = compute_nullifier(&a_sk, &rho);

            let mut j = Vec::with_capacity(1 + 32 + 32);
            j.push(MODE_SPEND);
            j.extend_from_slice(&cm_old);
            j.extend_from_slice(&nf);
            env::commit(&j);
        }

        _ => panic!("invalid mode"),
    }
}
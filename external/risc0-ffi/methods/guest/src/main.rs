#![no_main]

use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

/* this is where to add logic to check if transaction is valid (this is the code that will be proven)
    read tx data env::read()
    commit result env::commit()
*/

// example
fn main() {
    let input: Vec<u8> = env::read();
    
    let output: Vec<u8> = input.iter().map(|x| x.wrapping_add(1)).collect();
    
    env::commit(&output);
}

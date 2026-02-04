#ifndef RISC0_FFI_H
#define RISC0_FFI_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif



// structure to hold bytes
struct Risc0Bytes
{
    std::uint8_t* ptr;
    std::size_t len;
};

// prove using private inputs
Risc0Bytes risc0_prove_zk_inputs(const uint8_t* priv_ptr, size_t priv_len);

// verify a receipt, success = 0
int risc0_verify_receipt(const std::uint8_t* receipt_ptr, std::size_t receipt_len);

// free bytes returned from rust
void risc0_free_bytes(std::uint8_t* ptr, std::size_t len);

Risc0Bytes risc0_receipt_get_journal(const std::uint8_t* receipt_ptr, std::size_t receipt_len);


#ifdef __cplusplus
}
#endif

#endif

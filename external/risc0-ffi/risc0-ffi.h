#ifndef RISC0_FFI_H
#define RISC0_FFI_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

// initialise risc0
bool risc0_init(void);


int risc0_add(int a, int b);
char* risc0_hello();

bool risc0_create_proof(
    const uint8_t* input_data,
    size_t input_len,
    uint8_t** proof_out,
    size_t* proof_len
);

bool risc0_verify_proof(
    const uint8_t* proof_data,
    size_t proof_len
);

void risc0_free_string(char* str);

void risc0_free_proof(uint8_t* proof_data, size_t proof_len);

#ifdef __cplusplus
}
#endif

#endif

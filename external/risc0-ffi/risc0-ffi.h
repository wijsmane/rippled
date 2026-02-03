#ifndef RISC0_FFI_H
#define RISC0_FFI_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>


int // private inputs, public inputs, and full tx blob
risc0_prove_zk_inputs(const uint8_t* pub_ptr, size_t pub_len, const uint8_t* priv_ptr, size_t priv_len);


#ifdef __cplusplus
}
#endif

#endif

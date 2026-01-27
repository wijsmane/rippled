#ifndef RISC0_FFI_H
#define RISC0_FFI_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>


int
risc0_prove_tx(unsigned char const* tx_ptr, std::size_t tx_len);


#ifdef __cplusplus
}
#endif

#endif

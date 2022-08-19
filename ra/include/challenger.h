#ifndef RATLS_CHALLENGER_H_
#define RATLS_CHALLENGER_H_

#include "stdint.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Verify SGX-related X.509 extensions.
 * @return 0 if verification succeeds, 1 otherwise.
 */
int verify_sgx_cert_extensions
(
  uint8_t* der_crt,
  uint32_t der_crt_len
);

#ifdef __cplusplus
}
#endif

#endif  // RATLS_CHALLENGER_H_
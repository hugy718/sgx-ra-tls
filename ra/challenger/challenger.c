#ifndef SGX_SDK

#define _GNU_SOURCE // for memmem()

#endif // SGX_SDK

#include "challenger.h"
#include "challenger_internal.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sgx_quote.h>

#include "ra.h"

// used in trusted and untrusted
// put as verify callback
int verify_sgx_cert_extensions
(
    uint8_t* der_crt,
    uint32_t der_crt_len
)
{
    if (is_epid_ratls_cert(der_crt, der_crt_len)) {
        return epid_verify_sgx_cert_extensions(der_crt, der_crt_len);
    } else {
        return ecdsa_verify_sgx_cert_extensions(der_crt, der_crt_len);
    }
}

int ecdsa_verify_quote(uint8_t* quote_buf, uint32_t quote_len) {
  // get supplemental data
  uint32_t supplemental_data_size = 0;
  quote3_error_t q_ret = ecdsa_get_supplemental_data_size(
    &supplemental_data_size);
  if (q_ret != SGX_QL_SUCCESS) return -1;

  uint8_t* supplemental_data_buf = (uint8_t*) malloc(supplemental_data_size);
  if (supplemental_data_buf == NULL) return -1;

  q_ret = ecdsa_verify_quote_common(quote_buf, quote_len,
    supplemental_data_buf, supplemental_data_size);

  if (supplemental_data_buf) free(supplemental_data_buf);
  return (q_ret == SGX_QL_SUCCESS) ? 0 : -1;
}

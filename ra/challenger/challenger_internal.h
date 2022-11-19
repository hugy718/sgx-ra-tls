#ifndef RATLS_CHALLENGER_INTERNAL_H_
#define RATLS_CHALLENGER_INTERNAL_H_

#include <stdint.h>
#include <stddef.h>

#include <sgx_quote.h>
// ecdsa
#include <sgx_ql_lib_common.h>

#include "ra.h"

/**
 * @return 1 if it is an EPID-based attestation RA-TLS
 * certificate. Otherwise, 0.
 */
int is_epid_ratls_cert
(
    const uint8_t* der_crt,
    uint32_t der_crt_len
);

void epid_extract_x509_extensions
(
    const uint8_t* ext,
    uint32_t ext_len,
    attestation_verification_report_t* attn_report
);

void get_quote_from_ias_report
(
    const uint8_t* report /* in */,
    const uint32_t report_len  /* in */,
    sgx_quote_t* quote
);

int epid_verify_sgx_cert_extensions
(
    uint8_t* der_crt,
    uint32_t der_crt_len
);


quote3_error_t ecdsa_get_supplemental_data_size(uint32_t* supplemental_data_size);

quote3_error_t ecdsa_verify_quote_common(
  uint8_t* quote_buf, uint32_t quote_len,
  uint8_t* supplemental_data_buf, uint32_t supplemental_data_size);

int ecdsa_verify_quote(uint8_t* quote_buf, uint32_t quote_len);

int ecdsa_verify_sgx_cert_extensions
(
    uint8_t* der_crt,
    uint32_t der_crt_len
);

#endif  // RATLS_CHALLENGER_INTERNAL_H_

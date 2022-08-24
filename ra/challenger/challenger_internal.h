#ifndef RATLS_CHALLENGER_INTERNAL_H_
#define RATLS_CHALLENGER_INTERNAL_H_

#include <stdint.h>
#include <stddef.h>

#include <sgx_quote.h>

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

void extract_x509_extensions
(
    const uint8_t* ext,
    uint32_t ext_len,
    attestation_verification_report_t* attn_report
);

void get_quote_from_report
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

#endif  // RATLS_CHALLENGER_INTERNAL_H_

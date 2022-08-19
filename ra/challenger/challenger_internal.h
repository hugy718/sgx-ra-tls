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

int extract_x509_extension
(
    const uint8_t* ext,
    int ext_len,
    const uint8_t* oid,
    size_t oid_len,
    uint8_t* data,
    uint32_t* data_len,
    uint32_t data_max_len
);

void extract_x509_extensions
(
    const uint8_t* ext,
    int ext_len,
    attestation_verification_report_t* attn_report
);

int epid_verify_sgx_cert_extensions
(
    uint8_t* der_crt,
    uint32_t der_crt_len
);

#endif  // RATLS_CHALLENGER_INTERNAL_H_

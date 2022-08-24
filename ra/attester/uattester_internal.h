#ifndef RATLS_UATTESTER_INTERNAL_H_
#define RATLS_UATTESTER_INTERNAL_H_

#include <stdint.h>

#include "ra.h"
#include "attester.h"

void base64_encode
(
    const uint8_t *in,
    uint32_t in_len,
    uint8_t* out,
    uint32_t* out_len /* in/out */
);

void obtain_attestation_verification_report(
    const sgx_quote_t* quote,
    const uint32_t quote_size,
    const struct ra_tls_options* opts,
    attestation_verification_report_t* attn_report
);
    
#endif  // RATLS_UATTESTER_INTERNAL_H_

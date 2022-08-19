#ifndef RATLS_TATTESTER_H_
#define RATLS_TATTESTER_H_

#include "attester.h"
#ifdef __cplusplus
extern "C" {
#endif

void create_key_and_x509
(
    uint8_t* der_key,
    int* der_key_len,
    uint8_t* der_cert,
    int* der_cert_len,
    const struct ra_tls_options* opts
);

#ifdef __cplusplus
}
#endif

#endif  // RATLS_TATTESTER_H_

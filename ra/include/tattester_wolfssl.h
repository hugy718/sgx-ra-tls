#ifndef RATLS_TATTESTER_WOLFSSL_H_
#define RATLS_TATTESTER_WOLFSSL_H_

#include <stdint.h>

#include "wolfssl/options.h"
#include "wolfssl/ssl.h"

#ifdef __cplusplus
extern "C" {
#endif

void wolfssl_create_key_and_x509_ctx(WOLFSSL_CTX* ctx);

#ifdef __cplusplus
}
#endif

#endif  // RATLS_TATTESTER_WOLFSSL_H_

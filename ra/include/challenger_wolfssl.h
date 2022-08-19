#ifndef RATLS_CHALLENGER_WOLFSSL_H_
#define RATLS_CHALLENGER_WOLFSSL_H_

#include "wolfssl/options.h"
#include "wolfssl/ssl.h"

#ifdef __cplusplus
extern "C" {
#endif

int cert_verify_callback(int preverify, WOLFSSL_X509_STORE_CTX* store);

#ifdef __cplusplus
};
#endif

#endif  // RATLS_CHALLENGER_WOLFSSL_H_

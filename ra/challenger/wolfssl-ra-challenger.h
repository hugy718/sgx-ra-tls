#ifndef _WOLFSSL_RA_CHALLENGER_H_
#define _WOLFSSL_RA_CHALLENGER_H_

#include "wolfssl/ssl.h"

#ifdef __cplusplus
extern "C" {
#endif

int cert_verify_callback(int preverify, WOLFSSL_X509_STORE_CTX* store);

#ifdef __cplusplus
};
#endif

#endif  // _WOLFSSL_RA_CHALLENGER_H_

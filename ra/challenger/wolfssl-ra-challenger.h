#ifndef _WOLFSSL_RA_CHALLENGER_H_
#define _WOLFSSL_RA_CHALLENGER_H_

#include "wolfssl/ssl.h"

int cert_verify_callback(int preverify, WOLFSSL_X509_STORE_CTX* store);

#endif  // _WOLFSSL_RA_CHALLENGER_H_

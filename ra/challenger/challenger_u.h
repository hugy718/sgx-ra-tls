#ifndef CHALLENGER_U_H__
#define CHALLENGER_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "wolfssl/ssl.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t enc_wolfSSL_CTX_set_ratls_verify(sgx_enclave_id_t eid, WOLFSSL_CTX* ctx);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

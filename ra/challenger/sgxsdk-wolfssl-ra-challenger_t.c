#include "ra/challenger/wolfssl-ra-challenger.h"

#include "challenger_t.h"
#include "wolfssl-ra-challenger.h"

// only for trusted. ecall implementation

void enc_wolfSSL_CTX_set_ratls_verify(WOLFSSL_CTX* ctx) {
    if(sgx_is_within_enclave(ctx, wolfSSL_CTX_GetObjectSize()) != 1)
        abort();
    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, cert_verify_callback);
}
#include "wolfssl/options.h"
#include "wolfssl/ssl.h"

#include <stdlib.h>

#include "challenger_wolfssl.h"
#include "tattester_wolfssl.h"

void enc_wolfSSL_Debugging_ON(void)
{
    wolfSSL_Debugging_ON();
}

void enc_wolfSSL_Debugging_OFF(void)
{
    wolfSSL_Debugging_OFF();
}

int enc_wolfSSL_Init(void)
{
    return wolfSSL_Init();
}

WOLFSSL_CTX* enc_wolfSSL_CTX_new(WOLFSSL_METHOD* method)
{
    if(sgx_is_within_enclave(method, wolfSSL_METHOD_GetObjectSize()) != 1)
        abort();
    return wolfSSL_CTX_new(method);
}

WOLFSSL* enc_wolfSSL_new( WOLFSSL_CTX* ctx)
{
    if(sgx_is_within_enclave(ctx, wolfSSL_CTX_GetObjectSize()) != 1)
        abort();
    return wolfSSL_new(ctx);
}

int enc_wolfSSL_set_fd(WOLFSSL* ssl, int fd)
{
    if(sgx_is_within_enclave(ssl, wolfSSL_GetObjectSize()) != 1)
        abort();
    return wolfSSL_set_fd(ssl, fd);
}

int enc_wolfSSL_connect(WOLFSSL* ssl)
{
    if(sgx_is_within_enclave(ssl, wolfSSL_GetObjectSize()) != 1)
        abort();
    return wolfSSL_connect(ssl);
}

int enc_wolfSSL_write(WOLFSSL* ssl, const void* in, size_t sz)
{
    if(sgx_is_within_enclave(ssl, wolfSSL_GetObjectSize()) != 1)
        abort();
    return wolfSSL_write(ssl, in, (int) sz);
}

int enc_wolfSSL_get_error(WOLFSSL* ssl, int ret)
{
    if(sgx_is_within_enclave(ssl, wolfSSL_GetObjectSize()) != 1)
        abort();
    return wolfSSL_get_error(ssl, ret);
}

int enc_wolfSSL_read(WOLFSSL* ssl, void* data, size_t sz)
{
    if(sgx_is_within_enclave(ssl, wolfSSL_GetObjectSize()) != 1)
        abort();
    return wolfSSL_read(ssl, data, (int) sz);
}

void enc_wolfSSL_free(WOLFSSL* ssl)
{
    if(sgx_is_within_enclave(ssl, wolfSSL_GetObjectSize()) != 1)
        abort();
    wolfSSL_free(ssl);
}

void enc_wolfSSL_CTX_free(WOLFSSL_CTX* ctx)
{
    if(sgx_is_within_enclave(ctx, wolfSSL_CTX_GetObjectSize()) != 1)
        abort();
    wolfSSL_CTX_free(ctx);
}

int enc_wolfSSL_Cleanup(void)
{
    return wolfSSL_Cleanup();
}

void enc_create_key_and_x509(WOLFSSL_CTX* ctx) {
  wolfssl_create_key_and_x509_ctx(ctx);
}

void enc_wolfSSL_CTX_set_ratls_verify(WOLFSSL_CTX* ctx) {
  if(sgx_is_within_enclave(ctx, wolfSSL_CTX_GetObjectSize()) != 1)
      abort();
  // enforcing the check of clients certificate
  wolfSSL_CTX_set_verify(ctx,
    SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, cert_verify_callback);
}

WOLFSSL_METHOD* enc_wolfTLSv1_2_server_method(void)
{
    return wolfTLSv1_2_server_method();
}

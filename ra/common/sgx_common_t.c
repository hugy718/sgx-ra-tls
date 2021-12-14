#include <assert.h>
#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "common_t.h"

#include "sgx_trts.h"

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

int enc_wolfSSL_write(WOLFSSL* ssl, const void* in, int sz)
{
    if(sgx_is_within_enclave(ssl, wolfSSL_GetObjectSize()) != 1)
        abort();
    return wolfSSL_write(ssl, in, sz);
}

int enc_wolfSSL_get_error(WOLFSSL* ssl, int ret)
{
    if(sgx_is_within_enclave(ssl, wolfSSL_GetObjectSize()) != 1)
        abort();
    return wolfSSL_get_error(ssl, ret);
}

int enc_wolfSSL_read(WOLFSSL* ssl, void* data, int sz)
{
    if(sgx_is_within_enclave(ssl, wolfSSL_GetObjectSize()) != 1)
        abort();
    return wolfSSL_read(ssl, data, sz);
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

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

int sprintf(char* buf, const char *fmt, ...)
{
    va_list ap;
    int ret;
    va_start(ap, fmt);
    ret = vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    return ret;
}

double current_time(void)
{
    double curr;
    ocall_current_time(&curr);
    return curr;
}

int LowResTimer(void) /* low_res timer */
{
    int time;
    ocall_low_res_time(&time);
    return time;
}

size_t recv(int sockfd, void *buf, size_t len, int flags)
{
    size_t ret;
    // int sgxStatus;
    // sgxStatus = ocall_recv(&ret, sockfd, buf, len, flags);
    ocall_recv(&ret, sockfd, buf, len, flags);
    return ret;
}

size_t send(int sockfd, const void *buf, size_t len, int flags)
{
    size_t ret;
    // int sgxStatus;
    // sgxStatus = ocall_send(&ret, sockfd, buf, len, flags);
    ocall_send(&ret, sockfd, buf, len, flags);
    return ret;
}

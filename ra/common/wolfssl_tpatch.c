#include <assert.h>
#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "sgx_trts.h"
#include "wolfssl/wolfcrypt/wc_port.h"

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

unsigned int LowResTimer(void) /* low_res timer */
{
    unsigned int time;
    ocall_low_res_time(&time);
    return time;
}

long int recv(int sockfd, void *buf, size_t len, int flags)
{
    long int ret;
    return (ocall_recv(&ret, sockfd, buf, len, flags) == -1) ? -1 : ret;
}

long int send(int sockfd, const void *buf, size_t len, int flags)
{
    long int ret;
    return (ocall_send(&ret, sockfd, buf, len, flags) == -1) ? -1 : ret;
}

// gy211216 moved from wolfssl-ra-attester.c
#ifdef WOLFSSL_SGX
time_t XTIME(time_t* tloc) {
    time_t x = 1512498557; /* Dec 5, 2017, 10:29 PDT */
    if (tloc) *tloc = x;
    return x;
}

time_t mktime(struct tm* tm) {
    (void) tm;
    assert(0);
    return (time_t) 0;
}
#endif

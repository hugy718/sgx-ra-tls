#include <assert.h>
#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "Server_Enclave_t.h"

#include "sgx_trts.h"

WOLFSSL_METHOD* enc_wolfTLSv1_2_client_method(void)
{
    return wolfTLSv1_2_client_method();
}

WOLFSSL_METHOD* enc_wolfTLSv1_2_server_method(void)
{
    return wolfTLSv1_2_server_method();
}

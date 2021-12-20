#include <assert.h>
#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "Tclient_Enclave_t.h"

#include "sgx_trts.h"

WOLFSSL_METHOD* enc_wolfTLSv1_2_client_method(void)
{
    return wolfTLSv1_2_client_method();
}

#ifndef RATLS_ATTESTER_H_
#define RATLS_ATTESTER_H_

#include "sgx_quote.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ra_tls_options {
    sgx_spid_t spid;
    sgx_quote_sign_type_t quote_type;
    /* NULL-terminated string of domain name/IP, port and path prefix,
       e.g., api.trustedservices.intel.com/sgx/dev for development and
       api.trustedservices.intel.com/sgx for production. */
    const char ias_server[512];
    const char subscription_key[32];
};

#ifdef __cplusplus
}
#endif

#endif  // RATLS_ATTESTER_H_

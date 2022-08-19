#ifndef RATLS_UCHALLENGER_H_
#define RATLS_UCHALLENGER_H_

#include <stdint.h>

/**
 * Pretty-print information of EPID-based RA-TLS certificate to file descriptor.
 * a simpler workflow that only extract and print (no verification)
 * (used at untrusted side)
 */

void dprintf_ratls_cert
(
    int fd,
    uint8_t* der_crt,
    uint32_t der_crt_len
);

#endif  // RATLS_UCHALLENGER_H_

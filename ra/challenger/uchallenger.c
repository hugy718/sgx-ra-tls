#include "uchallenger.h"

#include <stdio.h>

#include "ra.h"
#include "challenger_internal.h"

static void dprintf_epid_ratls_cert
(
    int fd,
    uint8_t* der_crt,
    uint32_t der_crt_len
)
{
    attestation_verification_report_t report;
    extract_x509_extensions(der_crt, der_crt_len, &report);
    dprintf(fd, "\nIntel Attestation Service Report\n");
    dprintf(fd, "%.*s\n", report.ias_report_len, report.ias_report);

    sgx_quote_t quote = {0, };
    get_quote_from_report(report.ias_report, report.ias_report_len, &quote);
    sgx_report_body_t* body = &quote.report_body;

    dprintf(fd, "MRENCLAVE = ");
    for (int i=0; i < SGX_HASH_SIZE; ++i) dprintf(fd, "%02x", body->mr_enclave.m[i]);
    dprintf(fd, "\n");
    
    dprintf(fd, "MRSIGNER  = ");
    for (int i=0; i < SGX_HASH_SIZE; ++i) dprintf(fd, "%02x", body->mr_signer.m[i]);
    dprintf(fd, "\n");
}

void dprintf_ratls_cert
(
    int fd,
    uint8_t* der_crt,
    uint32_t der_crt_len
)
{
    if (is_epid_ratls_cert(der_crt, der_crt_len)) {
        dprintf_epid_ratls_cert(fd, der_crt, der_crt_len);
    } else {
        // dprintf_ecdsa_ratls_cert(fd, der_crt, der_crt_len);
        dprintf(fd, "Not Using EPID RA");
        return;
    }
}

#include "uchallenger.h"

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
}

// // probably we don't needs this. just use the report from dprintf_epid_ratls_cert to print out mrenclave and mrsigner 
// static void get_quote_from_extension
// (
//     const uint8_t* exts,
//     size_t exts_len,
//     sgx_quote_t* q
// )
// {
//     uint8_t report[2048];
//     uint32_t report_len;
    
//     int rc = extract_x509_extension(exts, exts_len,
//                                     ias_response_body_oid, ias_oid_len,
//                                     report, &report_len, sizeof(report));

//     if (rc == 1) {
//         get_quote_from_report(report, report_len, q);
//         return;
//     }

//     rc = extract_x509_extension(exts, exts_len,
//                                 quote_oid, ias_oid_len,
//                                 report, &report_len, sizeof(report));
//     assert(rc == 1);
//     memcpy(q, report, sizeof(*q));
// }

// // probably we don't needs this. just use the report from dprintf_epid_ratls_cert to print out mrenclave and mrsigner 
// static void get_quote_from_cert
// (
//     const uint8_t* der_crt,
//     uint32_t der_crt_len,
//     sgx_quote_t* q
// )
// {
//     DecodedCert crt;
//     int ret;

//     InitDecodedCert(&crt, (byte*) der_crt, der_crt_len, NULL);
//     InitSignatureCtx(&crt.sigCtx, NULL, INVALID_DEVID);
//     ret = ParseCertRelative(&crt, CERT_TYPE, NO_VERIFY, 0);
//     assert(ret == 0);
    
//     get_quote_from_extension(crt.extensions, crt.extensionsSz, q);

//     FreeDecodedCert(&crt);
// }

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

    // sgx_quote_t quote;
    // get_quote_from_cert(der_crt, der_crt_len, &quote);
    // sgx_report_body_t* body = &quote.report_body;

    // dprintf(fd, "MRENCLAVE = ");
    // for (int i=0; i < SGX_HASH_SIZE; ++i) dprintf(fd, "%02x", body->mr_enclave.m[i]);
    // dprintf(fd, "\n");
    
    // dprintf(fd, "MRSIGNER  = ");
    // for (int i=0; i < SGX_HASH_SIZE; ++i) dprintf(fd, "%02x", body->mr_signer.m[i]);
    // dprintf(fd, "\n");
}

#include <assert.h>
#include <string.h>

#include <sgx_uae_service.h>

#include "ra.h"
#include "ra-attester.h"
#include "ra_private.h"
#include "attester_t.h" // OCALLs

/* Trusted portion (called from within the enclave) to do remote
   attestation with the SGX SDK.  */
void do_remote_attestation
(
    sgx_report_data_t* report_data,
    const struct ra_tls_options* opts,
    attestation_verification_report_t* attn_report
)
{
    sgx_target_info_t target_info = {0, };
    ocall_sgx_init_quote(&target_info);

    sgx_report_t report = {0, };
    sgx_status_t status = sgx_create_report(&target_info, report_data, &report);
    assert(status == SGX_SUCCESS);

    ocall_remote_attestation(&report, opts, attn_report);
}

void ra_tls_create_report(
    sgx_report_t* report
)
{
    sgx_target_info_t target_info = {0, };
    sgx_report_data_t report_data = {0, };
    memset(report, 0, sizeof(*report));

    sgx_create_report(&target_info, &report_data, report);
}

extern struct ra_tls_options my_ra_tls_options;

void wolfssl_create_key_and_x509_ctx(WOLFSSL_CTX* ctx) {
    uint8_t der_key[2048];
    uint8_t der_cert[8 * 1024];
    int der_key_len = 2048;
    int der_cert_len = 8 * 1024;

    create_key_and_x509(der_key, &der_key_len,
                        der_cert, &der_cert_len,
                        &my_ra_tls_options);

    int ret;
    ret = wolfSSL_CTX_use_certificate_buffer(ctx, der_cert, der_cert_len,
                                             SSL_FILETYPE_ASN1);
    assert(ret == SSL_SUCCESS);

    wolfSSL_CTX_use_PrivateKey_buffer(ctx, der_key, der_key_len,
                                      SSL_FILETYPE_ASN1);
    assert(ret == SSL_SUCCESS);
}

void enc_create_key_and_x509(WOLFSSL_CTX* ctx) {
  wolfssl_create_key_and_x509_ctx(ctx);
}

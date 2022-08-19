#define _GNU_SOURCE // for memmem()
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sgx_report.h>
#include <sgx_uae_service.h>

#include "ra.h"
#include "attester.h"
#include "curl_helper.h"
#include "uattester_internal.h"

// for base64_encode only
#include "wolfssl/wolfcrypt/coding.h"

/* Untrusted code to do remote attestation with the SGX SDK. */

static const char pem_marker_begin[] = "-----BEGIN CERTIFICATE-----";
static const char pem_marker_end[] = "-----END CERTIFICATE-----";

static void extract_certificates_from_response_header
(
    CURL* curl,
    const char* header,
    size_t header_len,
    attestation_verification_report_t* attn_report
)
{
    // Locate x-iasreport-signature HTTP header field in the response.
    const char response_header_name[] = "X-IASReport-Signing-Certificate: ";
    char *field_begin = memmem(header,
                               header_len,
                               response_header_name,
                               strlen(response_header_name));
    assert(field_begin != NULL);
    field_begin += strlen(response_header_name);
    const char http_line_break[] = "\r\n";
    char *field_end = memmem(field_begin,
                             header_len - (field_begin - header),
                             http_line_break,
                             strlen(http_line_break));
    size_t field_len = field_end - field_begin;

    // Remove urlencoding from x-iasreport-signing-certificate field.
    int unescaped_len = 0;
    char* unescaped = curl_easy_unescape(curl,
                                         field_begin,
                                         field_len,
                                         &unescaped_len);
    
    char* cert_begin = memmem(unescaped,
                              unescaped_len,
                              pem_marker_begin,
                              strlen(pem_marker_begin));
    assert(cert_begin != NULL);
    char* cert_end = memmem(unescaped, unescaped_len,
                            pem_marker_end, strlen(pem_marker_end));
    assert(cert_end != NULL);
    uint32_t cert_len = cert_end - cert_begin + strlen(pem_marker_end);

    assert(cert_len <= sizeof(attn_report->ias_sign_cert));
    memcpy(attn_report->ias_sign_cert, cert_begin, cert_len);
    attn_report->ias_sign_cert_len = cert_len;
    
    cert_begin = memmem(cert_end,
                        unescaped_len - (cert_end - unescaped),
                        pem_marker_begin,
                        strlen(pem_marker_begin));
    assert(cert_begin != NULL);
    cert_end = memmem(cert_begin,
                     unescaped_len - (cert_begin - unescaped),
                     pem_marker_end,
                     strlen(pem_marker_end));
    assert(cert_end != NULL);
    cert_len = cert_end - cert_begin + strlen(pem_marker_end);

    assert(cert_len <= sizeof(attn_report->ias_sign_ca_cert));
    memcpy((char*) attn_report->ias_sign_ca_cert, cert_begin, cert_len);
    attn_report->ias_sign_ca_cert_len = cert_len;

    curl_free(unescaped);
    unescaped = NULL;
}

/* The header has the certificates and report signature. */
static void parse_response_header
(
    const char* header,
    size_t header_len,
    unsigned char* signature,
    const size_t signature_max_size,
    uint32_t* signature_size
)
{
    const char sig_tag[] = "X-IASReport-Signature: ";
    char* sig_begin = memmem((const char*) header,
                             header_len,
                             sig_tag,
                             strlen(sig_tag));
    assert(sig_begin != NULL);
    sig_begin += strlen(sig_tag);
    char* sig_end = memmem(sig_begin,
                           header_len - (sig_begin - header),
                           "\r\n",
                           strlen("\r\n"));
    assert(sig_end);

    assert((size_t) (sig_end - sig_begin) <= signature_max_size);
    memcpy(signature, sig_begin, sig_end - sig_begin);
    *signature_size = sig_end - sig_begin;
}

/** Turns a binary quote into an attestation verification report.

  Communicates with Intel Attestation Service via its HTTP REST interface.
*/
void obtain_attestation_verification_report
(
    const sgx_quote_t* quote,
    const uint32_t quote_size,
    const struct ra_tls_options* opts,
    attestation_verification_report_t* attn_report
)
{
    int ret;
  
    char url[512];
    ret = snprintf(url, sizeof(url), "https://%s/attestation/v4/report",
                   opts->ias_server);
    assert(ret < (int) sizeof(url));
    
    char buf[128];
    int rc = snprintf(buf, sizeof(buf), "Ocp-Apim-Subscription-Key: %.32s",
                      opts->subscription_key);
    assert(rc < (int) sizeof(buf));

    struct curl_slist *request_headers =
        curl_slist_append(NULL, "Content-Type: application/json");
    request_headers = curl_slist_append(request_headers, buf);
#ifndef NDEBUG
    printf("ocp-apim content: %s\n", buf);
#endif // NDEBUG
        
    const char json_template[] = "{\"isvEnclaveQuote\":\"%s\"}";
    unsigned char quote_base64[quote_size * 2];
    uint32_t quote_base64_len = sizeof(quote_base64);
    char json[quote_size * 2];

    base64_encode((uint8_t*) quote, quote_size,
                  quote_base64, &quote_base64_len);

    snprintf(json, sizeof(json), json_template, quote_base64);

#ifndef NDEBUG
    printf("the quote json sent: %s\n", json);
#endif // NDEBUG

    CURL *curl = curl_easy_init();
    assert(curl != NULL);
    struct buffer_and_size header = {(char*) malloc(1), 0};
    struct buffer_and_size body = {(char*) malloc(1), 0};
    http_get(curl, url, &header, &body, request_headers, json);
        
    parse_response_header(header.data, header.len,
                          attn_report->ias_report_signature,
                          sizeof(attn_report->ias_report_signature),
                          &attn_report->ias_report_signature_len);

    assert(sizeof(attn_report->ias_report) >= body.len);
    memcpy(attn_report->ias_report, body.data, body.len);
    attn_report->ias_report_len = body.len;

    extract_certificates_from_response_header(curl,
                                              header.data, header.len,
                                              attn_report);
    
    curl_easy_cleanup(curl);
    free(header.data);
    free(body.data);
    curl_slist_free_all(request_headers);
}

void ocall_remote_attestation
(
    sgx_report_t* report,
    const struct ra_tls_options* opts,
    attestation_verification_report_t* attn_report
)
{
    // produce quote
    uint32_t quote_size;
    sgx_calc_quote_size(NULL, 0, &quote_size);
    
    sgx_quote_t* quote = (sgx_quote_t*) calloc(1, quote_size);
    
    sgx_status_t status;
    status = sgx_get_quote(report,
                           opts->quote_type,
                           &opts->spid,
                           NULL,
                           NULL,
                           0,
                           NULL,
                           quote,
                           quote_size);
    assert(SGX_SUCCESS == status);

    // verify against IAS
    obtain_attestation_verification_report(quote, quote_size, opts, attn_report);
}

void ocall_sgx_init_quote
(
    sgx_target_info_t* target_info
)
{
    sgx_epid_group_id_t gid;
    sgx_status_t status = sgx_init_quote(target_info, &gid);
    assert(status == SGX_SUCCESS);
}

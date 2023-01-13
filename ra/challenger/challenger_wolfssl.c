#include "challenger_wolfssl.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/asn_public.h"
#include "wolfssl/wolfcrypt/coding.h"
#include "wolfssl/wolfcrypt/signature.h"

#include "ra.h"
#include "challenger.h"
#include "challenger_internal.h"
#include "common/internal_util_wolfssl.h"

// ecdsa
#define SGX_SDK 1
#include "sgx_ql_quote.h"
#include "sgx_utils.h"
#include "sgx_error.h"

extern unsigned char ias_sign_ca_cert_der[];
extern unsigned int ias_sign_ca_cert_der_len;

#ifdef SGX_SDK
/* SGX SDK does not have this. */
// an adapted implementation from SGX-Tor.
// ref: https://github.com/kaist-ina/SGX-Tor/blob/master/SGX-Tor_WIN/TorRealOriginal/compat.c retrieved on 18/12/2021 
const void *memmem(const void *_haystack, size_t hlen, 
  const void *_needle, size_t nlen) {
  const char *haystack = (const char*)_haystack;
  const char *needle = (const char*)_needle;
  if (nlen > hlen) return NULL;
  char first = *(const char*)needle;
  const char *p = haystack;
  const char *last_possible_start = haystack + hlen - nlen;
  while ((p = memchr(p, first, (size_t) (last_possible_start + 1 - p)))) {
    if (!memcmp(p, needle, nlen)) return p;
    p++;
  }
  return NULL;
}
#endif // SGX_SDK

#define OID(N) {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x8A, 0x39, (N)}

const uint8_t ias_response_body_oid[]    = OID(0x02);
const uint8_t ias_root_cert_oid[]        = OID(0x03);
const uint8_t ias_leaf_cert_oid[]        = OID(0x04);
const uint8_t ias_report_signature_oid[] = OID(0x05);

const uint8_t quote_oid[]          = OID(0x06);
const size_t ias_oid_len = sizeof(ias_response_body_oid);
const size_t quote_oid_len = sizeof(quote_oid);

/**
 * @return Returns -1 if OID not found. Otherwise, returns 1;
 */
static int find_oid
(
     const unsigned char* ext, size_t ext_len,
     const unsigned char* oid, size_t oid_len,
     const uint8_t** val, size_t* len
)
{
    const uint8_t* p = memmem(ext, ext_len, oid, oid_len);
    if (p == NULL) {
        return -1;
    }

    p += oid_len;

    int i = 0;

    // Some TLS libraries generate a BOOLEAN for the criticality of the extension.
    if (p[i] == 0x01) {
        assert(p[i++] == 0x01); // tag, 0x01 is ASN1 Boolean
        assert(p[i++] == 0x01); // length
        assert(p[i++] == 0x00); // value (0 is non-critical, non-zero is critical)
    }

    // Now comes the octet string
    assert(p[i++] == 0x04); // tag for octet string
    assert(p[i++] == 0x82); // length encoded in two bytes
    *len  =  (size_t) (p[i++] << 8);
    *len +=  p[i++];
    *val  = &p[i++];

    return 1;
}

/**
 * @return 1 if it is an EPID-based attestation RA-TLS
 * certificate. Otherwise, 0.
 */
int is_epid_ratls_cert
(
    const uint8_t* der_crt,
    uint32_t der_crt_len
)
{
    const uint8_t* ext_data;
    size_t ext_data_len;
    int rc;
    
    rc = find_oid(der_crt, der_crt_len,
                  ias_response_body_oid, ias_oid_len,
                  &ext_data, &ext_data_len);
    if (1 == rc) return 1;

    rc = find_oid(der_crt, der_crt_len,
                   quote_oid, quote_oid_len,
                   &ext_data, &ext_data_len);
    if (1 == rc) return 0;

    /* Something is fishy. Neither EPID nor ECDSA RA-TLC cert?! */
    assert(0);
    // Avoid compiler error: control reaches end of non-void function
    // [-Werror=return-type]
    return -1;
}

/**
 * @return Returns -1 if OID was not found. Otherwise, returns 1;
 */
static int extract_x509_extension
(
    const uint8_t* ext,
    uint32_t ext_len,
    const uint8_t* oid,
    size_t oid_len,
    uint8_t* data,
    uint32_t* data_len,
    uint32_t data_max_len
)
{
    const uint8_t* ext_data;
    size_t ext_data_len;
    
    int rc = find_oid(ext, ext_len, oid, oid_len, &ext_data, &ext_data_len);
    if (rc == -1) return -1;
    
    assert(ext_data != NULL);
    assert(ext_data_len <= data_max_len);
    memcpy(data, ext_data, ext_data_len);
    *data_len = (uint32_t) ext_data_len;

    return 1;
}

void get_quote_from_ias_report
(
    const uint8_t* report /* in */,
    const uint32_t report_len  /* in */,
    sgx_quote_t* quote
)
{
    // Move report into \0 terminated buffer such that we can work
    // with str* functions.
    char buf[report_len + 1];
    memcpy(buf, report, report_len);
    buf[report_len] = '\0';

    const char* json_string = "\"isvEnclaveQuoteBody\":\"";
    char* p_begin = strstr(buf, json_string);
    assert(p_begin != NULL);
    p_begin += strlen(json_string);
    const char* p_end = strchr(p_begin, '"');
    assert(p_end != NULL);

    const uint32_t quote_base64_len = (uint32_t) (p_end - p_begin);
    uint8_t* quote_bin = malloc(quote_base64_len);
    uint32_t quote_bin_len = quote_base64_len;

    Base64_Decode((const byte*) p_begin, quote_base64_len,
                  quote_bin, &quote_bin_len);
    
    assert(quote_bin_len <= sizeof(sgx_quote_t));
    memset(quote, 0, sizeof(sgx_quote_t));
    memcpy(quote, quote_bin, quote_bin_len);
    free(quote_bin);
}

static
int verify_report_data_against_server_cert
(
    DecodedCert* crt,
    sgx_report_body_t* report_body
)
{
    /* crt->publicKey seems to be the DER encoded public key. The
       OpenSSL DER formatted version of the public key obtained with
       openssl rsa -in ./server-key.pem -pubout -outform DER -out
       server-pubkey.der has an additional 24 bytes
       prefix/header. d->pubKeySize is 270 and the server-pubkey.der
       file has 294 bytes. That's to be expected according to [1] */
    /* [1] https://crypto.stackexchange.com/questions/14491/why-is-a-2048-bit-public-rsa-key-represented-by-540-hexadecimal-characters-in  */
    
    /* 2017-12-06, Thomas Knauth, A hard-coded offset into the
       DER-encoded public key only works for specific key sizes. The
       24 byte offset is specific to 2048 bit RSA keys. For example, a
       1024 bit RSA key only has an offset of 22.
 */
    RsaKey rsaKey;
    unsigned int idx = 0;
    int ret;
    
    wc_InitRsaKey(&rsaKey, NULL);
    ret = wc_RsaPublicKeyDecode(crt->publicKey, &idx, &rsaKey, crt->pubKeySize);
    assert(ret == 0);
    
    byte shaSum[SHA256_DIGEST_SIZE] = {0, };
    sha256_rsa_pubkey(shaSum, &rsaKey);
    wc_FreeRsaKey(&rsaKey);

#ifdef DEBUG
    printf("SHA256 of server's public key:\n");
    for (int i=0; i < SHA256_DIGEST_SIZE; ++i) printf("%02x", shaSum[i]);
    printf("\n");

    printf("report data:\n");
    for (int i=0; i < SGX_REPORT_DATA_SIZE; ++i) printf("%02x", report_body->report_data.d[i]);
    printf("\n");
#endif
    
    assert(SHA256_DIGEST_SIZE <= SGX_REPORT_DATA_SIZE);
    ret = memcmp(report_body->report_data.d, shaSum, SHA256_DIGEST_SIZE);
    assert(ret == 0);

    return ret;
}

static
int verify_ias_report_signature
(
    attestation_verification_report_t* attn_report
)
{
    DecodedCert crt;
    int ret;

    uint8_t der[4096];
    int der_len;
    der_len = wolfSSL_CertPemToDer(attn_report->ias_sign_cert,
      (int) attn_report->ias_sign_cert_len, der, sizeof(der), CERT_TYPE);
    assert(der_len > 0);
    
    InitDecodedCert(&crt, der, (word32) der_len, NULL);
    InitSignatureCtx(&crt.sigCtx, NULL, INVALID_DEVID);
    ret = ParseCertRelative(&crt, CERT_TYPE, NO_VERIFY, 0);
    assert(ret == 0);

    RsaKey rsaKey;
    unsigned int idx = 0;
    
    ret = wc_InitRsaKey(&rsaKey, NULL);
    assert(ret == 0);
    ret = wc_RsaPublicKeyDecode(crt.publicKey, &idx, &rsaKey, crt.pubKeySize);
    assert(ret == 0);

    ret = wc_SignatureVerify(WC_HASH_TYPE_SHA256,
                             /* This is required such that signature
                                matches what OpenSSL produces. OpenSSL
                                embeds the hash in an ASN.1 structure
                                before signing it. */
                             WC_SIGNATURE_TYPE_RSA_W_ENC,
                             attn_report->ias_report, attn_report->ias_report_len,
                             attn_report->ias_report_signature, attn_report->ias_report_signature_len,
                             &rsaKey, sizeof(rsaKey));

    FreeDecodedCert(&crt);
    wc_FreeRsaKey(&rsaKey);

    return ret;
}

static
int verify_ias_certificate_chain(attestation_verification_report_t* attn_report) {
    WOLFSSL_CERT_MANAGER* cm;

    cm = wolfSSL_CertManagerNew();
    assert(cm != NULL);

    /* like load verify locations, 1 for success, < 0 for error */
    int ret = wolfSSL_CertManagerLoadCABuffer(cm, ias_sign_ca_cert_der,
                                              ias_sign_ca_cert_der_len,
                                              SSL_FILETYPE_ASN1);
    assert(ret == 1);
    
    ret = wolfSSL_CertManagerVerifyBuffer(cm, attn_report->ias_sign_cert,
                                          attn_report->ias_sign_cert_len,
                                          SSL_FILETYPE_PEM);
    assert(ret == SSL_SUCCESS);
    
    wolfSSL_CertManagerFree(cm);
    cm = NULL;
    
    return 0;
}

/**
 * Check if isvEnclaveQuoteStatus is "OK"
 * Now temporarily bypasses the following statuses
 *  CONFIGURATION_NEEDED
 *  SW_HARDENING_NEEDED
 *  CONFIGURATION_AND_SW_HARDENING_NEEDED
 * (cf. https://www.intel.com/content/dam/develop/public/us/en/documents/sgx-attestation-api-spec.pdf, based on v4 rev-6.0).
 *
 * @return 0 if verified successfully, 1 otherwise.
 */
static int epid_verify_enclave_quote_status
(
    const uint8_t* ias_report,
    uint32_t   ias_report_len
)
{
    // Move ias_report into \0 terminated buffer such that we can work
    // with str* functions.
    char buf[ias_report_len + 1];
    memcpy(buf, ias_report, ias_report_len);
    buf[ias_report_len] = '\0';
    
    const char* json_string = "\"isvEnclaveQuoteStatus\":\"";
    char* p_begin = strstr(buf, json_string);
    assert(p_begin != NULL);
    p_begin += strlen(json_string);

    const char* status_OK = "OK\"";
    printf("------Attestation verfication report from IAS------\n");
    printf("%s\n", buf);
    printf("------Attestation verfication report from IAS------\n");
    if (0 == strncmp(p_begin, status_OK, strlen(status_OK))) return 0;
    // temporary bypass for configuration needed
    const char* status_CONFIGURATION_NEEDED = "CONFIGURATION_NEEDED\"";
    if (0 == strncmp(p_begin, status_CONFIGURATION_NEEDED, 
      strlen(status_CONFIGURATION_NEEDED))) {
      printf("WARNING: isvEnclaveQuoteStatus is CONFIGURATION_NEEDED\n");
      return 0;
    } 
    // temporary bypass for sw hardening needed
    const char* status_SW_HARDENING_NEEDED
      = "SW_HARDENING_NEEDED\"";
    if (0 == strncmp(p_begin, status_SW_HARDENING_NEEDED, 
      strlen(status_SW_HARDENING_NEEDED))) {
      printf("WARNING: isvEnclaveQuoteStatus is SW_HARDENING_NEEDED\n");
      return 0;
    } 
    // temporary bypass for configuration and sw hardening needed
    const char* status_CONFIGURATION_AND_SW_HARDENING_NEEDED
      = "CONFIGURATION_AND_SW_HARDENING_NEEDED\"";
    if (0 == strncmp(p_begin, status_CONFIGURATION_AND_SW_HARDENING_NEEDED, 
      strlen(status_CONFIGURATION_AND_SW_HARDENING_NEEDED))) {
      printf("WARNING: isvEnclaveQuoteStatus is CONFIGURATION_AND_SW_HARDENING_NEEDED\n");
      return 0;
    } 
#ifdef SGX_GROUP_OUT_OF_DATE
    const char* status_outdated = "GROUP_OUT_OF_DATE\"";
    if (0 == strncmp(p_begin, status_outdated, strlen(status_outdated))) {
        printf("WARNING: isvEnclaveQuoteStatus is GROUP_OUT_OF_DATE\n");
        return 0;
    }
#endif
    // return 1 to indicate error for other statuses.
    return 1;
}

/**
 * Extract all extensions of EPID-based cert.
 */
void epid_extract_x509_extensions
(
    const uint8_t* ext,
    uint32_t ext_len,
    attestation_verification_report_t* attn_report
)
{
    extract_x509_extension(ext, ext_len,
                           ias_response_body_oid, ias_oid_len,
                           attn_report->ias_report,
                           &attn_report->ias_report_len,
                           sizeof(attn_report->ias_report));

    extract_x509_extension(ext, ext_len,
                           ias_root_cert_oid, ias_oid_len,
                           attn_report->ias_sign_ca_cert,
                           &attn_report->ias_sign_ca_cert_len,
                           sizeof(attn_report->ias_sign_ca_cert));

    extract_x509_extension(ext, ext_len,
                           ias_leaf_cert_oid, ias_oid_len,
                           attn_report->ias_sign_cert,
                           &attn_report->ias_sign_cert_len,
                           sizeof(attn_report->ias_sign_cert));

    extract_x509_extension(ext, ext_len,
                           ias_report_signature_oid, ias_oid_len,
                           attn_report->ias_report_signature,
                           &attn_report->ias_report_signature_len,
                           sizeof(attn_report->ias_report_signature));
}

int epid_verify_sgx_cert_extensions
(
    uint8_t* der_crt,
    uint32_t der_crt_len
)
{
    attestation_verification_report_t attn_report;

    DecodedCert crt;
    int ret;

    InitDecodedCert(&crt, der_crt, der_crt_len, NULL);
    InitSignatureCtx(&crt.sigCtx, NULL, INVALID_DEVID);
    ret = ParseCertRelative(&crt, CERT_TYPE, NO_VERIFY, 0);
    assert(ret == 0);
    
    epid_extract_x509_extensions(crt.extensions, (uint32_t) crt.extensionsSz,
      &attn_report);

    /* Base64 decode attestation report signature. */
    uint8_t sig_base64[sizeof(attn_report.ias_report_signature)];
    memcpy(sig_base64, attn_report.ias_report_signature, attn_report.ias_report_signature_len);
    int rc = Base64_Decode(sig_base64, attn_report.ias_report_signature_len,
                           attn_report.ias_report_signature, &attn_report.ias_report_signature_len);
    assert(0 == rc);
    
    ret = verify_ias_certificate_chain(&attn_report);
    assert(ret == 0);

    ret = verify_ias_report_signature(&attn_report);
    assert(ret == 0);

    ret = epid_verify_enclave_quote_status(attn_report.ias_report,
                                      attn_report.ias_report_len);
    assert(ret == 0);
    
    sgx_quote_t quote = {0, };
    get_quote_from_ias_report(attn_report.ias_report,
                          attn_report.ias_report_len,
                          &quote);
    ret = verify_report_data_against_server_cert(&crt, &(quote.report_body));
    assert(ret == 0);

    FreeDecodedCert(&crt);

    return 0;
}

int ecdsa_verify_sgx_cert_extensions
(
    uint8_t* der_crt,
    uint32_t der_crt_len
)
{
    DecodedCert crt;
    int ret;

    InitDecodedCert(&crt, der_crt, der_crt_len, NULL);
    InitSignatureCtx(&crt.sigCtx, NULL, INVALID_DEVID);
    ret = ParseCertRelative(&crt, CERT_TYPE, NO_VERIFY, 0);
    assert(ret == 0);

    // just give a buffer here to use the find oid api above. should be enough
    uint8_t ecdsa_quote_buf[6144];
    uint32_t ecdsa_quote_len = 0;

    extract_x509_extension(crt.extensions, (uint32_t) crt.extensionsSz,
                           quote_oid, quote_oid_len,
                           ecdsa_quote_buf,
                           &ecdsa_quote_len,
                           sizeof(ecdsa_quote_buf));

    ret = ecdsa_verify_quote(ecdsa_quote_buf, ecdsa_quote_len);

    ret = verify_report_data_against_server_cert(&crt,
      &(((sgx_quote3_t*)ecdsa_quote_buf)->report_body));
    assert(ret == 0);

    FreeDecodedCert(&crt);
    return 0;
}

// sample tls cert verification logic
// user should override this and provide verification logic for other fields like MRENCLAVE and MRSIGNER to the verify_sgx_cert_extensions. 
int cert_verify_callback(int preverify, WOLFSSL_X509_STORE_CTX* store) {

    printf("Verifying SGX certificate extensions ... \n");
    (void) preverify;

    int ret = verify_sgx_cert_extensions(store->certs->buffer,
                                         store->certs->length);

    printf("Verifying SGX certificate extensions ... %s\n",
            ret == 0 ? "Success" : "Failure");
    return !ret;
}

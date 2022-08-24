#ifndef SGX_SDK

#define _GNU_SOURCE // for memmem()

#endif // SGX_SDK

#include "challenger.h"
#include "challenger_internal.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sgx_quote.h>

#include "ra.h"

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
                   quote_oid, ias_oid_len,
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

/**
 * Extract all extensions.
 */
void extract_x509_extensions
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

// used in trusted and untrusted
// put as verify callback
int verify_sgx_cert_extensions
(
    uint8_t* der_crt,
    uint32_t der_crt_len
)
{
    if (is_epid_ratls_cert(der_crt, der_crt_len)) {
        return epid_verify_sgx_cert_extensions(der_crt, der_crt_len);
    }
    assert(0);
    // Avoid compiler error: control reaches end of non-void function
    // [-Werror=return-type]
    return -1;
}


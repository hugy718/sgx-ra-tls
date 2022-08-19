#ifndef RATLS_RA_H_
#define RATLS_RA_H_

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  uint8_t ias_report[2*1024];
  uint32_t ias_report_len;
  uint8_t ias_sign_ca_cert[2*1024];
  uint32_t ias_sign_ca_cert_len;
  uint8_t ias_sign_cert[2*1024];
  uint32_t ias_sign_cert_len;
  uint8_t ias_report_signature[2*1024];
  uint32_t ias_report_signature_len;
} attestation_verification_report_t;

#ifdef __cplusplus
}
#endif

#endif  // RATLS_RA_H_

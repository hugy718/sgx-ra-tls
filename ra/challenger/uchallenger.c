#include "uchallenger.h"

#include <stdio.h>

#include "ra.h"
#include "challenger_internal.h"

// ecdsa
#include <time.h>
#include <sgx_dcap_quoteverify.h>

static void dprintf_epid_ratls_cert
(
    int fd,
    uint8_t* der_crt,
    uint32_t der_crt_len
)
{
    attestation_verification_report_t report;
    epid_extract_x509_extensions(der_crt, der_crt_len, &report);
    dprintf(fd, "\nIntel Attestation Service Report\n");
    dprintf(fd, "%.*s\n", report.ias_report_len, report.ias_report);

    sgx_quote_t quote = {0, };
    get_quote_from_ias_report(report.ias_report, report.ias_report_len,
      &quote);
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

void ocall_get_current_time(uint64_t* current_time) {
  if (!current_time) {
    printf("current time holder is nullptr \n");
    return;
  }
  time((time_t*) current_time);
}

quote3_error_t ocall_sgx_get_supplemental_data_size(
  uint32_t* supplemental_data_size) {
  return sgx_qv_get_quote_supplemental_data_size(supplemental_data_size);
}

quote3_error_t ocall_sgx_verify_quote(const uint8_t* quote_buf, uint32_t quote_len,
  time_t expiration_check_date, sgx_ql_qv_result_t* quote_verification_result,
  sgx_ql_qe_report_info_t* qve_report_info, size_t qve_report_info_size,
  uint8_t* supplemental_data_buf, uint32_t supplemental_data_size) {
  uint32_t collateral_expiration_status = 1;
  // validate parameter
  if (quote_buf == NULL || supplemental_data_buf == NULL) {
    return SGX_QL_ERROR_INVALID_PARAMETER;
  }

  return sgx_qv_verify_quote(quote_buf, quote_len, NULL, expiration_check_date,
    &collateral_expiration_status, quote_verification_result, qve_report_info,
    supplemental_data_size, supplemental_data_buf);
}

quote3_error_t ecdsa_get_supplemental_data_size(
  uint32_t* supplemental_data_size) {
  return sgx_qv_get_quote_supplemental_data_size(supplemental_data_size);
}

quote3_error_t ecdsa_verify_quote_common(uint8_t* quote_buf, uint32_t quote_len,
  uint8_t* supplemental_data_buf, uint32_t supplemental_data_size) {
  time_t current_time;
  time(&current_time);
  sgx_ql_qv_result_t qv_result;
  uint32_t collateral_expiration_status = 1;
  
  // validate parameter
  if (quote_buf == NULL || supplemental_data_buf == NULL) {
    return SGX_QL_ERROR_INVALID_PARAMETER;
  }

  return sgx_qv_verify_quote(quote_buf, quote_len, NULL, current_time,
    &collateral_expiration_status, &qv_result, NULL,
    supplemental_data_size, supplemental_data_buf);
}

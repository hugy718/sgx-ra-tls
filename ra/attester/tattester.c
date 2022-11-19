#include "tattester_internal.h"

#include <assert.h>

#include "sgx_error.h"
#include "sgx_utils.h"

#include "string.h"

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


// caller is owns the returned quote buffer
sgx_quote3_t* obtain_ecdsa_qe_quote(sgx_report_data_t* report_data,
  uint32_t* output_size, quote3_error_t* quote_error, sgx_status_t* status) {
  // obtain qe target info via ocall
  sgx_target_info_t target_info;
  *status = ocall_sgx_qe_get_target_info(quote_error,
    &target_info, sizeof(sgx_target_info_t));
  if (*status != SGX_SUCCESS) {
    *quote_error = SGX_QL_ERROR_UNEXPECTED;
  }
  if (*quote_error != SGX_QL_SUCCESS) {
    return NULL;
  }
   
  // create application enclave report.
  sgx_report_t app_report;
  *status = sgx_create_report(&target_info, report_data, &app_report);
  if (*status != SGX_SUCCESS) {
    *quote_error = SGX_QL_ERROR_UNEXPECTED;
  }
  if (*quote_error != SGX_QL_SUCCESS) {
    return NULL;
  }

  // obtain quote size via ocall
  uint32_t quote_size = 0;
  *status = ocall_sgx_qe_get_quote_size(quote_error, &quote_size);
  if (*status != SGX_SUCCESS) {
    *quote_error = SGX_QL_ERROR_UNEXPECTED;
  }
  if (*quote_error != SGX_QL_SUCCESS) {
    return NULL;
  }

  // allocate quote buffer
  uint8_t* quote_buf = (uint8_t*) malloc(quote_size);
  if (quote_buf == NULL) {
    *status = SGX_ERROR_OUT_OF_MEMORY;
    *quote_error = SGX_QL_ERROR_OUT_OF_MEMORY;
    return NULL;
  }
  memset(quote_buf, 0, quote_size);

  // obtain quote via ocall
  *status = ocall_sgx_qe_get_quote(quote_error, &app_report, sizeof(sgx_report_t), 
    quote_buf, quote_size);
  if (*status != SGX_SUCCESS) {
    *quote_error = SGX_QL_ERROR_UNEXPECTED;
  }
  if (*quote_error != SGX_QL_SUCCESS) {
    free(quote_buf);
    return NULL;
  }
  
  *quote_error = SGX_QL_SUCCESS;
  *status = SGX_SUCCESS;

  *output_size = quote_size;
  return (sgx_quote3_t*) quote_buf;
}

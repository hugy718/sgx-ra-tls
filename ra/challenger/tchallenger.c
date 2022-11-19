#include "challenger_internal.h"

#include "time.h"

#include "sgx_dcap_tvl.h"
#include "sgx_error.h"
#include "sgx_ql_quote.h"
#include "sgx_qve_header.h"

quote3_error_t ecdsa_get_supplemental_data_size(
  uint32_t* supplemental_data_size) {
  quote3_error_t ret = SGX_QL_ERROR_UNEXPECTED;
  sgx_status_t status = ocall_sgx_get_supplemental_data_size(&ret, supplemental_data_size);
  if ((status == SGX_SUCCESS) && (ret == SGX_QL_SUCCESS)) return ret;
  // clear data size and return error
  *supplemental_data_size = 0;
  return (ret == SGX_QL_SUCCESS) ? SGX_QL_ERROR_UNEXPECTED : ret;
}

quote3_error_t ecdsa_verify_quote_common(uint8_t* quote_buf, uint32_t quote_len,
  uint8_t* supplemental_data_buf, uint32_t supplemental_data_size) {
  time_t current_time;
  sgx_ql_qe_report_info_t qve_report_info;
  sgx_ql_qv_result_t qv_result;

  ocall_get_current_time((uint64_t*) &current_time);

  sgx_status_t status = sgx_read_rand(
    (unsigned char*) &(qve_report_info.nonce), sizeof(sgx_quote_nonce_t));
  if (status != SGX_SUCCESS) return SGX_QL_ERROR_UNEXPECTED;

  status = sgx_self_target(&qve_report_info.app_enclave_target_info);
  if (status != SGX_SUCCESS) return SGX_QL_ERROR_UNEXPECTED;

  quote3_error_t q_ret = SGX_QL_ERROR_UNEXPECTED;
  status = ocall_sgx_verify_quote(&q_ret, quote_buf, quote_len, current_time,
    &qv_result, &qve_report_info, sizeof(sgx_ql_qe_report_info_t),
    supplemental_data_buf, supplemental_data_size);
  if ((status != SGX_SUCCESS) || (q_ret != SGX_QL_SUCCESS)) {
    return SGX_QL_ERROR_UNEXPECTED;
  }

  uint32_t collateral_expiration_status = 0;
  //The ISVSVN threshold of Intel signed QvE
  const sgx_isv_svn_t qve_isvsvn_threshold = 5;
  q_ret = sgx_tvl_verify_qve_report_and_identity(quote_buf, quote_len,
    &qve_report_info, current_time, collateral_expiration_status, qv_result, supplemental_data_buf, supplemental_data_size, qve_isvsvn_threshold);
  return q_ret;
}
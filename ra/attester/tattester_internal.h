#ifndef RATLS_UATTESTER_INTERNAL_H_
#define RATLS_UATTESTER_INTERNAL_H_

#include "sgx_report.h"
// ecdsa
#include "sgx_error.h"
#include "sgx_quote_3.h"
#include "sgx_ql_lib_common.h"

#include "ra.h"
#include "attester.h"

void do_remote_attestation(sgx_report_data_t* report_data,
                           const struct ra_tls_options* opts,
                           attestation_verification_report_t* r);

sgx_quote3_t* obtain_ecdsa_qe_quote(sgx_report_data_t* report_data,
  uint32_t* output_size, quote3_error_t* quote_error, sgx_status_t* status);

#endif  // RATLS_UATTESTER_INTERNAL_H_

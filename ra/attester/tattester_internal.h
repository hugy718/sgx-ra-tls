#ifndef RATLS_UATTESTER_INTERNAL_H_
#define RATLS_UATTESTER_INTERNAL_H_

#include "sgx_report.h"

#include "ra.h"
#include "attester.h"

void do_remote_attestation(sgx_report_data_t* report_data,
                           const struct ra_tls_options* opts,
                           attestation_verification_report_t* r);

#endif  // RATLS_UATTESTER_INTERNAL_H_

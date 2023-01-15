#!/bin/bash

# set -x

if [[ "$USE_ECDSA" == 1 ]]; then
# ecdsa
# dummy ratls option to suppress warning
cat <<HEREDOC
#include "attester.h" 

struct ra_tls_options my_ra_tls_options;
HEREDOC
else
# epid
if [[ -z "$SPID" ]] || [[ -z "$QUOTE_TYPE" ]] || \
   [[ -z "$EPID_SUBSCRIPTION_KEY" ]]; then
    echo "EPID requires setting SPID, QUOTE_TYPE and EPID_SUBSCRIPTION_KEY!"
    exit 1
fi

if [[ "$QUOTE_TYPE" != "SGX_LINKABLE_SIGNATURE" ]] && \
   [[ "$QUOTE_TYPE" != "SGX_UNLINKABLE_SIGNATURE" ]]; then
    echo "QUOTE_TYPE must be one of SGX_UNLINKABLE_SIGNATURE or SGX_LINKABLE_SIGNATURE, but $QUOTE_TYPE received."
    exit 1
fi

SPID_BYTE_ARRAY=$(echo $SPID | python3 -c 'import sys ; s = sys.stdin.readline().strip(); print("".join(["0x"+s[2*i:2*i+2]+"," for i in range(len(s)//2)]))')

cat <<HEREDOC
#include "attester.h" 

struct ra_tls_options my_ra_tls_options = {
    // SPID format is 32 hex-character string, e.g., 0123456789abcdef0123456789abcdef
    .spid = {{$SPID_BYTE_ARRAY}},
    .quote_type = $QUOTE_TYPE,
    .ias_server = "api.trustedservices.intel.com/sgx/dev",
    // EPID_SUBSCRIPTION_KEY format is "012345679abcdef012345679abcdef"
    .subscription_key = "$EPID_SUBSCRIPTION_KEY"
};
HEREDOC
fi

#include "challenger_u.h"
#include <errno.h>

typedef struct ms_enc_wolfSSL_CTX_set_ratls_verify_t {
	WOLFSSL_CTX* ms_ctx;
} ms_enc_wolfSSL_CTX_set_ratls_verify_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_challenger = {
	0,
	{ NULL },
};
sgx_status_t enc_wolfSSL_CTX_set_ratls_verify(sgx_enclave_id_t eid, WOLFSSL_CTX* ctx)
{
	sgx_status_t status;
	ms_enc_wolfSSL_CTX_set_ratls_verify_t ms;
	ms.ms_ctx = ctx;
	status = sgx_ecall(eid, 0, &ocall_table_challenger, &ms);
	return status;
}


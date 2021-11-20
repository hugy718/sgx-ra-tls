# Non-SGX Client
The socket and wolfssl are initialized. Client connect to the server with address. (currently hardcoded in srvaddr in the program.)

`wolfSSL_CTX_set_verify()` is called which would faile with wolfssl default path and triggering the `cert_verify_callback()`, which calls `verify_sgx_cert_extensions()` defined in [wolfssl-ra-challenger.h](ra/wolfssl-ra-challenger.h).
1. `is_epid_ratls_cert()` checks if can find an oid (defined under ra.c).
2. `epid_verify_sgx_cert_extension()` calls 
  * `extract_x509_extensions()` -- decode and rpepare the attestation verification report for the calls below.
  * `verify_ias_certificate_chain()` -- note that [IAS CA cert](ra/ias_sign_ca_cert.c) is used here.
  * `verify_ias_report_signature()` -- validate the signature of attestation report with the public key, signature, data given in the report.
  * `verify_enclave_quote_status()` -- validate quote status. Should only check with "OK" but I for now added "CONFIGURATION_NEEDED" as many dell machine now produces such status.
  * `get_quote_from_report()` -- decode base64 encoded quote body.
  * `verify_report_data_against_server_cert()` -- validate that the certificate public key is the same as included in the quote (check server code when this is added to do remote attestation)

Note that the above process only validates that the report is authentic, it does not however check whether the enclave is correct. That is done by a separate pathway below. `wolfSSL_get_peer_certificate()` -> `wolfSSL_X509_get_der()` -> `get_quote_from_cert()` retrieves the quote. Then explicitly we can read the MRENCLAVE and MRSIGNER value.

Afterwards, client can proceed to send and read data from the connection.


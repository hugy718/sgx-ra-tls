# Enclave Server
Enclave is initialized in the App.c via `sgx_create_enclave` and the enclave id is returned to call `server_connect`.

The socket is first created using system socket library. The wolfssl context is created in enclave with each ecall ecapsulating a corresponding wolfssl api. (`enc_wolfSSL_Init()`, `enc_wolfTLSv1_2_server_method`, `enc_wolfSSL_CTX_new()`)

The key extension is done via the `create_key_and_x509()` which let enclave prepare a certificate with ias report embeded (remote attestation is done via ocalls.).
1. The API is defined in [ra-attester.h](ra/ra-attester.h) and implemented in [wolfssl-ra-attester.c](ra/wolfssl-ra-attester.c) (`wolfssl_create_key_and_x509()`).
2. The wolfssl implementation calls `do_remote_attestation` to obtain the report to be used in `generate_x509` to prepare the DER encoded x509 certificate. 

The socket is binded to the default port used by server is `111111` set in [server-tls.c](server/trusted/server-tls.c). and waiting for client connection.

enc_wolfSSL_new() is called to create an SSL session with the context.enc_wolfSSL_set_fd() set the file descriptor returned from accept to ssl session.

The server then can send and receive information via `wolfSSL_read()` and `wolfSSL_write()`.  The ecall version of them `enc_wolfSSL_read()` and `enc_wolfSSL_write()` let enclave put the info read in a untrusted buffer to print out for check and enclave send information on behalf of untrusted part.
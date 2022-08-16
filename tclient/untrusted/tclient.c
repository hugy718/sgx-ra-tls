#include "sgx_urts.h"
#include <sys/types.h>
#include <sys/socket.h>

#include "Tclient_Enclave_u.h"

#define CLIENT_ENCLAVE_FILENAME "Tclient_Enclave.signed.so"

#if _DEBUG
  #define DEBUG_VALUE SGX_DEBUG_FLAG
#else
  #define DEBUG_VALUE 1
#endif


#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <wolfssl/ssl.h>

#define MAXRCVDATASIZE 4096
#define SERV_PORT 11111
#define SERV_ADDR "127.0.0.1"

int main(int argc, char* argv[]) {
  // check input argument
  if (argc > 1) {
    printf("Usage: no argument needed for now\n");
  }


  // initialize client enclave
  sgx_enclave_id_t id;
  sgx_launch_token_t t;
  int sgxStatus = 0;
  int updated = 0;
  memset(t, 0, sizeof(sgx_launch_token_t));
  int ret = sgx_create_enclave(CLIENT_ENCLAVE_FILENAME, DEBUG_VALUE, 
    &t, &updated, &id, NULL);
  if (ret != SGX_SUCCESS) {
    printf("Failed to create Enclave : error %d - %#x.\n", ret, ret);
    return 1;
  }

  // setup socket
  int sockfd;
  struct sockaddr_in servAddr;
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    fprintf(stderr, "ERROR: failed to create the socket\n");
    return -1;
  }

  memset(&servAddr, 0, sizeof(servAddr));
  servAddr.sin_family = AF_INET;
  servAddr.sin_port = htons(SERV_PORT);
  if (inet_pton(AF_INET, SERV_ADDR, &servAddr.sin_addr) != 1) {
    fprintf(stderr, "ERROR: invalid address");
    return -1;
  }

  if (connect(sockfd, (struct sockaddr*) &servAddr, sizeof(servAddr)) == -1) {
    fprintf(stderr, "ERROR: failed to connect\n");
    return -1;
  }

  // setup wolfssl in enclave
  // gy1208 need to set verify callback
  WOLFSSL_CTX* ctx;
  WOLFSSL* ssl;
  WOLFSSL_METHOD* method;
#ifdef SGX_DEBUG
  enc_wolfSSL_Debugging_ON(id);
#else
  enc_wolfSSL_Debugging_OFF(id);
#endif

  /* Initialize wolfSSL */
  sgxStatus = enc_wolfSSL_Init(id, &ret);
  if (sgxStatus != SGX_SUCCESS || ret != WOLFSSL_SUCCESS) {
    printf("wolfSSL_Init failure\n");
    return EXIT_FAILURE;
  }
  sgxStatus = enc_wolfTLSv1_2_client_method(id, &method);
  if(sgxStatus != SGX_SUCCESS || method == NULL) {
    printf("wolfTLSv1_2_client_method failure\n");
    return EXIT_FAILURE;
  }

  sgxStatus = enc_wolfSSL_CTX_new(id, &ctx, method);
  if (sgxStatus != SGX_SUCCESS || ctx == NULL) {
    printf("wolfSSL_CTX_new failure");
    return EXIT_FAILURE;
  }
  // setup verify callback in enclave
  enc_wolfSSL_CTX_set_ratls_verify(id, ctx);
  // setup verify callback in enclave

  // link socket to wolfssl ctx
  sgxStatus = enc_wolfSSL_new(id, &ssl, ctx);
  if (sgxStatus != SGX_SUCCESS || ssl == NULL) {
    printf("wolfSSL_new failure");
    return EXIT_FAILURE;
  }

  sgxStatus = enc_wolfSSL_set_fd(id, &ret, ssl, sockfd);
  if (sgxStatus != SGX_SUCCESS || ret != SSL_SUCCESS) {
    printf("wolfSSL_set_fd failure\n");
    return EXIT_FAILURE;
  }
  // link socket to wolfssl ctx

  // establish connection
  sgxStatus = enc_wolfSSL_connect(id, &ret, ssl);
  if (sgxStatus != SGX_SUCCESS || ret != SSL_SUCCESS) {
    printf("Failed to connect to server\n");
    return EXIT_FAILURE;
  }
  // establish connection

  // send data
  const char* sendBuff = "GET / HTTP/1.0\r\n\r\n";
  sgxStatus = enc_wolfSSL_write(id, &ret, ssl, sendBuff, strlen(sendBuff));
  if(sgxStatus != SGX_SUCCESS || ret != strlen(sendBuff)) {
    printf("client write failed");
    return EXIT_FAILURE;
  }

  char rcvBuff[MAXRCVDATASIZE];
  memset(rcvBuff, 0, sizeof(rcvBuff));
  sgxStatus = enc_wolfSSL_read(id, &ret, ssl, rcvBuff, sizeof(rcvBuff)-1);
  if (sgxStatus != SGX_SUCCESS || ret == -1) {
    printf("Server failed to read\n");
    return EXIT_FAILURE;
  }

  printf("Server: \n%s\n", rcvBuff);

  /* Cleanup and return*/
  enc_wolfSSL_free(id, ssl);
  enc_wolfSSL_CTX_free(id, ctx);
  enc_wolfSSL_Cleanup(id, &ret);
  close(sockfd);
  return 0;
}

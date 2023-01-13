#define CLIENT_ENCLAVE_FILENAME "Tclient_Enclave.signed.so"

#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "sgx_urts.h"

#include "wolfssl/options.h"
#include "wolfssl/ssl.h"

#include "Tclient_Enclave_u.h"

#include <sys/types.h>
#include "time.h"

#define MAXRCVDATASIZE 4096
#define SERV_PORT 11111
#define SERV_ADDR "127.0.0.1"

int ocall_get_socket(const char* server_addr, size_t addr_len,
  uint16_t port) {
  // setup socket
  int sockfd;
  struct sockaddr_in servAddr;
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    fprintf(stderr, "ERROR: failed to create the socket\n");
    return -1;
  }

  memset(&servAddr, 0, sizeof(servAddr));
  servAddr.sin_family = AF_INET;
  servAddr.sin_port = htons(port);
  if (inet_pton(AF_INET, server_addr, &servAddr.sin_addr) != 1) {
    fprintf(stderr, "ERROR: invalid address");
    return -1;
  }

  if (connect(sockfd, (struct sockaddr*) &servAddr, sizeof(servAddr)) == -1) {
    fprintf(stderr, "ERROR: failed to connect\n");
    return -1;
  }
  return sockfd;
}

void ocall_close_socket(int sockfd) {
  close(sockfd);
}

int main(int argc, char* argv[]) {
  // check input argument
  if (argc > 1) {
    printf("Usage: no argument needed for now\n");
  }

  // initialize client enclave
  sgx_enclave_id_t id;
  sgx_launch_token_t t;
  sgx_status_t sgxStatus = 0;
  int updated = 0;
  memset(t, 0, sizeof(sgx_launch_token_t));
  int ret = sgx_create_enclave(CLIENT_ENCLAVE_FILENAME, SGX_DEBUG_FLAG, 
    &t, &updated, &id, NULL);
  if (ret != SGX_SUCCESS) {
    printf("Failed to create Enclave : error %d - %#x.\n", ret, ret);
    return 1;
  }

  {
    struct timeval time;
    gettimeofday(&time, 0);
    printf("timing(curl ra): %llu\n",
      (unsigned long long) time.tv_sec*1000*1000
      + (unsigned long long) time.tv_usec);
  }

  // send data
  const char* sendBuff = "GET / HTTP/1.0\r\n\r\n";
  sgxStatus = enc_sample_send(id, &ret, sendBuff, strlen(sendBuff),
    SERV_ADDR, sizeof(SERV_ADDR), SERV_PORT);
  if(sgxStatus != SGX_SUCCESS || ret == -1) {
    printf("client write failed");
    return EXIT_FAILURE;
  }

  char rcvBuff[MAXRCVDATASIZE];
  memset(rcvBuff, 0, sizeof(rcvBuff));
  sgxStatus = enc_retrieve_sample_reply(id, &ret, rcvBuff, sizeof(rcvBuff)-1);
  if (sgxStatus != SGX_SUCCESS || ret == -1) {
    printf("client failed to read\n");
    return EXIT_FAILURE;
  }

  {
    struct timeval time;
    gettimeofday(&time, 0);
    printf("timing(curl ra): %llu\n",
      (unsigned long long) time.tv_sec*1000*1000
      + (unsigned long long) time.tv_usec);
  }

  printf("Server: \n%s\n", rcvBuff);

  sgxStatus = enc_ssl_free(id, &ret);
  if (sgxStatus != SGX_SUCCESS || ret == -1) {
    printf("client failed to read\n");
    return EXIT_FAILURE;
  }
  return 0;
}

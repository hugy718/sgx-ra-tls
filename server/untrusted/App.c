/* App.c
*
* Copyright (C) 2006-2016 wolfSSL Inc.
*
* This file is part of wolfSSL.
*
* wolfSSL is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* wolfSSL is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
*/

#define SERVER_ENCLAVE_FILENAME "Server_Enclave.signed.so"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/types.h> /* for send/recv */
#include <sys/socket.h> /* for send/recv */

#include "sgx_urts.h"	 /* for enclave_id etc.*/

#include "Server_Enclave_u.h"   /* contains untrusted wrapper functions used to call enclave functions*/

#define DEFAULT_PORT 11111

int main(int argc, char* argv[]) /* not using since just testing w/ wc_test */
{
	sgx_enclave_id_t id;
	sgx_launch_token_t t;

	int ret = 0;
	int sgxStatus = 0;
	int updated = 0;
  memset(t, 0, sizeof(sgx_launch_token_t));
	ret = sgx_create_enclave(SERVER_ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &t, &updated, &id, NULL);
	if (ret != SGX_SUCCESS) {
		printf("Failed to create Enclave : error %d - %#x.\n", ret, ret);
		return 1;
	}

  int                sockfd;
  int                connd;
  struct sockaddr_in servAddr;
  struct sockaddr_in clientAddr;
  socklen_t          size = sizeof(clientAddr);
  char               buff[256];
  size_t             len;

  /* declare wolfSSL objects */
  WOLFSSL_CTX* ctx;
  WOLFSSL*     ssl;
  WOLFSSL_METHOD* method;

  /* Initialize wolfSSL */
  sgxStatus = enc_wolfSSL_Init(id, &ret);
  if (sgxStatus != SGX_SUCCESS || ret != WOLFSSL_SUCCESS) {
    printf("wolfSSL_Init failure\n");
    return EXIT_FAILURE;
  }

#ifdef SGX_DEBUG
  enc_wolfSSL_Debugging_ON(id);
#else
  enc_wolfSSL_Debugging_OFF(id);
#endif

  /* Create a socket that uses an internet IPv4 address,
    * Sets the socket to be stream based (TCP),
    * 0 means choose the default protocol. */
  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
      fprintf(stderr, "ERROR: failed to create the socket\n");
      return -1;
  }

  int enable = 1;
  ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
  assert(ret != -1);

  /* Create and initialize WOLFSSL_CTX */
  sgxStatus = enc_wolfTLSv1_2_server_method(id, &method);
  if (sgxStatus != SGX_SUCCESS || method == NULL) {
      printf("wolfTLSv1_2_server_method failure\n");
      return EXIT_FAILURE;
  }

  sgxStatus = enc_wolfSSL_CTX_new(id, &ctx, method);
  if (sgxStatus != SGX_SUCCESS || ctx == NULL) {
      printf("wolfSSL_CTX_new failure\n");
      return EXIT_FAILURE;
  }

#if 0
  /* Load server certificates into WOLFSSL_CTX */
  sgxStatus = enc_wolfSSL_CTX_use_certificate_buffer(id, &ret, ctx,
          server_cert_der_2048, sizeof_server_cert_der_2048, SSL_FILETYPE_ASN1);
  if (sgxStatus != SGX_SUCCESS || ret != SSL_SUCCESS) {
      printf("enc_wolfSSL_CTX_use_certificate_chain_buffer_format failure\n");
      return EXIT_FAILURE;ifndef DEPS_INCLUDE_DIR
	$(error DEPS_INCLUDE_DIR is not set. Please set to ratls dependency headers directory)
endif
ifndef SGX_WOLFSSL_LIB
	$(error SGX_WOLFSSL_LIB is not set. Please set to wolfssl library (build for RA_TLS) directory)
endif
  }

  /* Load server key into WOLFSSL_CTX */
  sgxStatus = enc_wolfSSL_CTX_use_PrivateKey_buffer(id, &ret, ctx,
          server_key_der_2048, sizeof_server_key_der_2048, SSL_FILETYPE_ASN1);
  if (sgxStatus != SGX_SUCCESS || ret != SSL_SUCCESS) {
      printf("wolfSSL_CTX_use_PrivateKey_buffer failure\n");
      return EXIT_FAILURE;
  }
#endif

  // prepare ra cert and add as extension
  sgxStatus = enc_create_key_and_x509(id, ctx);
  assert(sgxStatus == SGX_SUCCESS);
  // prepare ra cert and add as extension
  
  /* Initialize the server address struct with zeros */
  memset(&servAddr, 0, sizeof(servAddr));
  /* Fill in the server address */
  servAddr.sin_family      = AF_INET;             /* using IPv4      */
  servAddr.sin_port        = htons(DEFAULT_PORT); /* on DEFAULT_PORT */
  servAddr.sin_addr.s_addr = INADDR_ANY;          /* from anywhere   */

  /* Bind the server socket to our port */
  if (bind(sockfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) == -1) {
      fprintf(stderr, "ERROR: failed to bind\n");
      return -1;
  }

  /* Listen for a new connection, allow 5 pending connections */
  if (listen(sockfd, 5) == -1) {
      fprintf(stderr, "ERROR: failed to listen\n");
      return -1;
  }

  printf("Waiting for a connection...\n");

  /* Accept client connections */
  if ((connd = accept(sockfd, (struct sockaddr*)&clientAddr, &size))
      == -1) {
      fprintf(stderr, "ERROR: failed to accept the connection\n\n");
      return -1;
  }

  sgxStatus = enc_wolfSSL_new(id, &ssl, ctx);

  if (sgxStatus != SGX_SUCCESS || ssl == NULL) {
      printf("wolfSSL_new failure\n");
      return EXIT_FAILURE;
  }

  /* Attach wolfSSL to the socket */
  sgxStatus = enc_wolfSSL_set_fd(id, &ret, ssl, connd);
  if (sgxStatus != SGX_SUCCESS || ret != SSL_SUCCESS) {
      printf("wolfSSL_set_fd failure\n");
      return EXIT_FAILURE;
  }

  printf("Client connected successfully\n");

  /* Read the client data into our buff array */
  memset(buff, 0, sizeof(buff));
  sgxStatus = enc_wolfSSL_read(id, &ret, ssl, buff, sizeof(buff)-1);
  if(sgxStatus != SGX_SUCCESS || ret == -1) {
      printf("Server failed to read\n");
      return EXIT_FAILURE;
  }

  /* Print to stdout any data the client sends */
  printf("Client: %s\n", buff);

  /* Write our reply into buff */
  memset(buff, 0, sizeof(buff));
  const char msg[] = "I hear ya fa shizzle!\n"; 
  memcpy(buff, msg, sizeof(msg));
  len = strnlen(buff, sizeof(buff));

  /* Reply back to the client */
  sgxStatus = enc_wolfSSL_write(id, &ret, ssl, buff, len);
  if (sgxStatus != SGX_SUCCESS || ret != len) {
      printf("Server write failed.\n");
      return EXIT_FAILURE;
  }

  /* Cleanup after this connection */
  enc_wolfSSL_free(id, ssl);      /* Free the wolfSSL object              */
  close(connd);           /* Close the connection to the client   */

  /* Cleanup and return */
  sgxStatus = enc_wolfSSL_CTX_free(id, ctx);  /* Free the wolfSSL context object          */
  sgxStatus = enc_wolfSSL_Cleanup(id, &ret);      /* Cleanup the wolfSSL environment          */
  close(sockfd);          /* Close the socket listening for clients   */
  return 0;               /* Return reporting a success               */
}

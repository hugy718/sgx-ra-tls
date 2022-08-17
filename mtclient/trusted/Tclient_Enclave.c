#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>      /* vsnprintf */

#include "Tclient_Enclave_t.h"

#include "wolfssl-ra-attester.h"
#include "wolfssl-ra-challenger.h"

#include "sgx_trts.h"

typedef struct {
  bool initialized;
  WOLFSSL_CTX* ctx;
  WOLFSSL* ssl;
  WOLFSSL_METHOD* method;
} SslContext;

typedef struct {
  bool connected;
  int sockfd;
  size_t rcv_len;
  char rcvBuff[4096];
} SslChannel;

__thread SslContext loacl_context = {false, NULL, NULL, NULL};
__thread SslChannel channel = {false, 0, 0};

static int ssl_ctx_setup(SslContext* lc) {
  #ifdef SGX_DEBUG
  wolfSSL_Debugging_ON();
#else
  wolfSSL_Debugging_OFF();
#endif

  /* Initialize wolfSSL */
  int ret = wolfSSL_Init();
  if (ret != SSL_SUCCESS) return -1;
  lc->method = wolfTLSv1_2_client_method();
  if(lc->method == NULL) return -1;

  lc->ctx = wolfSSL_CTX_new(lc->method);
  if (lc->ctx == NULL) return -1;

  // setup verify callback in enclave (only difference with tclient)
  wolfSSL_CTX_set_verify(lc->ctx, SSL_VERIFY_PEER, cert_verify_callback);
  // setup verify callback in enclave (only difference with tclient)

  // prepare ra cert and add as extension
  wolfssl_create_key_and_x509_ctx(lc->ctx);
  // prepare ra cert and add as extension

  // link socket to wolfssl ctx
  lc->ssl = wolfSSL_new(lc->ctx);
  if (lc->ssl == NULL) return -1;
  lc->initialized = true;
  return 0;
}

static void channel_clear(SslChannel* c) {
  memset(c->rcvBuff, 0, sizeof(c->rcvBuff));
  c->rcv_len = 0;
}

static int channel_close(SslChannel* c) {
  c->connected = false;
  return (ocall_close_socket(c->sockfd) == SGX_SUCCESS) ? 0 : -1;
}

int channel_setup(const char* server_addr, size_t addr_len,
  uint16_t port, SslContext* lc, SslChannel* c) {

  // initialize ssl ctx
  if ((!loacl_context.initialized) && (ssl_ctx_setup(lc) != 0)) {
    return -1; 
  }

  // disconnect the last connection
  channel_clear(&channel);
  if (c->connected && (channel_close(c) != 0)) return -1;

  // prepare the sockfd at untrusted side
  sgx_status_t status = ocall_get_socket(&c->sockfd, server_addr,
    addr_len, port);
  if (status != SGX_SUCCESS) return -1;

  // link socket to wolfssl ctx
  int ret = wolfSSL_set_fd(lc->ssl, c->sockfd);
  if (ret != SSL_SUCCESS) return -1;

  // establish connection
  ret = wolfSSL_connect(lc->ssl);
  if (ret != SSL_SUCCESS) return -1;

  // mark connected
  c->connected = true;
  return 0;
}

int enc_sample_send(const char* msg, size_t msg_len,
  const char* server_addr, size_t addr_len, uint16_t port) {
  // setup wolfssl in enclave
  if (channel_setup(server_addr, addr_len, port, &loacl_context,
    &channel) != 0) return -1;
  
  if (wolfSSL_write(loacl_context.ssl, msg, (int) msg_len) != msg_len) {
    return -1;
  }
  channel_clear(&channel);
  int read_len = wolfSSL_read(loacl_context.ssl, channel.rcvBuff,
    sizeof(channel.rcvBuff)-1);
  if (read_len <= 0) return -1;
  channel.rcv_len = (size_t) read_len;
  return channel_close(&channel);
}

int enc_retrieve_sample_reply(void* data, size_t sz) {
  if (sz < channel.rcv_len) return -1;
  memcpy(data, channel.rcvBuff, channel.rcv_len);
  return 0;
}

int enc_ssl_free() {
  wolfSSL_free(loacl_context.ssl);
  wolfSSL_CTX_free(loacl_context.ctx);
  wolfSSL_Cleanup();
  channel_clear(&channel);
  return (channel.connected) ? channel_close(&channel) : 0;  
}

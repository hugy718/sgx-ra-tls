// suppress cert_verify_callback undefined error for server
// server does not do verify but due to the bad object grouping, the api to do so is added to the ratls server lib.
#include "challenger_wolfssl.h"

int cert_verify_callback(int preverify, WOLFSSL_X509_STORE_CTX* store) {
  return 0;
}

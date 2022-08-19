#ifndef RATLS_CURL_HELPER_H_
#define RATLS_CURL_HELPER_H_

#include "curl/curl.h"

struct buffer_and_size {
    char* data;
    size_t len;
};

void http_get
(
    CURL* curl,
    const char* url,
    struct buffer_and_size* header,
    struct buffer_and_size* body,
    struct curl_slist* request_headers,
    char* request_body
);

#endif  // RATLS_CURL_HELPER_H_

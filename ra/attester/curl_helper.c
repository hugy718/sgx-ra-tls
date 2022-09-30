#include "curl_helper.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

static
size_t accumulate_function(void *ptr, size_t size, size_t nmemb, void *userdata) {
    struct buffer_and_size* s = (struct buffer_and_size*) userdata;
    s->data = (char*) realloc(s->data, s->len + size * nmemb);
    assert(s->data != NULL);
    memcpy(s->data + s->len, ptr, size * nmemb);
    s->len += size * nmemb;
    
    return size * nmemb;
}

static void curl_ra_print_time() {
  struct timeval t;
  gettimeofday(&t, 0);
  printf("timing(curl ra): %llu\n",
    (unsigned long long) t.tv_sec*1000*1000
    + (unsigned long long) t.tv_usec);
}

void http_get
(
    CURL* curl,
    const char* url,
    struct buffer_and_size* header,
    struct buffer_and_size* body,
    struct curl_slist* request_headers,
    char* request_body
)
{
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
    
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, accumulate_function);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, header);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, accumulate_function);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, body);

    if (request_headers) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, request_headers);
    }
    if (request_body) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_body);
    }

    curl_ra_print_time();
    CURLcode res = curl_easy_perform(curl);
    curl_ra_print_time();

    if (res != CURLE_OK) {
      printf("sent url: %s\n", url);
      do {
        printf("sent header: %s\n", request_headers->data);
        request_headers = request_headers->next;
      } while (request_headers);
      printf("sent body: %s\n", request_body);
      printf("resp header: %.*s\n", header->len, header->data);
      printf("resp body: %.*s\n", body->len, body->data);
      printf("curl code: %d\n", res);
      fflush(stdout);
    }
    assert(res == CURLE_OK);
}


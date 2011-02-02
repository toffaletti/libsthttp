#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "http_stream.h"

static void *do_get(void *arg) {
  const char *error_at = NULL;
  char *uri_s = (char *)arg;
  struct http_stream *s = http_stream_create(HTTP_CLIENT, ST_UTIME_NO_TIMEOUT);

  uri_t *uri = uri_new();
  fprintf(stderr, "uri: %s\n", uri_s);
  if (uri_parse(uri, uri_s, strlen(uri_s), &error_at) == 0) {
    fprintf(stderr, "uri_parse error: %s\n", error_at);
    goto done;
  }
  uri_normalize(uri);
  fprintf(stderr, "h: %s\n", uri->host);
  fprintf(stderr, "p: %u\n", uri->port);

  if (http_stream_connect(s, uri->host, uri->port) != HTTP_STREAM_OK) goto done;
  http_stream_request_init(s, "GET", uri);
  if (http_stream_request_send(s) != HTTP_STREAM_OK) goto done;
  if (http_stream_response_read(s) != HTTP_STREAM_OK) goto done;

  size_t total = 0;
  char buf[4 * 1024];
  for (;;) {
    ssize_t nr = sizeof(buf);
    int status = http_stream_read(s, buf, &nr);
    fprintf(stderr, "http_stream_read nr: %zd\n", nr);
    if (nr <= 0 || status != HTTP_STREAM_OK) break;
    fwrite(buf, sizeof(char), nr, stdout);
    total += nr;
  }
  fprintf(stderr, "http_stream_read total: %zu\n", total);

done:
  uri_free(uri);
  http_stream_close(s);
  return NULL;
}

int main(int argc, char *argv[]) {
  int status;
  st_init();
  status = ares_library_init(ARES_LIB_INIT_ALL);
  if (status != ARES_SUCCESS)
  {
    fprintf(stderr, "ares_library_init: %s\n", ares_strerror(status));
    return 1;
  }

  fprintf(stderr, "sizeof(http_stream): %zu\n", sizeof(struct http_stream));

  st_thread_t t = st_thread_create(do_get, argv[argc-1], 1, 1024 * 128);
  st_thread_join(t, NULL);

  ares_library_cleanup();
  return 0;
}


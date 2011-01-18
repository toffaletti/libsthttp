#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "http_stream.h"

static void *do_get(void *arg) {
  const char *error_at = NULL;
  char *uri_s = (char *)arg;
  struct http_stream *s = http_stream_create(HTTP_CLIENT, ST_UTIME_NO_TIMEOUT);

  uri u;
  uri_init(&u);
  fprintf(stderr, "uri: %s\n", uri_s);
  if (uri_parse(&u, uri_s, strlen(uri_s), &error_at) == 0) {
    fprintf(stderr, "uri_parse error: %s\n", error_at);
    goto done;
  }
  uri_normalize(&u);
  fprintf(stderr, "h: %s\n", u.host);
  fprintf(stderr, "p: %u\n", u.port);
  if (g_strcmp0(u.scheme, "http") == 0 && u.port == 0) {
    u.port = 80;
  }

  if (!http_stream_connect(s, u.host, u.port)) goto done;
  if (!http_stream_request(s, &u)) goto done;

  ssize_t total = 0;
  char buf[4 * 1024];
  for (;;) {
    ssize_t nr = http_stream_read(s, buf, sizeof(buf));
    fprintf(stderr, "http_stream_read nr: %zd\n", nr);
    if (nr == 0 || nr == -1) break;
    fwrite(buf, sizeof(char), nr, stdout);
    total += nr;
  }
  fprintf(stderr, "http_stream_read total: %zu\n", total);

done:
  uri_free(&u);
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

  printf("sizeof(http_stream): %zu\n", sizeof(struct http_stream));

  st_thread_t t = st_thread_create(do_get, argv[argc-1], 1, 1024 * 128);
  st_thread_join(t, NULL);

  ares_library_cleanup();
  return 0;
}


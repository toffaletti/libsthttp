#include "st.h"
#include "st_dns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "uri_parser.h"
#include "http_message.h"

#define min(a, b) ((a) > (b) ? (b) : (a))
#define max(a, b) ((a) > (b) ? (a) : (b))

struct http_stream {

  httpclient_parser *clp;
  http_response *resp;
  const gchar *transfer_encoding;

  const gchar *start;
  const gchar *end;

  gchar *buf;
  size_t blen;

  st_netfd_t nfd;

  ssize_t content_size;
  size_t total_read;
  size_t chunk_read;

}; /* http_stream */

struct http_stream *http_stream_open(httpclient_parser *clp, http_response *resp, st_netfd_t nfd) {
  struct http_stream *s = (struct http_stream *)calloc(1, sizeof(struct http_stream));
  s->clp = clp;
  s->resp = resp;
  s->nfd = nfd;
  s->blen = 8 * 1024;
  s->buf = g_malloc(s->blen);
  s->content_size = -1; /* unknown content size */

  http_response_parser_init(s->resp, s->clp);
  size_t bpos = 0;
  do {
    httpclient_parser_init(s->clp);
    ssize_t nr = st_read(s->nfd, &s->buf[bpos], s->blen-bpos, ST_UTIME_NO_TIMEOUT);
    fprintf(stderr, "nr: %zd\n", nr);
    size_t pe = httpclient_parser_execute(s->clp, s->buf, bpos+nr, 0);
    fprintf(stderr, "pe: %zu\n", pe);
    if (httpclient_parser_has_error(s->clp)) {
      fprintf(stderr, "parser error");
      break;
    }
    if (!httpclient_parser_is_finished(s->clp)) {
      s->blen += (4 * 1024);
      g_assert(s->blen < (4 * 1024 * 1024));
      s->buf = g_realloc(s->buf, s->blen);
      bpos += nr;
      fprintf(stderr, "bpos: %zu\n", bpos);
      http_response_clear(s->resp);
    }
  } while (!httpclient_parser_is_finished(s->clp));

  if (httpclient_parser_is_finished(s->clp) && !httpclient_parser_has_error(s->clp)) {
    // TODO: probably use enum for transfer encoding
    s->transfer_encoding = http_response_header_getstr(resp, "Transfer-Encoding");
    const gchar *content_length = http_response_header_getstr(resp, "Content-Length");
    if (content_length) { s->content_size = strtoull(content_length, NULL, 0); }
    fprintf(stderr, "transfer_encoding: %s\n", s->transfer_encoding);
    s->start = resp->body;
    s->end = resp->body + resp->body_length;
  }
  return s;
}

static ssize_t _http_stream_read_chunked(struct http_stream *s, void *ptr, size_t size) {
  fprintf(stderr, "start: %p end: %p len: %zd\n", s->start, s->end, s->end - s->start);
  fprintf(stderr, "chunk_read: %zu/%zu\n", s->chunk_read, s->resp->chunk_size);
  if (s->chunk_read > 0 && s->chunk_read == s->resp->chunk_size) {
    fprintf(stderr, "CHUNK DONE\n");
    s->chunk_read = 0;
    // XXX: fix this because it might advance past end
    s->start += 2; // crlf
  }
  g_assert(s->start <= s->end);

  if (s->start == s->end) {
    size_t nr = st_read(s->nfd, s->buf, s->blen, ST_UTIME_NO_TIMEOUT);
    s->start = s->buf;
    s->end = s->buf + nr;
  }

  if (s->chunk_read == 0) {
    http_response_clear(s->resp);
    httpclient_parser_init(s->clp);
    httpclient_parser_execute(s->clp, s->start, s->end - s->start, 0);
    fprintf(stderr, "\n=====\n");
    fprintf(stderr, "nread: %zu\n", s->clp->nread);
    fprintf(stderr, "chunk_size: %zu\n", s->resp->chunk_size);
    fprintf(stderr, "last_chunk: %d\n", s->resp->last_chunk);
    fprintf(stderr, "error?: %d\n", httpclient_parser_has_error(s->clp));
    fprintf(stderr, "finished?: %d\n", httpclient_parser_is_finished(s->clp));
    if (s->resp->last_chunk) { return 0; }
    if (httpclient_parser_has_error(s->clp)) { return -1; }
    s->start += s->clp->nread-1;
  }

  if (s->start < s->end) {
    g_assert(s->end >= s->start);
    g_assert(s->resp->chunk_size >= s->chunk_read);
    ssize_t rvalue = min(s->resp->chunk_size - s->chunk_read, min(size, (size_t)(s->end - s->start)));
    memcpy(ptr, s->start, rvalue);
    s->start += rvalue;
    s->chunk_read += rvalue;
    return rvalue;
  }
  return -1;
}

ssize_t http_stream_read(struct http_stream *s, void *ptr, size_t size) {
  if (httpclient_parser_has_error(s->clp)) { return -1; }
  g_assert(s->resp->body);

  if (g_strcmp0("chunked", s->transfer_encoding) == 0) {
    return _http_stream_read_chunked(s, ptr, size);
  } else {
    if (s->content_size >= 0 && s->content_size == s->total_read) { return 0; }
    if (s->total_read == 0) {
      s->start = s->resp->body;
      s->end = s->resp->body + s->resp->body_length;
    }
    g_assert(s->end >= s->start);
    if (s->total_read < s->resp->body_length) {
      ssize_t rvalue = min(size, (size_t)(s->end - s->start));
      memcpy(ptr, s->start, rvalue);
      s->start += rvalue;
      s->total_read += rvalue;
      return rvalue;
    }
    ssize_t nr = st_read(s->nfd, ptr, size, ST_UTIME_NO_TIMEOUT);
    s->total_read += nr;
    fprintf(stderr, "read %zu bytes, %zu/%zu\n", nr, s->total_read, s->content_size);
    return nr;
  }

  return -1;
}

void http_stream_close(struct http_stream *s) {
  g_assert(s->buf);
  g_free(s->buf);
  memset(s, 0, sizeof(struct http_stream));
  free(s);
}

static void *do_get(void *arg) {
  const char *error_at = NULL;
  char *uri_s = (char *)arg;
  int status;
  struct hostent *host;

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
  status = st_gethostbyname_r(u.host, &host);

  char **p = NULL;
  for (p = host->h_addr_list; *p; p++)
  {
    char addr_buf[46] = "??";
    inet_ntop(host->h_addrtype, *p, addr_buf, sizeof(addr_buf));
    fprintf(stderr, "%-32s\t%s\n", host->h_name, addr_buf);

    int sock;

    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
      perror("socket");
      goto done;
    }

    st_netfd_t rmt_nfd;
    if ((rmt_nfd = st_netfd_open_socket(sock)) == NULL) {
      perror("st_netfd_open_socket");
      goto done;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = host->h_addrtype;
    addr.sin_port = htons(u.port);
    memcpy(&addr.sin_addr, *p, host->h_length);
    if (st_connect(rmt_nfd, (struct sockaddr*)&addr, sizeof(addr), ST_UTIME_NO_TIMEOUT) < 0) {
      perror("st_connect");
      st_netfd_close(rmt_nfd);
      continue;
    }

    fprintf(stderr, "connected\n");
    fprintf(stderr, "p: %s\n", u.path);
    http_request req;
    http_request_make(&req, "GET", u.path);
    http_request_header_append(&req, "Host", u.host);
    http_request_fwrite(&req, stderr);

    GString *req_data = http_request_data(&req);
    st_write(rmt_nfd, req_data->str, req_data->len, ST_UTIME_NO_TIMEOUT);

    http_request_free(&req);
    g_string_free(req_data, TRUE);

    http_response resp;
    httpclient_parser clp;

    struct http_stream *s = http_stream_open(&clp, &resp, rmt_nfd);

    GString *resp_data = http_response_data(s->resp);
    fprintf(stderr, "resp: %s\n", resp_data->str);
    g_string_free(resp_data, TRUE);

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

    http_stream_close(s);
    http_response_free(&resp);
    st_netfd_close(rmt_nfd);
    break;
  }

done:

  uri_free(&u);
  ares_free_hostent(host);

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

  st_thread_t t = st_thread_create(do_get, argv[argc-1], 1, 1024 * 128);
  st_thread_join(t, NULL);

  ares_library_cleanup();
  return 0;
}


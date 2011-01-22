#include "http_stream.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define min(a, b) ((a) > (b) ? (b) : (a))
#define max(a, b) ((a) > (b) ? (a) : (b))

struct http_stream *http_stream_create(int mode, st_utime_t timeout) {
  struct http_stream *s = (struct http_stream *)calloc(1, sizeof(struct http_stream));
  s->nfd = NULL;
  s->blen = 8 * 1024;
  s->buf = g_malloc(s->blen);
  s->content_size = -1; /* unknown content size */
  s->timeout = timeout;
  s->mode = mode;
  if (s->mode == HTTP_CLIENT) {
    http_response_parser_init(&s->resp, &s->parser.client);
  } else {
    http_request_parser_init(&s->req, &s->parser.server);
  }
  return s;
}

int http_stream_connect(struct http_stream *s, const char *address, uint16_t port) {
  int status;
  struct hostent *host;
  int rvalue = 0;

  g_assert(s->mode == HTTP_CLIENT);

  if (!port) port = 80;

  status = st_gethostbyname_r(address, &host);
  if (status || host == NULL) return 0;

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
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, *p, host->h_length);
    if (st_connect(rmt_nfd, (struct sockaddr*)&addr, sizeof(addr), s->timeout) < 0) {
      perror("st_connect");
      st_netfd_close(rmt_nfd);
      continue;
    }

    s->nfd = rmt_nfd;
    fprintf(stderr, "connected\n");
    rvalue = 1;
    break;
  }

done:
  ares_free_hostent(host);
  return rvalue;
}

ssize_t http_stream_send_chunk(struct http_stream *s, const char *buf, size_t size) {
  const char endbuf[] = "\r\n";
  char lenbuf[64];
  struct iovec vec[3];
  int len = snprintf(lenbuf, sizeof(lenbuf)-1, "%zx\r\n", size);
  if (len <= 0) return len;
  vec[0].iov_base = lenbuf;
  vec[0].iov_len = len;
  vec[1].iov_base = (char *)buf;
  vec[1].iov_len = size;
  vec[2].iov_base = (char *)endbuf;
  vec[2].iov_len = 2;

  ssize_t nw = st_writev(s->nfd, vec, 3, s->timeout);
  return nw;
}

ssize_t http_stream_send_chunk_end(struct http_stream *s) {
  ssize_t nw = st_write(s->nfd, "0\r\n\r\n", 5, s->timeout);
  return nw;
}

ssize_t http_stream_request_send(struct http_stream *s) {
  //http_request_fwrite(&s->req, stderr);
  GString *req_data = http_request_data(&s->req);
  //fprintf(stderr, "REQ: %s\n", req_data->str);
  ssize_t nw = st_write(s->nfd, req_data->str, req_data->len, s->timeout);
  g_string_free(req_data, TRUE);
  return nw;
}

ssize_t http_stream_response_send(struct http_stream *s, int body) {
  GString *req_data = http_response_data(&s->resp);
  ssize_t nw = st_write(s->nfd, req_data->str, req_data->len, s->timeout);
  g_string_free(req_data, TRUE);
  if (body && s->resp.body_length) {
    nw = st_write(s->nfd, s->resp.body, s->resp.body_length, s->timeout);
  }
  return nw;
}

int http_stream_request_read(struct http_stream *s, st_netfd_t nfd) {
  g_assert(s->mode == HTTP_SERVER);
  s->nfd = nfd;
  size_t bpos = 0;
  http_request_clear(&s->req);
  do {
    http_parser_init(&s->parser.server);
    ssize_t nr = st_read(s->nfd, &s->buf[bpos], s->blen-bpos, s->timeout);
    fprintf(stderr, "read_request nr: %zd\n", nr);
    if (nr <= 0) return 0;
    size_t pe = http_parser_execute(&s->parser.server, s->buf, bpos+nr, 0);
    fprintf(stderr, "pe: %zu\n", pe);
    if (http_parser_has_error(&s->parser.server)) {
      fprintf(stderr, "http_stream_request_read parser error\n");
      break;
    }
    if (!http_parser_is_finished(&s->parser.server)) {
      if (bpos+nr+1024 >= s->blen) {
        s->blen += (4 * 1024);
        g_assert(s->blen < (4 * 1024 * 1024));
        s->buf = g_realloc(s->buf, s->blen);
      }
      bpos += nr;
      fprintf(stderr, "bpos: %zu\n", bpos);
      http_request_clear(&s->req);
    }
  } while (!http_parser_is_finished(&s->parser.server));

  if (http_parser_is_finished(&s->parser.server) && !http_parser_has_error(&s->parser.server)) {
    // TODO: probably use enum for transfer encoding
    const gchar *transfer_encoding = http_response_header_getstr(&s->req, "Transfer-Encoding");
    if (g_strcmp0(transfer_encoding, "chunked") == 0) {
      s->transfer_encoding = TE_CHUNKED;
    }
    const gchar *content_length = http_response_header_getstr(&s->req, "Content-Length");
    if (content_length) {
      s->content_size = strtoull(content_length, NULL, 0);
    } else {
      /* pretty sure client *must* send content length if there is any */
      s->content_size = 0;
    }
    fprintf(stderr, "transfer_encoding: %s\n", transfer_encoding);
    s->start = s->req.body;
    s->end = s->req.body + s->req.body_length;

    if (http_request_header_getstr(&s->req, "Expect")) {
      http_response_init(&s->resp, 100, "Continue");
      printf("sending 100-continue\n");
      ssize_t nw = http_stream_response_send(s, 0);
      http_response_free(&s->resp);
      if (nw <= 0) return 0;
    }
  }
  return (http_parser_is_finished(&s->parser.server) &&
    !http_parser_has_error(&s->parser.server)) ? 1: -1;
}

int http_stream_request_init(struct http_stream *s, const char *method, uri *u) {
  char *request_uri = uri_compose_partial(u);
  fprintf(stderr, "request URI: %s\n", request_uri);
  http_request_make(&s->req, method, request_uri);
  free(request_uri);
  http_request_header_append(&s->req, "Host", u->host);
  /* TODO: bogus UA */
  http_request_header_append(&s->req, "User-Agent", "Mozilla/5.0 (X11; U; Linux x86_64; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Ubuntu/10.10 Chromium/8.0.552.224 Chrome/8.0.552.224 Safari/534.10");
  /* TODO: check results, handle errors */
  return 1;
}

int http_stream_response_read(struct http_stream *s) {
  g_assert(s->mode == HTTP_CLIENT);

  size_t bpos = 0;
  do {
    httpclient_parser_init(&s->parser.client);
    ssize_t nr = st_read(s->nfd, &s->buf[bpos], s->blen-bpos, s->timeout);
    if (nr <= 0) break;
    size_t pe = httpclient_parser_execute(&s->parser.client, s->buf, bpos+nr, 0);
    fprintf(stderr, "pe: %zu\n", pe);
    if (httpclient_parser_has_error(&s->parser.client)) {
      fprintf(stderr, "parser error");
      break;
    }
    if (!httpclient_parser_is_finished(&s->parser.client)) {
      if (bpos+nr+1024 >= s->blen) {
        s->blen += (4 * 1024);
        g_assert(s->blen < (4 * 1024 * 1024));
        s->buf = g_realloc(s->buf, s->blen);
      }
      bpos += nr;
      fprintf(stderr, "bpos: %zu\n", bpos);
      http_response_clear(&s->resp);
    }
  } while (!httpclient_parser_is_finished(&s->parser.client));

  if (httpclient_parser_is_finished(&s->parser.client) && !httpclient_parser_has_error(&s->parser.client)) {
    // TODO: probably use enum for transfer encoding
    const gchar *transfer_encoding = http_response_header_getstr(&s->resp, "Transfer-Encoding");
    if (g_strcmp0(transfer_encoding, "chunked") == 0) {
      s->transfer_encoding = TE_CHUNKED;
    }
    const gchar *content_length = http_response_header_getstr(&s->resp, "Content-Length");
    if (content_length) { s->content_size = strtoull(content_length, NULL, 0); }
    fprintf(stderr, "transfer_encoding: %s\n", transfer_encoding);
    s->start = s->resp.body;
    s->end = s->resp.body + s->resp.body_length;
  }

  //GString *resp_data = http_response_data(&s->resp);
  //fprintf(stderr, "resp: %s\n", resp_data->str);
  //g_string_free(resp_data, TRUE);

  return (httpclient_parser_is_finished(&s->parser.client) &&
    !httpclient_parser_has_error(&s->parser.client));
}

static ssize_t _http_stream_read_chunked(struct http_stream *s, void *ptr, size_t size) {
  fprintf(stderr, "start: %p end: %p len: %zd\n", s->start, s->end, s->end - s->start);
  fprintf(stderr, "chunk_read: %zu/%zu\n", s->chunk_read, s->resp.chunk_size);
  if (s->start == s->end) {
    size_t nr = st_read(s->nfd, s->buf, s->blen, s->timeout);
    s->start = s->buf;
    s->end = s->buf + nr;
  }
  if (s->chunk_read > 0 && s->chunk_read == s->resp.chunk_size) {
    fprintf(stderr, "CHUNK DONE\n");
    s->chunk_read = 0;
    if (s->start+2 >= s->end) {
      size_t skip = 2 - (s->end - s->start); // skip crlf
      size_t nr = st_read(s->nfd, s->buf, s->blen, s->timeout);
      s->start = s->buf+skip;
      s->end = s->buf + nr;
    } else {
      s->start += 2; // crlf
    }
  }
  g_assert(s->start <= s->end);

  if (s->chunk_read == 0) {
    http_response_clear(&s->resp);
    httpclient_parser_init(&s->parser.client);
    httpclient_parser_execute(&s->parser.client, s->start, s->end - s->start, 0);
    fprintf(stderr, "\n=====\n");
    fprintf(stderr, "nread: %zu\n", s->parser.client.nread);
    fprintf(stderr, "chunk_size: %zu\n", s->resp.chunk_size);
    fprintf(stderr, "last_chunk: %d\n", s->resp.last_chunk);
    fprintf(stderr, "error?: %d\n", httpclient_parser_has_error(&s->parser.client));
    fprintf(stderr, "finished?: %d\n", httpclient_parser_is_finished(&s->parser.client));
    if (s->resp.last_chunk) { return 0; }
    if (httpclient_parser_has_error(&s->parser.client)) { return -1; }
    s->start += s->parser.client.nread-1;
  }

  if (s->start < s->end) {
    g_assert(s->end >= s->start);
    g_assert(s->resp.chunk_size >= s->chunk_read);
    ssize_t rvalue = min(s->resp.chunk_size - s->chunk_read, min(size, (size_t)(s->end - s->start)));
    memcpy(ptr, s->start, rvalue);
    s->start += rvalue;
    s->chunk_read += rvalue;
    return rvalue;
  }
  return -1;
}

static ssize_t _http_stream_read_server(struct http_stream *s, void *ptr, size_t size) {
  if (http_parser_has_error(&s->parser.server)) { return -1; }
  fprintf(stderr, "req body: %p\n", s->req.body);

  if (s->content_size >= 0 && (size_t)s->content_size == s->total_read) { return 0; }
  if (s->total_read == 0 && s->req.body) {
    s->start = s->req.body;
    s->end = s->req.body + s->req.body_length;
  }
  g_assert(s->end >= s->start);
  if (s->total_read < s->req.body_length && s->req.body_length > 0) {
    ssize_t rvalue = min(size, (size_t)(s->end - s->start));
    memcpy(ptr, s->start, rvalue);
    s->start += rvalue;
    s->total_read += rvalue;
    return rvalue;
  }
  ssize_t nr = st_read(s->nfd, ptr, size, s->timeout);
  s->total_read += nr;
  fprintf(stderr, "read %zu bytes, %zu/%zu\n", nr, s->total_read, s->content_size);
  return nr;
}

static ssize_t _http_stream_read_client(struct http_stream *s, void *ptr, size_t size) {
  if (httpclient_parser_has_error(&s->parser.client)) { return -1; }
  /* status 204 means no body */
  if (s->resp.status_code == 204) { return 0; }

  if (s->transfer_encoding == TE_CHUNKED) {
    return _http_stream_read_chunked(s, ptr, size);
  } else {
    if (s->content_size >= 0 && (size_t)s->content_size == s->total_read) { return 0; }
    if (s->total_read == 0 && s->resp.body) {
      s->start = s->resp.body;
      s->end = s->resp.body + s->resp.body_length;
    }
    if (s->total_read < s->resp.body_length) {
      g_assert(s->end >= s->start);
      ssize_t rvalue = min(size, (size_t)(s->end - s->start));
      memcpy(ptr, s->start, rvalue);
      s->start += rvalue;
      s->total_read += rvalue;
      return rvalue;
    }
    ssize_t nr = st_read(s->nfd, ptr, size, s->timeout);
    s->total_read += nr;
    fprintf(stderr, "read %zu bytes, %zu/%zu\n", nr, s->total_read, s->content_size);
    return nr;
  }

  return -1;
}

ssize_t http_stream_read(struct http_stream *s, void *ptr, size_t size) {
  switch (s->mode) {
  case HTTP_CLIENT:
    return _http_stream_read_client(s, ptr, size);
  case HTTP_SERVER:
    return _http_stream_read_server(s, ptr, size);
  }
  return -1;
}

void http_stream_close(struct http_stream *s) {
  g_assert(s->buf);
  g_free(s->buf);
  http_response_free(&s->resp);
  http_request_free(&s->req);
  if (s->nfd) { st_netfd_close(s->nfd); }
  memset(s, 0, sizeof(struct http_stream));
  free(s);
}

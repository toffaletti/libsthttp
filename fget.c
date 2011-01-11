#include "st.h"
#include "st_dns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "uri_parser.h"
#include "http_message.h"

static void *do_get(void *arg) {
  size_t blen = 4 * 1024;
  char *buf = g_malloc(blen);
  size_t bpos = 0;
  const char *error_at = NULL;
  char *uri_s = (char *)arg;
  struct hostent *host;
  int status;

  uri u;
  uri_init(&u);
  printf("uri: %s\n", uri_s);
  if (uri_parse(&u, uri_s, strlen(uri_s), &error_at) == 0) {
    printf("uri_parse error: %s\n", error_at);
    goto done;
  }
  uri_normalize(&u);
  printf("h: %s\n", u.host);
  printf("p: %u\n", u.port);
  if (g_strcmp0(u.scheme, "http") == 0 && u.port == 0) {
    u.port = 80;
  }
  status = st_gethostbyname_r(u.host, &host);

  char **p = NULL;
  for (p = host->h_addr_list; *p; p++)
  {
    char addr_buf[46] = "??";
    inet_ntop(host->h_addrtype, *p, addr_buf, sizeof(addr_buf));
    printf("%-32s\t%s", host->h_name, addr_buf);
    puts("");

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

    printf("connected\n");
    printf("p: %s\n", u.path);
    http_request req;
    http_request_make(&req, "GET", u.path);
    http_request_header_append(&req, "Host", u.host);
    http_request_fwrite(&req, stdout);

    GString *req_data = http_request_data(&req);
    st_write(rmt_nfd, req_data->str, req_data->len, ST_UTIME_NO_TIMEOUT);

    http_request_free(&req);
    g_string_free(req_data, TRUE);

    http_response resp;
    httpclient_parser clp;

    http_response_parser_init(&resp, &clp);
    do {
      httpclient_parser_init(&clp);
      ssize_t nr = st_read(rmt_nfd, &buf[bpos], blen-bpos, ST_UTIME_NO_TIMEOUT);

      //buf[bpos + nr - 1] = 0;
      printf("nr: %zd\n", nr);
      size_t pe = httpclient_parser_execute(&clp, buf, bpos+nr, 0);
      printf("pe: %zu\n", pe);
      if (httpclient_parser_has_error(&clp)) {
        perror("parser error");
        goto done;
      }
      if (!httpclient_parser_is_finished(&clp)) {
        blen += (4 * 1024);
        buf = g_realloc(buf, blen);
        bpos += nr;
        printf("bpos: %zu\n", bpos);
        http_response_clear(&resp);
      }

      if (blen > (4 * 1024 * 1024)) {
        // too big
        goto done;
      }
    } while (!httpclient_parser_is_finished(&clp));

    printf("body_length: %zu\n", resp.body_length);
    GString *resp_data = http_response_data(&resp);
    printf("resp: %s\n", resp_data->str);
    g_string_free(resp_data, TRUE);

    const gchar *transfer_encoding = http_response_header_getstr(&resp, "Transfer-Encoding");
    const gchar *content_length = http_response_header_getstr(&resp, "Content-Length");
    size_t content_size = 0;
    if (content_length) { content_size = strtoull(content_length, NULL, 0); }
    printf("transfer_encoding: %s\n", transfer_encoding);
    if (g_strcmp0("chunked", transfer_encoding) == 0) {
      memmove(buf, resp.body, resp.body_length);
      bpos = resp.body_length;

parser_init:
      http_response_clear(&resp);
      httpclient_parser_init(&clp);
      httpclient_parser_execute(&clp, buf, bpos, 0);
      printf("\n=====\n");
      printf("nread: %zu\n", clp.nread);
      printf("chunk_size: %zu\n", resp.chunk_size);
      printf("last_chunk: %d\n", resp.last_chunk);
      printf("error?: %d\n", httpclient_parser_has_error(&clp));
      printf("finished?: %d\n", httpclient_parser_is_finished(&clp));
      if (resp.last_chunk || httpclient_parser_has_error(&clp)) {
        goto done;
      }
      // consume(body, min(resp.chunk_size, resp.body_length));
      if (bpos >= resp.chunk_size+2) {
        bpos = bpos-resp.chunk_size-2;
        memmove(buf, &resp.body[resp.chunk_size+2], bpos);
        goto parser_init;
      }

      size_t total_read = bpos - (clp.nread-1);
      while (total_read < resp.chunk_size+2) { // +2 for crlf
        size_t nr = st_read(rmt_nfd, buf, blen, ST_UTIME_NO_TIMEOUT);
        // consume(buf, nr);
        total_read += nr;
        bpos = nr;
      }

      if (total_read > resp.chunk_size+2) {
        // number of bytes in the buffer that are past this chunk
        size_t extra = (total_read - resp.chunk_size) - 2;
        memmove(buf, &buf[bpos - extra], extra);
        bpos = extra;
        goto parser_init;
      }

      if (resp.chunk_size) {
        size_t nr = st_read(rmt_nfd, buf, blen, ST_UTIME_NO_TIMEOUT);
        bpos = nr;
        goto parser_init;
      }
    } else {
      size_t total_read = resp.body_length;
      for (;;) {
        ssize_t nr = st_read(rmt_nfd, buf, blen, ST_UTIME_NO_TIMEOUT);
        if (nr <= 0) break;
        total_read += nr;
        printf("read %zu bytes, %zu/%zu\n", nr, total_read, content_size);
        if (content_size && total_read >= content_size) break;
      }
    }
    break;
  }

done:

  g_free(buf);
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


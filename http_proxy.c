#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "http_stream.h"

#define SEC2USEC(s) ((s)*1000000LL)

void *handle_connection(void *arg) {
  st_netfd_t client_nfd = (st_netfd_t)arg;
  struct http_stream *s = http_stream_create(HTTP_SERVER, SEC2USEC(10));
  char buf[4*1024];
  for (;;) {
    if (http_stream_read_request(s, client_nfd) < 0) break;
    struct http_stream *cs = http_stream_create(HTTP_CLIENT, SEC2USEC(10));
    http_request_debug_print(&s->req);

    fprintf(stderr, "request uri: %s\n", s->req.uri);
    const char *error_at = NULL;
    uri u;
    uri_init(&u);
    if (uri_parse(&u, s->req.uri, strlen(s->req.uri), &error_at) == 0) {
      fprintf(stderr, "uri_parse error: %s\n", error_at);
      goto release;
    }
    uri_normalize(&u);
    if (!http_stream_connect(cs, u.host, u.port)) goto release;
    if (!http_stream_request(cs, s->req.method, &u, 0)) goto release;

    size_t total = 0;
    for (;;) {
      ssize_t nr = http_stream_read(s, buf, sizeof(buf));
      fprintf(stderr, "http_stream_read nr: %zd\n", nr);
      if (nr <= 0) break;
      /*fwrite(buf, sizeof(char), nr, stdout);*/
      ssize_t nw = st_write(s->nfd, buf, nr, s->timeout);
      total += nr;
    }
    fprintf(stderr, "http_stream_read total: %zu\n", total);

    /* TODO: properly create a new response and copy headers */
    s->resp = cs->resp;
    http_response_header_remove(&s->resp, "Content-Length");
    http_response_header_remove(&s->resp, "Transfer-Encoding");
    http_response_header_append(&s->resp, "Transfer-Encoding", "chunked");
    ssize_t nw = http_stream_response_send(s, 0);
    memset(&s->resp, 0, sizeof(http_response));
    fprintf(stderr, "http_stream_response_send: %zd\n", nw);

    total = 0;
    for (;;) {
      ssize_t nr = http_stream_read(cs, buf, sizeof(buf));
      fprintf(stderr, "http_stream_read nr: %zd\n", nr);
      if (nr <= 0) break;
      /*fwrite(buf, sizeof(char), nr, stdout);*/
      total += nr;
      ssize_t nw = http_stream_send_chunk(s, buf, nr);
      printf("chunk nr: %zd chunk nw: %zd\n", nr, nw);
      if (nw <= 0 || nw < nr) break;
    }
    http_stream_send_chunk_end(s);
    fprintf(stderr, "written to client: %zu\n", total);
release:
    http_response_free(&s->resp);
    uri_free(&u);
    http_stream_close(cs);
    /* TODO: break loop if HTTP/1.0 and not keep-alive */
  }
  fprintf(stderr, "exiting handle_connection\n");
  http_stream_close(s);
  return NULL;
}

int main(int argc, char *argv[]) {
  st_init();

  int sock;
  int n;
  struct sockaddr_in serv_addr;

  if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket");
  }

  n = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&n, sizeof(n)) < 0) {
    perror("setsockopt SO_REUSEADDR");
  }

  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(8080);
  serv_addr.sin_addr.s_addr = inet_addr("0.0.0.0");

  if (bind(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    perror("bind");
  }

  if (listen(sock, 10) < 0) {
    perror("listen");
  }

  st_netfd_t server_nfd = st_netfd_open_socket(sock);
  st_netfd_t client_nfd;
  struct sockaddr_in from;
  int fromlen = sizeof(from);

  for (;;) {
    client_nfd = st_accept(server_nfd,
      (struct sockaddr *)&from, &fromlen, ST_UTIME_NO_TIMEOUT);
    printf("accepted\n");
    if (st_thread_create(handle_connection,
      (void *)client_nfd, 0, 1024 * 1024) == NULL)
    {
      fprintf(stderr, "st_thread_create error\n");
    }
  }

  return EXIT_SUCCESS;
}
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
  struct http_stream *s = http_stream_create(HTTP_SERVER, SEC2USEC(30));
  char buf[4*1024];
  int error = 0;
  for (;;) {
    if (http_stream_request_read(s, client_nfd) < 0) break;
    struct http_stream *cs = http_stream_create(HTTP_CLIENT, SEC2USEC(30));
    //http_request_debug_print(&s->req);

    fprintf(stderr, "request uri: %s\n", s->req.uri);
    const char *error_at = NULL;
    uri u;
    uri_init(&u);
    if (uri_parse(&u, s->req.uri, strlen(s->req.uri), &error_at) == 0) {
      fprintf(stderr, "uri_parse error: %s\n", error_at);
      goto release;
    }
    uri_normalize(&u);
    if (!http_stream_connect(cs, u.host, u.port)) { error = 1; goto release; }
    http_request_header_remove(&s->req, "Accept-Encoding");
    http_request_header_remove(&s->req, "Proxy-Connection");
    cs->req = s->req;
    char *request_uri = uri_compose_partial(&u);
    cs->req.uri = request_uri;
    if (!http_stream_request_send(cs)) { error = 1; goto release; }
    memset(&cs->req, 0, sizeof(http_request));
    free(request_uri);

    size_t total = 0;
    for (;;) {
      ssize_t nr = http_stream_read(s, buf, sizeof(buf));
      fprintf(stderr, "http_stream_read nr: %zd\n", nr);
      if (nr <= 0) break;
      /*fwrite(buf, sizeof(char), nr, stdout);*/
      ssize_t nw = st_write(cs->nfd, buf, nr, s->timeout);
      if (nw != nr) { error=1; goto release; }
      fprintf(stderr, "st_write nw: %zd\n", nr);
      total += nr;
    }
    fprintf(stderr, "http_stream_read total: %zu\n", total);

    if (!http_stream_response_read(cs)) { error=1; goto release; }

    /* TODO: properly create a new response and copy headers */
    s->resp = cs->resp;
    s->resp.http_version = "HTTP/1.1";
    http_response_header_remove(&s->resp, "Content-Length");
    http_response_header_remove(&s->resp, "Transfer-Encoding");
    if (s->resp.status_code != 204)
        http_response_header_append(&s->resp, "Transfer-Encoding", "chunked");
    ssize_t nw = http_stream_response_send(s, 0);
    memset(&s->resp, 0, sizeof(http_response));
    fprintf(stderr, "http_stream_response_send: %zd\n", nw);
    if (s->resp.status_code != 204) {
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
      fprintf(stderr, "written to client: %zu\n", total);
      if (total > 0) {
        http_stream_send_chunk_end(s);
      } else {
        fprintf(stderr, "for request: %s\n", s->req.uri);
      }
    }
release:
    http_response_free(&s->resp);
    http_request_clear(&s->req);
    uri_free(&u);
    http_stream_close(cs);
    /* TODO: break loop if HTTP/1.0 and not keep-alive */
    if (error) {
      fprintf(stderr, "ERROR, exiting\n");
      break;
    }
  }
  fprintf(stderr, "exiting handle_connection\n");
  http_stream_close(s);
  return NULL;
}

int main(int argc, char *argv[]) {

  g_assert(st_set_eventsys(ST_EVENTSYS_ALT) == 0);
  st_init();
  int status = ares_library_init(ARES_LIB_INIT_ALL);
  if (status != ARES_SUCCESS)
  {
    fprintf(stderr, "ares_library_init: %s\n", ares_strerror(status));
    return 1;
  }

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
  ares_library_cleanup();
  return EXIT_SUCCESS;
}

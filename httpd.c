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
    if (http_stream_request_read(s, client_nfd) < 0) break;
    http_request_debug_print(s->req, stderr);
    size_t total = 0;
    for (;;) {
      ssize_t nr = sizeof(buf);
      int status = http_stream_read(s, buf, &nr);
      fprintf(stderr, "http_stream_read nr: %zd\n", nr);
      if (status != HTTP_STREAM_OK) break;
      /*fwrite(buf, sizeof(char), nr, stdout);*/
      total += nr;
    }
    fprintf(stderr, "http_stream_read total: %zu\n", total);

    http_response_init_200_OK(&s->resp);
    http_response_header_append(&s->resp, "Content-type", "text/html");
    /*http_response_header_append(&s->resp, "Connection", "close");*/
    http_response_set_body(&s->resp, "<H2>It worked!</H2>");
    ssize_t nw = http_stream_response_send(s, 1);
    fprintf(stderr, "http_stream_response_send: %zd\n", nw);
    http_response_free(&s->resp);
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

#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "st.h"
#include "http_message.h"

#define SEC2USEC(s) ((s)*1000000LL)

void *handle_connection(void *arg) {
  st_netfd_t client_nfd = (st_netfd_t)arg;
  size_t bufsize = 2 * 1024 * 1024;
  char *buf = g_malloc(bufsize);
  char *mark = buf;
  http_request req;
  http_parser parser;
  http_request_parser_init(&req, &parser);
  for (;;) {
    http_parser_init(&parser);
    memset(buf, 0, bufsize);
    size_t rb = bufsize;
    while (!http_parser_is_finished(&parser) &&
      !http_parser_has_error(&parser) &&
      mark < buf+bufsize)
    {
      ssize_t nr = st_read(client_nfd, mark, rb, SEC2USEC(10));
      if (nr <= 0) {
        perror("st_read");
        goto cleanup;
      }
      rb -= nr;
      mark += nr;
      http_parser_execute(&parser, buf, mark-buf, mark-buf - nr);
    }

    if (http_parser_is_finished(&parser) &&
      !http_parser_has_error(&parser))
    {
      http_request_debug_print(&req);
      printf("\n");
      http_request_fwrite(&req, stdout);

      if (http_request_header_getstr(&req, "EXPECT")) {
        size_t content_length = http_request_header_getull(&req, "CONTENT_LENGTH");
        http_response resp;
        http_response_init(&resp, "100", "Continue");
        printf("sending 100-continue\n");
        GString *resp_data = http_response_data(&resp);
        printf("resp data: %s", resp_data->str);
        st_write(client_nfd, resp_data->str, resp_data->len, ST_UTIME_NO_TIMEOUT);
        http_response_free(&resp);
        g_string_free(resp_data, TRUE);
        size_t nb = 0;
        while (nb < content_length) {
          ssize_t nr = st_read(client_nfd, buf, rb, SEC2USEC(10));
          printf("got %zd bytes %zd total\n", nr, nr + nb);
          if (nr <= 0) break;
          nb += nr;
        }
      }
      http_response resp;
      http_response_init_200_OK(&resp);
      http_response_header_append(&resp, "Content-type", "text/html");
      http_response_header_append(&resp, "Connection", "close");
      http_response_set_body(&resp, "<H2>It worked!</H2>");
      GString *resp_data = http_response_data(&resp);
      st_write(client_nfd, resp_data->str, resp_data->len, ST_UTIME_NO_TIMEOUT);
      if (resp.body_length) {
        st_write(client_nfd, resp.body, resp.body_length, ST_UTIME_NO_TIMEOUT);
      }
      http_response_free(&resp);
    }
    http_request_clear(&req);
  }
cleanup:
  http_request_free(&req);
  st_netfd_close(client_nfd);
  g_free(buf);
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

#include <glib.h>
#include <string.h>
#include "http_message.h"

static void test_http_request_init(void) {
  http_request req;
  http_request_init(&req);
  g_assert(req.body == NULL);
  http_request_free(&req);
}

static void test_http_request_parser_init(void) {
  http_request req;
  http_parser parser;
  http_request_parser_init(&req, &parser);
  http_parser_init(&parser);
  g_assert(req.body == NULL);
  g_assert(parser.data == &req);
  http_request_free(&req);
}

static void test_http_request_parser_p0(void) {
  http_request req;
  http_parser parser;
  http_request_parser_init(&req, &parser);
  static const char *sdata =
  "GET /test/this?thing=1&stuff=2&fun&good HTTP/1.1\r\n"
  "User-Agent: curl/7.21.0 (i686-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18\r\n"
  "Host: localhost:8080\r\n"
  "Accept: */*\r\n\r\n";
  http_parser_init(&parser);
  char *data = g_strdup(sdata);
  char *p = data;
  while (!http_parser_is_finished(&parser) &&
    !http_parser_has_error(&parser) &&
    *p != 0)
  {
    p += 1; /* feed parser 1 byte at a time */
    http_parser_execute(&parser, data, p-data, p-data-1);
  }
  g_assert(!http_parser_has_error(&parser));
  g_assert(http_parser_is_finished(&parser));
  g_assert(g_strcmp0(req.method, "GET") == 0);
  g_assert(g_strcmp0(req.uri, "/test/this?thing=1&stuff=2&fun&good") == 0);
  g_assert(g_strcmp0(req.path, "/test/this") == 0);
  g_assert(g_strcmp0(req.query_string, "thing=1&stuff=2&fun&good") == 0);
  g_assert(g_strcmp0(req.http_version, "HTTP/1.1") == 0);
  g_assert(g_strcmp0(req.body, NULL) == 0);
  g_assert(req.body_length == 0);

  g_assert(g_strcmp0(g_datalist_get_data(&req.headers, "USER_AGENT"),
    "curl/7.21.0 (i686-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18") == 0);
  g_assert(g_strcmp0(g_datalist_get_data(&req.headers, "HOST"), "localhost:8080") == 0);
  g_assert(g_strcmp0(g_datalist_get_data(&req.headers, "ACCEPT"), "*/*") == 0);

  http_request_free(&req);
  g_free(data);
}

int main(int argc, char *argv[]) {
  g_test_init(&argc, &argv, NULL);
  g_test_add_func("/http/request/init", test_http_request_init);
  g_test_add_func("/http/request/parser/init", test_http_request_parser_init);
  g_test_add_func("/http/request/parser/p0", test_http_request_parser_p0);
  return g_test_run();
}

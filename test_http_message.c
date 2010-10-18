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

static void test_http_request_parser_normalize_header_names(void) {
  http_request req;
  http_parser parser;
  http_request_parser_init(&req, &parser);
  static const char *sdata =
  "GET /test/this?thing=1&stuff=2&fun&good HTTP/1.1\r\n"
  "usER-agEnT: curl/7.21.0 (i686-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18\r\n"
  "host: localhost:8080\r\n"
  "ACCEPT: */*\r\n\r\n";
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

  g_assert(g_strcmp0(http_request_get_header(&req, "User-Agent"),
    "curl/7.21.0 (i686-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18") == 0);
  g_assert(g_strcmp0(http_request_get_header(&req, "Host"), "localhost:8080") == 0);
  g_assert(g_strcmp0(http_request_get_header(&req, "Accept"), "*/*") == 0);

  http_request_free(&req);
  g_free(data);
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

  g_assert(g_strcmp0(http_request_get_header(&req, "User-Agent"),
    "curl/7.21.0 (i686-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18") == 0);
  g_assert(g_strcmp0(http_request_get_header(&req, "Host"), "localhost:8080") == 0);
  g_assert(g_strcmp0(http_request_get_header(&req, "Accept"), "*/*") == 0);

  http_request_free(&req);
  g_free(data);
}

static void test_http_request_parser_p1(void) {
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
  /* parse all in one go */
  http_parser_execute(&parser, data, strlen(data), 0);
  g_assert(!http_parser_has_error(&parser));
  g_assert(http_parser_is_finished(&parser));
  g_assert(g_strcmp0(req.method, "GET") == 0);
  g_assert(g_strcmp0(req.uri, "/test/this?thing=1&stuff=2&fun&good") == 0);
  g_assert(g_strcmp0(req.path, "/test/this") == 0);
  g_assert(g_strcmp0(req.query_string, "thing=1&stuff=2&fun&good") == 0);
  g_assert(g_strcmp0(req.http_version, "HTTP/1.1") == 0);
  g_assert(g_strcmp0(req.body, NULL) == 0);
  g_assert(req.body_length == 0);

  g_assert(g_strcmp0(http_request_get_header(&req, "User-Agent"),
    "curl/7.21.0 (i686-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18") == 0);
  g_assert(g_strcmp0(http_request_get_header(&req, "Host"), "localhost:8080") == 0);
  g_assert(g_strcmp0(http_request_get_header(&req, "Accept"), "*/*") == 0);

  http_request_free(&req);
  g_free(data);
}

static void test_http_request_parser_p2(void) {
  http_request req;
  http_parser parser;
  http_request_parser_init(&req, &parser);
  static const char *sdata = "GET /test/this?thing=1&stuff=2&fun&good HTTP/1.1\r\n";
  http_parser_init(&parser);
  char *data = g_strdup(sdata);
  http_parser_execute(&parser, data, strlen(data), 0);
  g_assert(!http_parser_has_error(&parser));
  g_assert(!http_parser_is_finished(&parser));
  g_assert(g_strcmp0(req.method, "GET") == 0);
  g_assert(g_strcmp0(req.uri, "/test/this?thing=1&stuff=2&fun&good") == 0);
  g_assert(g_strcmp0(req.path, "/test/this") == 0);
  g_assert(g_strcmp0(req.query_string, "thing=1&stuff=2&fun&good") == 0);
  g_assert(g_strcmp0(req.http_version, "HTTP/1.1") == 0);
  g_assert(g_strcmp0(req.body, NULL) == 0);
  g_assert(req.body_length == 0);

  http_request_free(&req);
  g_free(data);
}

static void test_http_request_parser_p3(void) {
  http_request req;
  http_parser parser;
  http_request_parser_init(&req, &parser);
  static const char *sdata = "\x01\xff 83949475dsf--==\x45 dsfsdfds";
  http_parser_init(&parser);
  char *data = g_strdup(sdata);
  http_parser_execute(&parser, data, strlen(data), 0);
  g_assert(http_parser_has_error(&parser));
  g_assert(!http_parser_is_finished(&parser));

  http_request_free(&req);
  g_free(data);
}

static void test_http_request_parser_proxy_http12(void) {
  http_request req;
  http_parser parser;
  http_request_parser_init(&req, &parser);
  static const char *sdata =
  "GET http://example.com:9182/test/this?thing=1&stuff=2&fun&good HTTP/1.1\r\n"
  "User-Agent: curl/7.21.0 (i686-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18\r\n"
  "Host: localhost:8080\r\n"
  "Accept: */*\r\n\r\n";
  http_parser_init(&parser);
  char *data = g_strdup(sdata);
  /* parse all in one go */
  http_parser_execute(&parser, data, strlen(data), 0);
  g_assert(!http_parser_has_error(&parser));
  g_assert(http_parser_is_finished(&parser));
  g_assert(g_strcmp0(req.method, "GET") == 0);
  g_assert(g_strcmp0(req.uri, "http://example.com:9182/test/this?thing=1&stuff=2&fun&good") == 0);
  /* path is NULL when fully qualified uri is used */
  /* TODO: maybe add support for full uri parsing */
  g_assert(req.path == NULL);
  g_assert(req.query_string == NULL);
  g_assert(g_strcmp0(req.http_version, "HTTP/1.1") == 0);
  g_assert(g_strcmp0(req.body, NULL) == 0);
  g_assert(req.body_length == 0);

  g_assert(g_strcmp0(http_request_get_header(&req, "User-Agent"),
    "curl/7.21.0 (i686-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18") == 0);
  g_assert(g_strcmp0(http_request_get_header(&req, "Host"), "localhost:8080") == 0);
  g_assert(g_strcmp0(http_request_get_header(&req, "Accept"), "*/*") == 0);

  http_request_free(&req);
  g_free(data);
}

static void test_http_request_clear(void) {
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
  /* parse all in one go */
  http_parser_execute(&parser, data, strlen(data), 0);
  g_assert(!http_parser_has_error(&parser));
  g_assert(http_parser_is_finished(&parser));
  g_assert(g_strcmp0(req.method, "GET") == 0);
  g_assert(g_strcmp0(req.uri, "/test/this?thing=1&stuff=2&fun&good") == 0);
  g_assert(g_strcmp0(req.path, "/test/this") == 0);
  g_assert(g_strcmp0(req.query_string, "thing=1&stuff=2&fun&good") == 0);
  g_assert(g_strcmp0(req.http_version, "HTTP/1.1") == 0);
  g_assert(g_strcmp0(req.body, NULL) == 0);
  g_assert(req.body_length == 0);

  g_assert(g_strcmp0(http_request_get_header(&req, "User-Agent"),
    "curl/7.21.0 (i686-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18") == 0);
  g_assert(g_strcmp0(http_request_get_header(&req, "Host"), "localhost:8080") == 0);
  g_assert(g_strcmp0(http_request_get_header(&req, "Accept"), "*/*") == 0);

  /* clear this request */
  http_request_clear(&req);

  g_assert(req.method == 0);
  g_assert(req.uri == 0);
  g_assert(req.path == 0);
  g_assert(req.query_string == 0);
  g_assert(req.http_version == 0);
  g_assert(req.body == 0);
  g_assert(req.body_length == 0);

  http_parser_init(&parser);
  http_parser_execute(&parser, data, strlen(data), 0);
  g_assert(!http_parser_has_error(&parser));
  g_assert(http_parser_is_finished(&parser));
  g_assert(g_strcmp0(req.method, "GET") == 0);
  g_assert(g_strcmp0(req.uri, "/test/this?thing=1&stuff=2&fun&good") == 0);
  g_assert(g_strcmp0(req.path, "/test/this") == 0);
  g_assert(g_strcmp0(req.query_string, "thing=1&stuff=2&fun&good") == 0);
  g_assert(g_strcmp0(req.http_version, "HTTP/1.1") == 0);
  g_assert(g_strcmp0(req.body, NULL) == 0);
  g_assert(req.body_length == 0);

  g_assert(g_strcmp0(http_request_get_header(&req, "User-Agent"),
    "curl/7.21.0 (i686-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18") == 0);
  g_assert(g_strcmp0(http_request_get_header(&req, "Host"), "localhost:8080") == 0);
  g_assert(g_strcmp0(http_request_get_header(&req, "Accept"), "*/*") == 0);

  http_request_free(&req);
  g_free(data);
}

static void test_http_response_init(void) {
  http_response resp;
  http_response_init(&resp, "200", "OK");
  g_assert(g_strcmp0("200", resp.status_code) == 0);
  g_assert(g_strcmp0("OK", resp.reason) == 0);
  g_assert(g_strcmp0("HTTP/1.1", resp.http_version) == 0);
  g_assert(resp.body == NULL);
  http_response_free(&resp);
}

static void test_http_response_init_200_OK(void) {
  http_response resp;
  http_response_init_200_OK(&resp);
  g_assert(g_strcmp0("200", resp.status_code) == 0);
  g_assert(g_strcmp0("OK", resp.reason) == 0);
  g_assert(g_strcmp0("HTTP/1.1", resp.http_version) == 0);
  g_assert(resp.body == NULL);
  http_response_free(&resp);
}

static void test_http_response_data(void) {
  http_response resp;
  http_response_init_200_OK(&resp);
  http_response_set_header(&resp, "Host", "localhost");
  http_response_set_header(&resp, "Content-Length", "0");
  g_assert(g_strcmp0("200", resp.status_code) == 0);
  g_assert(g_strcmp0("OK", resp.reason) == 0);
  g_assert(g_strcmp0("HTTP/1.1", resp.http_version) == 0);
  g_assert(resp.body == NULL);
  g_assert(g_strcmp0("0", http_response_get_header(&resp, "Content-Length")) == 0);
  GString *s = http_response_data(&resp);
  static const char *expected_data =
  "HTTP/1.1 200 OK\r\n"
  "Host: localhost\r\n"
  "Content-Length: 0\r\n"
  "\r\n";
  g_assert(g_strcmp0(expected_data, s->str) == 0);
  g_string_free(s, TRUE);
  http_response_free(&resp);
}

static void test_http_response_body(void) {
  http_response resp;
  http_response_init_200_OK(&resp);
  http_response_set_header(&resp, "Host", "localhost");
  http_response_set_header(&resp, "Content-Type", "text/plain");
  static const char *body = "this is a test.\r\nthis is only a test.";
  char numstr[32];
  snprintf(numstr, sizeof(numstr), "%zu", strlen(body));
  http_response_set_body(&resp, body);
  g_assert(g_strcmp0("200", resp.status_code) == 0);
  g_assert(g_strcmp0("OK", resp.reason) == 0);
  g_assert(g_strcmp0("HTTP/1.1", resp.http_version) == 0);
  g_assert(g_strcmp0(body, resp.body) == 0);
  g_assert(g_strcmp0("text/plain", http_response_get_header(&resp, "Content-Type")) == 0);
  g_assert(g_strcmp0("37", http_response_get_header(&resp, "Content-Length")) == 0);
  GString *s = http_response_data(&resp);
  static const char *expected_data =
  "HTTP/1.1 200 OK\r\n"
  "Host: localhost\r\n"
  "Content-Type: text/plain\r\n"
  "Content-Length: 37\r\n"
  "\r\n";
  g_assert(g_strcmp0(expected_data, s->str) == 0);

  g_string_free(s, TRUE);
  http_response_free(&resp);
}

static void test_http_response_parser_init(void) {
  http_response resp;
  httpclient_parser parser;
  http_response_parser_init(&resp, &parser);
  httpclient_parser_init(&parser);
  g_assert(resp.body == NULL);
  g_assert(parser.data == &resp);
  http_response_free(&resp);
}

static void test_http_response_parser_normalize_header_names(void) {
  http_response resp;
  httpclient_parser parser;
  http_response_parser_init(&resp, &parser);
  httpclient_parser_init(&parser);
  static const char *sdata =
  "HTTP/1.1 200 OK\r\n"
  "cOnTent-leNgtH: 37\r\n"
  "ConteNt-tYpE: text/plain\r\n"
  "HOST: localhost\r\n\r\n"
  "this is a test.\r\nthis is only a test.";
  char *data = g_strdup(sdata);
  char *p = data;
  while (!httpclient_parser_is_finished(&parser) &&
    !httpclient_parser_has_error(&parser) &&
    *p != 0)
  {
    p += 1; /* feed parser 1 byte at a time */
    httpclient_parser_execute(&parser, data, p-data, p-data-1);
  }
  g_assert(!httpclient_parser_has_error(&parser));
  g_assert(httpclient_parser_is_finished(&parser));

  g_assert(g_strcmp0("HTTP/1.1", resp.http_version) == 0);
  g_assert(g_strcmp0("200", resp.status_code) == 0);
  g_assert(g_strcmp0("OK", resp.reason) == 0);
  g_assert(g_strcmp0("this is a test.\r\nthis is only a test.", resp.body) == 0);
  g_assert(g_strcmp0("37", http_response_get_header(&resp, "Content-Length")) == 0);
  g_assert(g_strcmp0("text/plain", http_response_get_header(&resp, "Content-Type")) == 0);
  http_response_free(&resp);
  g_free(data);
}

static void test_http_response_parser_p0(void) {
  http_response resp;
  httpclient_parser parser;
  http_response_parser_init(&resp, &parser);
  httpclient_parser_init(&parser);
  static const char *sdata =
  "HTTP/1.1 200 OK\r\n"
  "Content-Length: 37\r\n"
  "Content-Type: text/plain\r\n"
  "Host: localhost\r\n\r\n"
  "this is a test.\r\nthis is only a test.";
  char *data = g_strdup(sdata);
  char *p = data;
  while (!httpclient_parser_is_finished(&parser) &&
    !httpclient_parser_has_error(&parser) &&
    *p != 0)
  {
    p += 1; /* feed parser 1 byte at a time */
    httpclient_parser_execute(&parser, data, p-data, p-data-1);
  }
  g_assert(!httpclient_parser_has_error(&parser));
  g_assert(httpclient_parser_is_finished(&parser));

  g_assert(g_strcmp0("HTTP/1.1", resp.http_version) == 0);
  g_assert(g_strcmp0("200", resp.status_code) == 0);
  g_assert(g_strcmp0("OK", resp.reason) == 0);
  g_assert(g_strcmp0("this is a test.\r\nthis is only a test.", resp.body) == 0);
  g_assert(g_strcmp0("37", http_response_get_header(&resp, "Content-Length")) == 0);
  g_assert(g_strcmp0("text/plain", http_response_get_header(&resp, "Content-Type")) == 0);
  http_response_free(&resp);
  g_free(data);
}

static void test_http_response_parser_p1(void) {
  http_response resp;
  httpclient_parser parser;
  http_response_parser_init(&resp, &parser);
  httpclient_parser_init(&parser);
  static const char *sdata =
  "HTTP/1.1 200 OK\r\n"
  "Content-Length: 37\r\n"
  "Content-Type: text/plain\r\n"
  "Host: localhost\r\n\r\n"
  "this is a test.\r\nthis is only a test.";
  char *data = g_strdup(sdata);
  httpclient_parser_execute(&parser, data, strlen(data), 0);
  g_assert(!httpclient_parser_has_error(&parser));
  g_assert(httpclient_parser_is_finished(&parser));

  g_assert(g_strcmp0("this is a test.\r\nthis is only a test.", resp.body) == 0);
  g_assert(parser.data == &resp);

  g_assert(g_strcmp0("HTTP/1.1", resp.http_version) == 0);
  g_assert(g_strcmp0("200", resp.status_code) == 0);
  g_assert(g_strcmp0("OK", resp.reason) == 0);
  g_assert(g_strcmp0("37", http_response_get_header(&resp, "Content-Length")) == 0);
  g_assert(g_strcmp0("text/plain", http_response_get_header(&resp, "Content-Type")) == 0);

  http_response_free(&resp);
  g_free(data);
}

static void test_http_response_parser_chunked(void) {
  http_response resp;
  httpclient_parser parser;
  http_response_parser_init(&resp, &parser);
  httpclient_parser_init(&parser);
  /* borrowed from http://en.wikipedia.org/wiki/Chunked_transfer_encoding */
  static const char *sdata =
  "HTTP/1.1 200 OK\r\n"
  "Content-Type: text/plain\r\n"
  "Transfer-Encoding: chunked\r\n\r\n"
  "25\r\n"
  "This is the data in the first chunk\r\n"
  "1C\r\n"
  "and this is the second one\r\n"
  "3\r\n"
  "con"
  "8\r\n"
  "sequence"
  "0\r\n"
  "\r\n";
  char *data = g_strdup(sdata);
  httpclient_parser_execute(&parser, data, strlen(data), 0);
  g_assert(!httpclient_parser_has_error(&parser));
  g_assert(httpclient_parser_is_finished(&parser));

  g_assert(g_strcmp0("HTTP/1.1", resp.http_version) == 0);
  g_assert(g_strcmp0("200", resp.status_code) == 0);
  g_assert(g_strcmp0("OK", resp.reason) == 0);
  g_assert(g_strcmp0("text/plain", http_response_get_header(&resp, "Content-Type")) == 0);
  g_assert(g_strcmp0("chunked", http_response_get_header(&resp, "Transfer-Encoding")) == 0);

  /* reset the parse for the chunked part */
  httpclient_parser_init(&parser);
  httpclient_parser_execute(&parser, resp.body, strlen(resp.body), 0);
  g_assert(!httpclient_parser_has_error(&parser));
  g_assert(httpclient_parser_is_finished(&parser));
  g_assert(resp.chunk_size == 37);
  g_assert(resp.last_chunk == FALSE);

  httpclient_parser_init(&parser);
  httpclient_parser_execute(&parser, resp.body+37, strlen(resp.body+37), 0);
  g_assert(!httpclient_parser_has_error(&parser));
  g_assert(httpclient_parser_is_finished(&parser));
  g_assert(resp.chunk_size == 28);
  g_assert(resp.last_chunk == FALSE);

  httpclient_parser_init(&parser);
  httpclient_parser_execute(&parser, resp.body+28, strlen(resp.body)+28, 0);
  g_assert(!httpclient_parser_has_error(&parser));
  g_assert(httpclient_parser_is_finished(&parser));
  g_assert(resp.chunk_size == 3);
  g_assert(resp.last_chunk == FALSE);

  httpclient_parser_init(&parser);
  httpclient_parser_execute(&parser, resp.body+3, strlen(resp.body+3), 0);
  g_assert(!httpclient_parser_has_error(&parser));
  g_assert(httpclient_parser_is_finished(&parser));
  g_assert(resp.chunk_size == 8);
  g_assert(resp.last_chunk == FALSE);

  httpclient_parser_init(&parser);
  httpclient_parser_execute(&parser, resp.body+8, strlen(resp.body+8), 0);
  g_assert(!httpclient_parser_has_error(&parser));
  g_assert(httpclient_parser_is_finished(&parser));
  g_assert(resp.chunk_size == 0);
  g_assert(resp.last_chunk == FALSE);

  httpclient_parser_init(&parser);
  httpclient_parser_execute(&parser, resp.body+0, strlen(resp.body+0), 0);
  g_assert(!httpclient_parser_has_error(&parser));
  g_assert(httpclient_parser_is_finished(&parser));
  g_assert(resp.chunk_size == 0);
  g_assert(resp.last_chunk == TRUE);

  http_response_free(&resp);
  g_free(data);
}

int main(int argc, char *argv[]) {
  g_test_init(&argc, &argv, NULL);
  g_test_add_func("/http/request/init", test_http_request_init);
  g_test_add_func("/http/request/parser/init", test_http_request_parser_init);
  g_test_add_func("/http/request/parser/normalize_header_names", test_http_request_parser_normalize_header_names);
  g_test_add_func("/http/request/parser/p0", test_http_request_parser_p0);
  g_test_add_func("/http/request/parser/p1", test_http_request_parser_p1);
  g_test_add_func("/http/request/parser/p2", test_http_request_parser_p2);
  g_test_add_func("/http/request/parser/p3", test_http_request_parser_p3);
  g_test_add_func("/http/request/parser/proxy_http12", test_http_request_parser_proxy_http12);
  g_test_add_func("/http/request/clear", test_http_request_clear);

  g_test_add_func("/http/response/init", test_http_response_init);
  g_test_add_func("/http/response/init_200_OK", test_http_response_init_200_OK);
  g_test_add_func("/http/response/data", test_http_response_data);
  g_test_add_func("/http/response/body", test_http_response_body);
  g_test_add_func("/http/response/parser/init", test_http_response_parser_init);
  g_test_add_func("/http/response/parser/normalize_header_names", test_http_response_parser_normalize_header_names);
  g_test_add_func("/http/response/parser/p0", test_http_response_parser_p0);
  g_test_add_func("/http/response/parser/p1", test_http_response_parser_p1);
  g_test_add_func("/http/response/parser/chunked", test_http_response_parser_chunked);
  return g_test_run();
}

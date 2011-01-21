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

static void test_http_request_make1(void) {
  http_request req;
  http_request_make(&req, "GET", "/test/this?thing=1&stuff=2&fun&good");
  http_request_header_append(&req, "user-agent",
    "curl/7.21.0 (i686-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18");
  http_request_header_append(&req, "host", "localhost:8080");
  http_request_header_append(&req, "accept", "*/*");
  static const char *sdata =
  "GET /test/this?thing=1&stuff=2&fun&good HTTP/1.1\r\n"
  "User-Agent: curl/7.21.0 (i686-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18\r\n"
  "Host: localhost:8080\r\n"
  "Accept: */*\r\n"
  "\r\n";
  GString *s = http_request_data(&req);
  g_assert(g_strcmp0(sdata, s->str) == 0);
  g_string_free(s, TRUE);
  http_request_free(&req);
}

static void test_http_request_make_parse(void) {
  http_request req;
  http_request_make(&req, "GET", "/test/this?thing=1&stuff=2&fun&good");
  http_request_header_append(&req, "user-agent",
    "curl/7.21.0 (i686-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18");
  http_request_header_append(&req, "host", "localhost:8080");
  http_request_header_append(&req, "accept", "*/*");
  GString *s = http_request_data(&req);

  http_request req2;
  http_parser parser;
  http_request_parser_init(&req2, &parser);
  http_parser_init(&parser);
  http_parser_execute(&parser, s->str, s->len, 0);
  g_assert(!http_parser_has_error(&parser));
  g_assert(http_parser_is_finished(&parser));

  g_string_free(s, TRUE);

  http_request_free(&req2);
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

  g_assert(g_strcmp0(http_request_header_getstr(&req, "User-Agent"),
    "curl/7.21.0 (i686-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18") == 0);
  g_assert(g_strcmp0(http_request_header_getstr(&req, "Host"), "localhost:8080") == 0);
  g_assert(g_strcmp0(http_request_header_getstr(&req, "Accept"), "*/*") == 0);

  http_request_free(&req);
  g_free(data);
}

static void test_http_request_parser_unicode_escape(void) {
  http_request req;
  http_parser parser;
  http_request_parser_init(&req, &parser);
  static const char *sdata =
  "GET http://b.scorecardresearch.com/b?C1=8&C2=6035047&C3=463.9924&C4=ad21868c&C5=173229&C6=16jfaue1ukmeoq&C7=http%3A//remotecontrol.mtv.com/2011/01/20/sammi-sweetheart-giancoloa-terrell-owens-hair/&C8=Hot%20Shots%3A%20Sammi%20%u2018Sweetheart%u2019%20Lets%20Terrell%20Owens%20Play%20With%20Her%20Hair%20%BB%20MTV%20Remote%20Control%20Blog&C9=&C10=1680x1050&rn=58013009 HTTP/1.1\r\n"
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
#if 0
  g_assert(g_strcmp0(req.uri, "/test/this?thing=1&stuff=2&fun&good") == 0);
  g_assert(g_strcmp0(req.path, "/test/this") == 0);
  g_assert(g_strcmp0(req.query_string, "thing=1&stuff=2&fun&good") == 0);
#endif
  g_assert(g_strcmp0(req.http_version, "HTTP/1.1") == 0);
  g_assert(g_strcmp0(req.body, NULL) == 0);
  g_assert(req.body_length == 0);

  g_assert(g_strcmp0(http_request_header_getstr(&req, "User-Agent"),
    "curl/7.21.0 (i686-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18") == 0);
  g_assert(g_strcmp0(http_request_header_getstr(&req, "Host"), "localhost:8080") == 0);
  g_assert(g_strcmp0(http_request_header_getstr(&req, "Accept"), "*/*") == 0);

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

  g_assert(g_strcmp0(http_request_header_getstr(&req, "User-Agent"),
    "curl/7.21.0 (i686-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18") == 0);
  g_assert(g_strcmp0(http_request_header_getstr(&req, "Host"), "localhost:8080") == 0);
  g_assert(g_strcmp0(http_request_header_getstr(&req, "Accept"), "*/*") == 0);

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

  g_assert(g_strcmp0(http_request_header_getstr(&req, "User-Agent"),
    "curl/7.21.0 (i686-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18") == 0);
  g_assert(g_strcmp0(http_request_header_getstr(&req, "Host"), "localhost:8080") == 0);
  g_assert(g_strcmp0(http_request_header_getstr(&req, "Accept"), "*/*") == 0);

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

  g_assert(g_strcmp0(http_request_header_getstr(&req, "User-Agent"),
    "curl/7.21.0 (i686-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18") == 0);
  g_assert(g_strcmp0(http_request_header_getstr(&req, "Host"), "localhost:8080") == 0);
  g_assert(g_strcmp0(http_request_header_getstr(&req, "Accept"), "*/*") == 0);

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

  g_assert(g_strcmp0(http_request_header_getstr(&req, "User-Agent"),
    "curl/7.21.0 (i686-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18") == 0);
  g_assert(g_strcmp0(http_request_header_getstr(&req, "Host"), "localhost:8080") == 0);
  g_assert(g_strcmp0(http_request_header_getstr(&req, "Accept"), "*/*") == 0);

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

  g_assert(g_strcmp0(http_request_header_getstr(&req, "User-Agent"),
    "curl/7.21.0 (i686-pc-linux-gnu) libcurl/7.21.0 OpenSSL/0.9.8o zlib/1.2.3.4 libidn/1.18") == 0);
  g_assert(g_strcmp0(http_request_header_getstr(&req, "Host"), "localhost:8080") == 0);
  g_assert(g_strcmp0(http_request_header_getstr(&req, "Accept"), "*/*") == 0);

  http_request_free(&req);
  g_free(data);
}

static void test_http_request_headers(void) {
  http_request req;
  http_request_init(&req);
  http_request_header_append(&req, "test-a", "test-a");
  http_request_header_append(&req, "test-b", "test-b");
  http_request_header_append(&req, "test-c", "test-c");
  http_request_header_append(&req, "test-a", "test-a");
  g_assert(g_strcmp0("test-a", http_request_header_getstr(&req, "test-a")));
  g_assert(g_strcmp0("test-b", http_request_header_getstr(&req, "test-b")));
  g_assert(g_strcmp0("test-c", http_request_header_getstr(&req, "test-c")));
  g_assert(http_request_header_remove(&req, "Test-A"));
  g_assert(http_request_header_remove(&req, "Test-B"));
  g_assert(http_request_header_remove(&req, "Test-C"));
  g_assert(http_request_header_remove(&req, "Test-A") == FALSE);
  http_request_free(&req);
}

/* http response */

static void test_http_response_init(void) {
  http_response resp;
  http_response_init(&resp, 200, "OK");
  g_assert(resp.status_code == 200);
  g_assert(g_strcmp0("OK", resp.reason) == 0);
  g_assert(g_strcmp0("HTTP/1.1", resp.http_version) == 0);
  g_assert(resp.body == NULL);
  http_response_free(&resp);
}

static void test_http_response_init_200_OK(void) {
  http_response resp;
  http_response_init_200_OK(&resp);
  g_assert(resp.status_code == 200);
  g_assert(g_strcmp0("OK", resp.reason) == 0);
  g_assert(g_strcmp0("HTTP/1.1", resp.http_version) == 0);
  g_assert(resp.body == NULL);
  http_response_free(&resp);
}

static void test_http_response_data(void) {
  http_response resp;
  http_response_init_200_OK(&resp);
  http_response_header_append(&resp, "Host", "localhost");
  http_response_header_append(&resp, "Content-Length", "0");
  g_assert(resp.status_code == 200);
  g_assert(g_strcmp0("OK", resp.reason) == 0);
  g_assert(g_strcmp0("HTTP/1.1", resp.http_version) == 0);
  g_assert(resp.body == NULL);
  g_assert(g_strcmp0("0", http_response_header_getstr(&resp, "Content-Length")) == 0);
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
  http_response_header_append(&resp, "Host", "localhost");
  http_response_header_append(&resp, "Content-Type", "text/plain");
  static const char *body = "this is a test.\r\nthis is only a test.";
  char numstr[32];
  snprintf(numstr, sizeof(numstr), "%zu", strlen(body));
  http_response_set_body(&resp, body);
  g_assert(resp.status_code == 200);
  g_assert(g_strcmp0("OK", resp.reason) == 0);
  g_assert(g_strcmp0("HTTP/1.1", resp.http_version) == 0);
  g_assert(g_strcmp0(body, resp.body) == 0);
  g_assert(g_strcmp0("text/plain", http_response_header_getstr(&resp, "Content-Type")) == 0);
  g_assert(g_strcmp0("37", http_response_header_getstr(&resp, "Content-Length")) == 0);
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
  g_assert(resp.status_code == 200);
  g_assert(g_strcmp0("OK", resp.reason) == 0);
  g_assert(g_strcmp0("this is a test.\r\nthis is only a test.", resp.body) == 0);
  g_assert(g_strcmp0("37", http_response_header_getstr(&resp, "Content-Length")) == 0);
  g_assert(g_strcmp0("text/plain", http_response_header_getstr(&resp, "Content-Type")) == 0);
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
  g_assert(resp.status_code == 200);
  g_assert(g_strcmp0("OK", resp.reason) == 0);
  g_assert(g_strcmp0("this is a test.\r\nthis is only a test.", resp.body) == 0);
  g_assert(g_strcmp0("37", http_response_header_getstr(&resp, "Content-Length")) == 0);
  g_assert(g_strcmp0("text/plain", http_response_header_getstr(&resp, "Content-Type")) == 0);
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
  g_assert(resp.status_code == 200);
  g_assert(g_strcmp0("OK", resp.reason) == 0);
  g_assert(g_strcmp0("37", http_response_header_getstr(&resp, "Content-Length")) == 0);
  g_assert(g_strcmp0("text/plain", http_response_header_getstr(&resp, "Content-Type")) == 0);

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
  "This is the data in the first chunk\r\n\r\n"
  "1C\r\n"
  "and this is the second one\r\n\r\n"
  "3\r\n"
  "con\r\n"
  "8\r\n"
  "sequence\r\n"
  "0\r\n"
  "\r\n";
  char *data = g_strdup(sdata);
  httpclient_parser_execute(&parser, data, strlen(data), 0);
  g_assert(!httpclient_parser_has_error(&parser));
  g_assert(httpclient_parser_is_finished(&parser));

  g_assert(g_strcmp0("HTTP/1.1", resp.http_version) == 0);
  g_assert(resp.status_code == 200);
  g_assert(g_strcmp0("OK", resp.reason) == 0);
  g_assert(g_strcmp0("text/plain", http_response_header_getstr(&resp, "Content-Type")) == 0);
  g_assert(g_strcmp0("chunked", http_response_header_getstr(&resp, "Transfer-Encoding")) == 0);

  /* reset the parse for the chunked part */
  httpclient_parser_init(&parser);
  httpclient_parser_execute(&parser, resp.body, strlen(resp.body), 0);
  g_assert(!httpclient_parser_has_error(&parser));
  g_assert(httpclient_parser_is_finished(&parser));
  g_assert(resp.chunk_size == 37);
  g_assert(resp.last_chunk == FALSE);

  const gchar *mark = resp.body+resp.chunk_size+2; // 2 for terminating crlf
  httpclient_parser_init(&parser);
  httpclient_parser_execute(&parser, mark, strlen(mark), 0);
  g_assert(!httpclient_parser_has_error(&parser));
  g_assert(httpclient_parser_is_finished(&parser));
  g_assert(resp.chunk_size == 28);
  g_assert(resp.last_chunk == FALSE);

  mark = resp.body+resp.chunk_size+2;
  httpclient_parser_init(&parser);
  httpclient_parser_execute(&parser, mark, strlen(mark), 0);
  g_assert(!httpclient_parser_has_error(&parser));
  g_assert(httpclient_parser_is_finished(&parser));
  g_assert(resp.chunk_size == 3);
  g_assert(resp.last_chunk == FALSE);

  mark = resp.body+resp.chunk_size+2;
  httpclient_parser_init(&parser);
  httpclient_parser_execute(&parser, mark, strlen(mark), 0);
  g_assert(!httpclient_parser_has_error(&parser));
  g_assert(httpclient_parser_is_finished(&parser));
  g_assert(resp.chunk_size == 8);
  g_assert(resp.last_chunk == FALSE);

  mark = resp.body+resp.chunk_size+2;
  httpclient_parser_init(&parser);
  httpclient_parser_execute(&parser, mark, strlen(mark), 0);
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
  g_test_add_func("/http/request/make1", test_http_request_make1);
  g_test_add_func("/http/request/make_parse", test_http_request_make_parse);
  g_test_add_func("/http/request/parser/init", test_http_request_parser_init);
  g_test_add_func("/http/request/parser/normalize_header_names", test_http_request_parser_normalize_header_names);
  g_test_add_func("/http/request/parser/unicode_escape", test_http_request_parser_unicode_escape);
  g_test_add_func("/http/request/parser/p0", test_http_request_parser_p0);
  g_test_add_func("/http/request/parser/p1", test_http_request_parser_p1);
  g_test_add_func("/http/request/parser/p2", test_http_request_parser_p2);
  g_test_add_func("/http/request/parser/p3", test_http_request_parser_p3);
  g_test_add_func("/http/request/parser/proxy_http12", test_http_request_parser_proxy_http12);
  g_test_add_func("/http/request/headers", test_http_request_headers);
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

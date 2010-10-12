#include "http_message.h"
#include <string.h>

static void request_method(void *data, const char *at, size_t length) {
  http_request *msg = (http_request *)data;
  msg->method = g_string_chunk_insert_len(msg->chunk, at, length);
}

static void request_uri(void *data, const char *at, size_t length) {
  http_request *msg = (http_request *)data;
  msg->uri = g_string_chunk_insert_len(msg->chunk, at, length);
}

static void fragment(void *data, const char *at, size_t length) {
  http_request *msg = (http_request *)data;
  msg->fragment = g_string_chunk_insert_len(msg->chunk, at, length);
}

static void request_path(void *data, const char *at, size_t length) {
  http_request *msg = (http_request *)data;
  msg->path = g_string_chunk_insert_len(msg->chunk, at, length);
}

static void query_string(void *data, const char *at, size_t length) {
  http_request *msg = (http_request *)data;
  msg->query_string = g_string_chunk_insert_len(msg->chunk, at, length);
}

static void http_version(void *data, const char *at, size_t length) {
  http_request *req = (http_request *)data;
  req->http_version = g_string_chunk_insert_len(req->chunk, at, length);
}

static void header_done(void *data, const char *at, size_t length) {
  http_request *req = (http_request *)data;
  // set body
  if (length) {
    req->body = at;
    req->body_length = length;
  }
}

void http_request_set_header(http_request *req,
  const gchar *field, const gchar *value)
{
  const gchar *h = g_intern_string(field);
  gchar *v = g_string_chunk_insert(req->chunk, value);
  g_datalist_set_data(&req->headers, h, v);
}

static void http_field(void *data, const char *field,
  size_t flen, const char *value, size_t vlen)
{
  http_request *req = (http_request *)data;
  /* cast away const then temporarily NULL terminate */
  gchar *f = (gchar *)field;
  gchar *v = (gchar *)value;
  /* save character being replaced by NULL */
  gchar svf = f[flen];
  gchar vvf = v[vlen];
  f[flen] = 0;
  v[vlen] = 0;
  http_request_set_header(req, field, value);
  /* restore saved character */
  f[flen] = svf;
  v[vlen] = vvf;
}

void http_request_init(http_request *req) {
  req->chunk = g_string_chunk_new(1024 * 1024);
  http_request_clear(req);
  g_datalist_init(&req->headers);
}

void http_request_parser_init(http_request *req, http_parser *p) {
  http_request_init(req);
  p->data = req;
  p->http_field = http_field;
  p->request_method = request_method;
  p->request_uri = request_uri;
  p->fragment = fragment;
  p->request_path = request_path;
  p->query_string = query_string;
  p->http_version = http_version;
  p->header_done = header_done;
}

void http_request_clear(http_request *req) {
  req->method = NULL;
  req->uri = NULL;
  req->fragment = NULL;
  req->path = NULL;
  req->query_string = NULL;
  req->http_version = NULL;
  req->body = NULL;
  req->body_length = 0;
  g_datalist_clear(&req->headers);
  g_string_chunk_clear(req->chunk);
}

static void http_request_print_headers(GQuark key_id, gpointer data, gpointer user_data) {
  (void)user_data;
  printf(" %s : %s\n", g_quark_to_string(key_id), (const gchar *)data);
}

void http_request_print(http_request *req) {
  printf("method: %s\n", req->method);
  printf("uri: %s\n", req->uri);
  printf("fragment: %s\n", req->fragment);
  printf("path: %s\n", req->path);
  printf("query: %s\n", req->query_string);
  printf("http version: %s\n", req->http_version);
  printf("headers:\n");
  g_datalist_foreach(&req->headers, http_request_print_headers, NULL);
  printf("length: %zu\n", req->body_length);
  printf("body: %s\n", req->body);
}

/*
 * turn http11 formatted header field names into valid http header fields.
 * returns newly allocated string.
 */
static gchar *http_format_field_name(const gchar *infield) {
  gchar *field = g_strdup(infield);
  int first_letter = 1;
  for (gchar *p = field; *p != 0; p++) {
    if (!first_letter) {
      *p = g_ascii_tolower(*p);
      if (*p == '_') {
        *p = '-';
        first_letter = 1;
      } else if (*p == '-') {
        first_letter = 1;
      }
    } else {
      first_letter = 0;
    }
  }
  return field;
}

static void http_request_write_headers(GQuark key_id, gpointer data, gpointer user_data) {
  FILE *f = (FILE *)user_data;
  gchar *field = http_format_field_name(g_quark_to_string(key_id));
  fprintf(f, "%s: %s\r\n", field, (const gchar *)data);
  g_free(field);
}

void http_request_fwrite(http_request *req, FILE *f) {
  fprintf(f, "%s %s %s\r\n", req->http_version, req->method, req->uri);
  g_datalist_foreach(&req->headers, http_request_write_headers, f);
  fprintf(f, "\r\n");
}

void http_response_init(http_response *resp) {
  resp->chunk = g_string_chunk_new(1024 * 1024);
  g_datalist_init(&resp->headers);
  resp->http_version = g_string_chunk_insert(resp->chunk, "HTTP/1.1");
  resp->status_code = g_string_chunk_insert(resp->chunk, "200");
  resp->reason = g_string_chunk_insert(resp->chunk, "OK");
  resp->body = NULL;
  resp->body_length = 0;
}

void http_response_set_header(http_response *resp,
  const gchar *field, const gchar *value)
{
  const gchar *h = g_intern_string(field);
  gchar *v = g_string_chunk_insert(resp->chunk, value);
  g_datalist_set_data(&resp->headers, h, v);
}

void http_response_set_body(http_response *resp, const gchar *body) {
  gchar lenstr[32];
  resp->body = body;
  resp->body_length = strlen(body);
  g_snprintf(lenstr, sizeof(lenstr)-1, "%zu", resp->body_length);
  http_response_set_header(resp, "Content-Length", lenstr);
}

static void http_response_data_headers(GQuark key_id, gpointer data, gpointer user_data) {
  GString *s = (GString *)user_data;
  gchar *field = http_format_field_name(g_quark_to_string(key_id));
  g_string_append_printf(s, "%s: %s\r\n", field, (const gchar *)data);
  g_free(field);
}

GString *http_response_data(http_response *resp) {
  GString *s = g_string_sized_new(1024);
  g_string_printf(s, "%s %s %s\r\n", resp->http_version,
    resp->status_code, resp->reason);
  // TODO: maybe add required headers like content-length
  g_datalist_foreach(&resp->headers, http_response_data_headers, s);
  g_string_append_printf(s, "\r\n");
  return s;
}

void http_response_free(http_response *resp) {
  g_datalist_clear(&resp->headers);
  g_string_chunk_free(resp->chunk);
}

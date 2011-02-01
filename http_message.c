#include "http_message.h"
#include <string.h>
#include <stdlib.h>

struct message_header_s {
  gchar *name;
  gchar *value;
};
typedef struct message_header_s message_header_t;

/* TODO 
 * - add function to serialize to iovec for speedy writes
 * - http://www.jmarshall.com/easy/http/
 */

/*
 * normalize http11 message header field names.
 */
static gchar *normalize_header_name(gchar *field) {
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
      *p = g_ascii_toupper(*p);
      first_letter = 0;
    }
  }
  return field;
}

static gint header_name_compare(gconstpointer a, gconstpointer b) {
  const message_header_t *am = (message_header_t *)a;
  const gchar *field = (const gchar *)b;
  return g_strcmp0(field, am->name);
}

void http_header_append(GQueue *headers,
  GStringChunk *chunk,
  const gchar *field, const gchar *value)
{
  message_header_t *hdr = g_slice_new(message_header_t);
  hdr->name = g_string_chunk_insert(chunk, field);
  normalize_header_name(hdr->name);
  hdr->value = g_string_chunk_insert(chunk, value);
  g_queue_push_tail(headers, hdr);
}

gboolean http_header_remove(GQueue *headers,
  const gchar *field)
{
  GList *l = g_queue_find_custom(headers, field, header_name_compare);
  gboolean found = FALSE;
  while (l) {
    g_slice_free(message_header_t, l->data);
    g_queue_delete_link(headers, l);
    found = TRUE;
    l = g_queue_find_custom(headers, field, header_name_compare);
  }
  return found;
}

const gchar *http_header_getstr(GQueue *headers,
  const gchar *field)
{
  GList *l = g_queue_find_custom(headers, field, header_name_compare);
  if (l) {
    return ((message_header_t *)l->data)->value;
  }
  return NULL;
}

unsigned long long http_header_getull(GQueue *headers,
  const gchar *field)
{
  return strtoull(
    http_header_getstr(headers, field), NULL, 0);
}

static void request_method(void *data, const char *at, size_t length) {
  http_request_t *msg = (http_request_t *)data;
  msg->method = g_string_chunk_insert_len(msg->chunk, at, length);
}

static void request_uri(void *data, const char *at, size_t length) {
  http_request_t *msg = (http_request_t *)data;
  msg->uri = g_string_chunk_insert_len(msg->chunk, at, length);
}

static void fragment(void *data, const char *at, size_t length) {
  http_request_t *msg = (http_request_t *)data;
  msg->fragment = g_string_chunk_insert_len(msg->chunk, at, length);
}

static void request_path(void *data, const char *at, size_t length) {
  http_request_t *msg = (http_request_t *)data;
  msg->path = g_string_chunk_insert_len(msg->chunk, at, length);
}

static void query_string(void *data, const char *at, size_t length) {
  http_request_t *msg = (http_request_t *)data;
  msg->query_string = g_string_chunk_insert_len(msg->chunk, at, length);
}

static void http_version(void *data, const char *at, size_t length) {
  http_request_t *req = (http_request_t *)data;
  req->http_version = g_string_chunk_insert_len(req->chunk, at, length);
}

static void header_done(void *data, const char *at, size_t length) {
  http_request_t *req = (http_request_t *)data;
  /* set body */
  /* TODO: not sure this logic is right. length might be wrong */
  if (length) {
    req->body = at;
    req->body_length = length;
  }
}

static void http_field(void *data, const char *field,
  size_t flen, const char *value, size_t vlen)
{
  http_request_t *req = (http_request_t *)data;
  /* cast away const then temporarily NULL terminate */
  gchar *f = (gchar *)field;
  gchar *v = (gchar *)value;
  /* save character being replaced by NULL */
  gchar svf = f[flen];
  gchar vvf = v[vlen];
  f[flen] = 0;
  v[vlen] = 0;
  http_request_header_append(req, field, value);
  /* restore saved character */
  f[flen] = svf;
  v[vlen] = vvf;
}

#if 0
void http_request_init(http_request_t *req) {
  req->chunk = g_string_chunk_new(1024 * 4);
  req->headers = NULL;
  http_request_clear(req);
  req->headers = g_queue_new();
}
#endif

http_request_t *http_request_new(void) {
  http_request_t *req = g_slice_new0(http_request_t);
  req->chunk = g_string_chunk_new(1024 * 4);
  req->headers = g_queue_new();
  return req;
}

static void free_message_headers(gpointer data, gpointer user_data) {
  (void)user_data;
  g_slice_free(message_header_t, data);
}

void http_request_free(http_request_t *req) {
  g_queue_foreach(req->headers, free_message_headers, NULL);
  g_queue_free(req->headers);
  g_string_chunk_free(req->chunk);
  g_slice_free(http_request_t, req);
}

void http_request_clear(http_request_t *req) {
  req->method = NULL;
  req->uri = NULL;
  req->fragment = NULL;
  req->path = NULL;
  req->query_string = NULL;
  req->http_version = NULL;
  req->body = NULL;
  req->body_length = 0;
  if (req->headers) {
    g_queue_foreach(req->headers, free_message_headers, NULL);
    g_queue_clear(req->headers);
  }
  g_string_chunk_clear(req->chunk);
}

void http_request_parser_init(http_request_t *req, http_parser *p) {
#if 0
  http_request_init(req);
#endif
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

void http_request_make(http_request_t *req,
  const gchar *method, const gchar *uri)
{
#if 0
  http_request_init(req);
#endif
  req->method = g_string_chunk_insert(req->chunk, method);
  req->uri = g_string_chunk_insert(req->chunk, uri);
  req->http_version = g_string_chunk_insert(req->chunk, "HTTP/1.1");
}

static void http_request_write_headers(gpointer data, gpointer user_data) {
  FILE *f = (FILE *)user_data;
  message_header_t *hdr = (message_header_t *)data;
  fprintf(f, "%s: %s\r\n", hdr->name, hdr->value);
}

void http_request_debug_print(http_request_t *req, FILE *f) {
  fprintf(f, "method: %s\n", req->method);
  fprintf(f, "uri: %s\n", req->uri);
  fprintf(f, "fragment: %s\n", req->fragment);
  fprintf(f, "path: %s\n", req->path);
  fprintf(f, "query: %s\n", req->query_string);
  fprintf(f, "http version: %s\n", req->http_version);
  fprintf(f, "headers:\n");
  g_queue_foreach(req->headers, http_request_write_headers, f);
  fprintf(f, "length: %zu\n", req->body_length);
  fprintf(f, "body: %s\n", req->body);
}

void http_request_fwrite(http_request_t *req, FILE *f) {
  fprintf(f, "%s %s %s\r\n", req->method, req->uri, req->http_version);
  g_queue_foreach(req->headers, http_request_write_headers, f);
  fprintf(f, "\r\n");
}

static void message_headers_to_data(gpointer data, gpointer user_data) {
  GString *s = (GString *)user_data;
  message_header_t *hdr = (message_header_t *)data;
  g_string_append_printf(s, "%s: %s\r\n", hdr->name, hdr->value);
}

GString *http_request_data(http_request_t *req) {
  GString *s = g_string_sized_new(1024 * 4);
  g_string_printf(s, "%s %s %s\r\n", req->method,
    req->uri, req->http_version);
  g_queue_foreach(req->headers, message_headers_to_data, s);
  g_string_append_printf(s, "\r\n");
  return s;
}

/* http_response */

static void http_field_cl(void *data, const char *field,
  size_t flen, const char *value, size_t vlen)
{
  http_response *resp = (http_response *)data;
  /* cast away const then temporarily NULL terminate */
  gchar *f = (gchar *)field;
  gchar *v = (gchar *)value;
  /* save character being replaced by NULL */
  gchar svf = f[flen];
  gchar vvf = v[vlen];
  f[flen] = 0;
  v[vlen] = 0;
  /* TODO: need to normalize header. for example, convert to all caps */
  http_response_header_append(resp, field, value);
  /* restore saved character */
  f[flen] = svf;
  v[vlen] = vvf;
}

static void reason_phrase_cl(void *data, const char *at, size_t length) {
  http_response *resp = (http_response *)data;
  resp->reason = g_string_chunk_insert_len(resp->chunk, at, length);
}

static void status_code_cl(void *data, const char *at, size_t length) {
  http_response *resp = (http_response *)data;
  char s = at[length];
  ((char *)at)[length] = 0;
  resp->status_code = strtoul(at, NULL, 0);
  ((char *)at)[length] = s;
}

static void chunk_size_cl(void *data, const char *at, size_t length) {
  http_response *resp = (http_response *)data;
  const gchar *chunk_size = g_string_chunk_insert_len(resp->chunk, at, length);
  resp->chunk_size = strtoull(chunk_size, NULL, 16);
}

static void http_version_cl(void *data, const char *at, size_t length) {
  http_response *resp = (http_response *)data;
  resp->http_version = g_string_chunk_insert_len(resp->chunk, at, length);
}

static void header_done_cl(void *data, const char *at, size_t length) {
  http_response *resp = (http_response *)data;
  /* set body */
  /* TODO: the length is not right here */
  /* printf("HEADER DONE: %zu [%s]\n", length, at); */
  if (at || length) {
    resp->body = at;
    resp->body_length = length;
  }
}

static void last_chunk_cl(void *data, const char *at, size_t length) {
  (void)at;
  (void)length;
  http_response *resp = (http_response *)data;
  resp->last_chunk = TRUE;
}

void http_response_init_200_OK(http_response *resp) {
  http_response_init(resp, 200, "OK");
}

void http_response_init(http_response *resp, unsigned long code, const gchar *reason) {
  resp->chunk = g_string_chunk_new(1024 * 4);
  resp->headers = g_queue_new();
  resp->http_version = g_string_chunk_insert(resp->chunk, "HTTP/1.1");
  resp->status_code = code;
  resp->reason = g_string_chunk_insert(resp->chunk, reason);
  resp->body = NULL;
  resp->body_length = 0;
  resp->chunk_size = 0;
  resp->last_chunk = FALSE;
}

void http_response_parser_init(http_response *resp, httpclient_parser *p) {
  resp->chunk = g_string_chunk_new(1024 * 4);
  resp->headers = g_queue_new();
  resp->http_version = NULL;
  resp->status_code = 0;
  resp->reason = NULL;
  resp->body = NULL;
  resp->body_length = 0;
  resp->chunk_size = 0;
  resp->last_chunk = FALSE;
  p->data = resp;
  p->http_field = http_field_cl;
  p->reason_phrase = reason_phrase_cl;
  p->status_code = status_code_cl;
  p->chunk_size = chunk_size_cl;
  p->http_version = http_version_cl;
  p->header_done = header_done_cl;
  p->last_chunk = last_chunk_cl;
}

void http_response_set_body(http_response *resp, const gchar *body) {
  gchar lenstr[32];
  resp->body = body;
  resp->body_length = strlen(body);
  g_snprintf(lenstr, sizeof(lenstr)-1, "%zu", resp->body_length);
  /* TODO: remove header first */
  http_response_header_append(resp, "Content-Length", lenstr);
}

GString *http_response_data(http_response *resp) {
  GString *s = g_string_sized_new(1024);
  g_string_printf(s, "%s %lu %s\r\n", resp->http_version,
    resp->status_code, resp->reason);
  /* TODO: maybe add required headers like content-length */
  g_queue_foreach(resp->headers, message_headers_to_data, s);
  g_string_append_printf(s, "\r\n");
  return s;
}

void http_response_clear(http_response *resp) {
  resp->http_version = NULL;
  resp->status_code = 0;
  resp->reason = NULL;
  resp->body = NULL;
  resp->body_length = 0;
  resp->chunk_size = 0;
  resp->last_chunk = 0;

  if (resp->headers) {
    g_queue_foreach(resp->headers, free_message_headers, NULL);
    g_queue_clear(resp->headers);
  }
  g_string_chunk_clear(resp->chunk);
}

void http_response_free(http_response *resp) {
  if (resp->headers) {
    g_queue_foreach(resp->headers, free_message_headers, NULL);
    g_queue_free(resp->headers);
  }
  if (resp->chunk) { g_string_chunk_free(resp->chunk); }
  resp->headers = 0;
  resp->chunk = 0;
}

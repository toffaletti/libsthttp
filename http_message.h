#include <stdio.h>
#include <glib.h>
#include "http11/http11_parser.h"
#include "http11_client/http11_parser.h"

struct http_request_s {
  GStringChunk *chunk; /* string pool */
  GQueue *headers;
  gchar *method;
  gchar *uri;
  gchar *fragment;
  gchar *path;
  gchar *query_string;
  gchar *http_version;
  const gchar *body;
  size_t body_length;
};
typedef struct http_request_s http_request_t;

struct http_response_s {
  GStringChunk *chunk; /* string pool */
  GQueue *headers;
  gchar *http_version;
  unsigned long status_code;
  gchar *reason;
  const gchar *body;
  size_t body_length;
  size_t chunk_size;
  int last_chunk;
};
typedef struct http_response_s http_response_t;

extern void http_header_append(GQueue *headers,
  GStringChunk *chunk,
  const gchar *field, const gchar *value);
extern gboolean http_header_remove(GQueue *headers,
  const gchar *field);
extern const gchar *http_header_getstr(GQueue *headers,
  const gchar *field);
extern unsigned long long http_header_getull(GQueue *headers,
  const gchar *field);

/* http_request_t */

extern http_request_t *http_request_new(void);
/* extern void http_request_init(http_request_t *req); */
extern void http_request_parser_init(http_request_t *req, http_parser *p);
extern void http_request_clear(http_request_t *req);
extern void http_request_debug_print(http_request_t *req, FILE *f);
extern void http_request_fwrite(http_request_t *req, FILE *f);
extern GString *http_request_data(http_request_t *req);

#define http_request_header_append(req, field, value) \
  http_header_append( \
    G_STRUCT_MEMBER(GQueue *, req, G_STRUCT_OFFSET(http_request_t, headers)), \
    G_STRUCT_MEMBER(GStringChunk *, req, G_STRUCT_OFFSET(http_request_t, chunk)), \
    field, value)

#define http_request_header_remove(req, field) \
  http_header_remove( \
    G_STRUCT_MEMBER(GQueue *, req, G_STRUCT_OFFSET(http_request_t, headers)), field)

#define http_request_header_getstr(req, field) \
  http_header_getstr( \
    G_STRUCT_MEMBER(GQueue *, req, G_STRUCT_OFFSET(http_request_t, headers)), field)

#define http_request_header_getull(req, field) \
  http_header_getull( \
    G_STRUCT_MEMBER(GQueue *, req, G_STRUCT_OFFSET(http_request_t, headers)), field)

extern void http_request_make(http_request_t *req,
  const gchar *method, const gchar *uri);
extern void http_request_free(http_request_t *req);

/* http_response */

#define http_response_header_append(resp, field, value) \
  http_header_append( \
    G_STRUCT_MEMBER(GQueue *, resp, G_STRUCT_OFFSET(http_response_t, headers)), \
    G_STRUCT_MEMBER(GStringChunk *, resp, G_STRUCT_OFFSET(http_response_t, chunk)), \
    field, value)

#define http_response_header_remove(resp, field) \
  http_header_remove( \
    G_STRUCT_MEMBER(GQueue *, resp, G_STRUCT_OFFSET(http_response_t, headers)), field)

#define http_response_header_getstr(resp, field) \
  http_header_getstr( \
    G_STRUCT_MEMBER(GQueue *, resp, G_STRUCT_OFFSET(http_response_t, headers)), field)

#define http_response_header_getull(resp, field) \
  http_header_getull( \
    G_STRUCT_MEMBER(GQueue *, resp, G_STRUCT_OFFSET(http_response_t, headers)), field)

extern http_response_t *http_response_new(unsigned long code, const gchar *reason);
extern void http_response_parser_init(http_response_t *resp, httpclient_parser *p);
extern GString *http_response_data(http_response_t *resp);
extern void http_response_set_body(http_response_t *resp, const gchar *body);
extern void http_response_clear(http_response_t *resp);
extern void http_response_free(http_response_t *resp);


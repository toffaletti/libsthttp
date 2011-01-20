#include <stdio.h>
#include <glib.h>
#include "http11/http11_parser.h"
#include "http11_client/http11_parser.h"

typedef struct http_request {
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
} http_request;

typedef struct http_response {
  GStringChunk *chunk; /* string pool */
  GQueue *headers;
  gchar *http_version;
  unsigned long status_code;
  gchar *reason;
  const gchar *body;
  size_t body_length;
  size_t chunk_size;
  int last_chunk;
} http_response;

extern void http_header_append(GQueue *headers,
  GStringChunk *chunk,
  const gchar *field, const gchar *value);
extern gboolean http_header_remove(GQueue *headers,
  const gchar *field);
extern const gchar *http_header_getstr(GQueue *headers,
  const gchar *field);
extern unsigned long long http_header_getull(GQueue *headers,
  const gchar *field);

/* http_request */

extern void http_request_init(http_request *req);
extern void http_request_parser_init(http_request *req, http_parser *p);
extern void http_request_clear(http_request *req);
extern void http_request_debug_print(http_request *req);
extern void http_request_fwrite(http_request *req, FILE *f);
extern GString *http_request_data(http_request *req);

#define http_request_header_append(req, field, value) \
  http_header_append( \
    G_STRUCT_MEMBER(GQueue *, req, G_STRUCT_OFFSET(http_request, headers)), \
    G_STRUCT_MEMBER(GStringChunk *, req, G_STRUCT_OFFSET(http_request, chunk)), \
    field, value)

#define http_request_header_remove(req, field) \
  http_header_remove( \
    G_STRUCT_MEMBER(GQueue *, req, G_STRUCT_OFFSET(http_request, headers)), field)

#define http_request_header_getstr(req, field) \
  http_header_getstr( \
    G_STRUCT_MEMBER(GQueue *, req, G_STRUCT_OFFSET(http_request, headers)), field)

#define http_request_header_getull(req, field) \
  http_header_getull( \
    G_STRUCT_MEMBER(GQueue *, req, G_STRUCT_OFFSET(http_request, headers)), field)

extern void http_request_make(http_request *req,
  const gchar *method, const gchar *uri);
extern void http_request_free(http_request *req);

/* http_response */

#define http_response_header_append(resp, field, value) \
  http_header_append( \
    G_STRUCT_MEMBER(GQueue *, resp, G_STRUCT_OFFSET(http_response, headers)), \
    G_STRUCT_MEMBER(GStringChunk *, resp, G_STRUCT_OFFSET(http_response, chunk)), \
    field, value)

#define http_response_header_remove(resp, field) \
  http_header_remove( \
    G_STRUCT_MEMBER(GQueue *, resp, G_STRUCT_OFFSET(http_response, headers)), field)

#define http_response_header_getstr(resp, field) \
  http_header_getstr( \
    G_STRUCT_MEMBER(GQueue *, resp, G_STRUCT_OFFSET(http_response, headers)), field)

#define http_response_header_getull(resp, field) \
  http_header_getull( \
    G_STRUCT_MEMBER(GQueue *, resp, G_STRUCT_OFFSET(http_response, headers)), field)

extern void http_response_parser_init(http_response *resp, httpclient_parser *p);
extern void http_response_init_200_OK(http_response *resp);
extern void http_response_init(http_response *resp, unsigned long code, const gchar *reason);
extern GString *http_response_data(http_response *resp);
extern void http_response_set_body(http_response *resp, const gchar *body);
extern void http_response_clear(http_response *resp);
extern void http_response_free(http_response *resp);


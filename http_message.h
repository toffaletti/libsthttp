#include <stdio.h>
#include <glib.h>
#include "http11/http11_parser.h"

typedef struct http_request {
  GStringChunk *chunk; /* string pool */
  GData *headers;
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
  GData *headers;
  gchar *http_version;
  gchar *status_code;
  gchar *reason;
  const gchar *body;
  size_t body_length;
} http_response;

/* http_request */

extern void http_request_init(http_request *req);
extern void http_request_parser_init(http_request *req, http_parser *p);
extern void http_request_clear(http_request *req);
extern void http_request_print(http_request *req);
extern void http_request_fwrite(http_request *req, FILE *f);

extern void http_request_set_header(http_request *req,
  const gchar *field, const gchar *value);

extern void http_request_free(http_request *req);

/* http_response */

extern void http_response_init(http_response *resp);
extern GString *http_response_data(http_response *resp);
extern void http_response_set_header(http_response *resp,
  const gchar *field, const gchar *value);
extern void http_response_set_body(http_response *resp, const gchar *body);
extern void http_response_free(http_response *resp);

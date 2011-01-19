#include "st.h"
#include "st_dns.h"
#include "uri_parser.h"
#include "http_message.h"

/* transfer encoding */
enum {
    TE_NONE = 0,
    TE_CHUNKED
};

/* stream mode */
enum {
    HTTP_CLIENT,
    HTTP_SERVER
};

struct http_stream {
  const gchar *start;
  const gchar *end;

  gchar *buf;
  size_t blen;

  st_netfd_t nfd;

  ssize_t content_size;
  size_t total_read;
  size_t chunk_read;

  st_utime_t timeout;
  int transfer_encoding;
  int mode;

  union {
    http_parser server;
    httpclient_parser client;
  } parser;
  http_response resp;
  http_request req;
}; /* http_stream */


extern struct http_stream *http_stream_create(int mode, st_utime_t timeout);
extern int http_stream_connect(struct http_stream *s, const char *address, uint16_t port);
extern ssize_t http_stream_request_send(struct http_stream *s);
extern int http_stream_request(struct http_stream *s, const gchar *method, uri *u, int full_uri);
extern int http_stream_read_request(struct http_stream *s, st_netfd_t nfd);
extern ssize_t http_stream_response_send(struct http_stream *s, int body);
extern ssize_t http_stream_read(struct http_stream *s, void *ptr, size_t size);
extern ssize_t http_stream_send_chunk(struct http_stream *s, const char *buf, size_t size);
extern ssize_t http_stream_send_chunk_end(struct http_stream *s);
extern void http_stream_close(struct http_stream *s);

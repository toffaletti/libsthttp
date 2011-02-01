#include "st.h"
#include "st_dns.h"
#include "uri_parser.h"
#include "http_message.h"

/* transfer encoding */
enum transfer_encoding_e {
    TE_NONE = 0,
    TE_CHUNKED
};

/* stream mode */
enum http_stream_mode_e {
    HTTP_CLIENT,
    HTTP_SERVER
};

/* stream status codes */
enum http_stream_status_e {
    HTTP_STREAM_OK = 0,
    HTTP_STREAM_DNS_ERROR,
    HTTP_STREAM_SOCKET_ERROR,
    HTTP_STREAM_CONNECT_ERROR,
    HTTP_STREAM_WRITE_ERROR,
    HTTP_STREAM_READ_ERROR,
    HTTP_STREAM_PARSE_ERROR,
    HTTP_STREAM_CLOSED, /* read returned 0 */
    HTTP_STREAM_TIMEOUT,
    HTTP_STREAM_ERROR = -1
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
  enum transfer_encoding_e transfer_encoding;
  enum http_stream_mode_e mode;
  enum http_stream_status_e status;

  union {
    http_parser server;
    httpclient_parser client;
  } parser;
  http_response resp;
  http_request_t *req;
}; /* http_stream */


extern struct http_stream *http_stream_create(int mode, st_utime_t timeout);
extern int http_stream_connect(struct http_stream *s, const char *address, uint16_t port);
extern int http_stream_request_send(struct http_stream *s);
extern int http_stream_request_init(struct http_stream *s, const char *method, uri *u);
extern int http_stream_response_read(struct http_stream *s);
extern int http_stream_request_read(struct http_stream *s, st_netfd_t nfd);
extern int http_stream_response_send(struct http_stream *s, int body);
extern int http_stream_read(struct http_stream *s, void *ptr, ssize_t *size);
extern int http_stream_send_chunk(struct http_stream *s, const char *buf, size_t size);
extern int http_stream_send_chunk_end(struct http_stream *s);
extern void http_stream_close(struct http_stream *s);

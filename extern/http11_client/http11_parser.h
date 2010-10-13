/**
 * Copyright (c) 2005 Zed A. Shaw
 * You can redistribute it and/or modify it under the same terms as Ruby.
 */

#ifndef http11client_parser_h
#define http11client_parser_h

#include <sys/types.h>

#if defined(_WIN32)
#include <stddef.h>
#endif

typedef void (*cl_element_cb)(void *data, const char *at, size_t length);
typedef void (*cl_field_cb)(void *data, const char *field, size_t flen, const char *value, size_t vlen);

typedef struct httpclient_parser {
  int cs;
  size_t body_start;
  int content_len;
  size_t nread;
  size_t mark;
  size_t field_start;
  size_t field_len;

  void *data;

  cl_field_cb http_field;
  cl_element_cb reason_phrase;
  cl_element_cb status_code;
  cl_element_cb chunk_size;
  cl_element_cb http_version;
  cl_element_cb header_done;
  cl_element_cb last_chunk;

} httpclient_parser;

int httpclient_parser_init(httpclient_parser *parser);
int httpclient_parser_finish(httpclient_parser *parser);
size_t httpclient_parser_execute(httpclient_parser *parser, const char *data, size_t len, size_t off);
int httpclient_parser_has_error(httpclient_parser *parser);
int httpclient_parser_is_finished(httpclient_parser *parser);

#define httpclient_parser_nread(parser) (parser)->nread

#endif

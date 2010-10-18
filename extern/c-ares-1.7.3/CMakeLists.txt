cmake_minimum_required(VERSION 2.6)
project(c-ares)

add_definitions(
-DHAVE_CONFIG_H
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_library(cares STATIC
ares_cancel.c
ares__close_sockets.c
ares_data.c
ares_destroy.c
ares_expand_name.c
ares_expand_string.c
ares_fds.c
ares_free_hostent.c
ares_free_string.c
ares_gethostbyaddr.c
ares_gethostbyname.c
ares__get_hostent.c
ares_getnameinfo.c
ares_getopt.c
ares_getsock.c
ares_init.c
ares_library_init.c
ares_llist.c
ares_mkquery.c
ares_nowarn.c
ares_options.c
ares_parse_aaaa_reply.c
ares_parse_a_reply.c
ares_parse_mx_reply.c
ares_parse_ns_reply.c
ares_parse_ptr_reply.c
ares_parse_srv_reply.c
ares_parse_txt_reply.c
ares_process.c
ares_query.c
ares__read_line.c
ares_search.c
ares_send.c
ares_strcasecmp.c
ares_strdup.c
ares_strerror.c
ares_timeout.c
ares__timeval.c
ares_version.c
ares_writev.c
bitncmp.c
inet_net_pton.c
)
target_link_libraries(cares rt)

add_executable(ahost ahost.c)
target_link_libraries(ahost cares)

add_executable(adig adig.c)
target_link_libraries(adig cares)

add_executable(acountry acountry.c)
target_link_libraries(acountry cares)

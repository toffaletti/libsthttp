cmake_minimum_required(VERSION 2.6)
project(fw)

add_subdirectory(extern)

# st_dns and st_ssl extensions are now here
set(STX_DIR ${CMAKE_CURRENT_SOURCE_DIR}/extern/state-threads/extensions)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/extern)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/extern/libguri)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/extern/state-threads)
include_directories(${STX_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/extern/c-ares-1.7.4)
include_directories(/usr/include/glib-2.0/ /usr/lib/glib-2.0/include/)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread -std=gnu99 -g3 -ggdb -Wall -Wextra -pedantic")

add_executable(httpd httpd.c ${STX_DIR}/cares-st.c http_message.c http_stream.c)
target_link_libraries(httpd glib-2.0 st cares guri http11 http11client)
add_dependencies(httpd st cares guri http11 http11client)

add_executable(http_proxy http_proxy.c ${STX_DIR}/cares-st.c http_message.c http_stream.c)
target_link_libraries(http_proxy glib-2.0 st cares guri http11 http11client)
add_dependencies(http_proxy st cares guri http11 http11client)

add_executable(test-http-message test_http_message.c http_message.c)
target_link_libraries(test-http-message glib-2.0 http11 http11client)

#add_executable(adns-st adns-st.c)
#target_link_libraries(adns-st glib-2.0 st adns)

add_executable(fget fget.c ${STX_DIR}/cares-st.c http_message.c http_stream.c)
target_link_libraries(fget glib-2.0 st cares guri http11 http11client)
add_dependencies(fget st cares guri http11 http11client)

add_executable(app app.c)
target_link_libraries(app glib-2.0 st)
add_dependencies(app st)


cmake_minimum_required(VERSION 2.6)
project(fw)

add_subdirectory(extern)
add_subdirectory(uri)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/uri)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/extern)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/extern/state-threads)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/extern/c-ares-1.7.4)
include_directories(/usr/include/glib-2.0/ /usr/lib/glib-2.0/include/)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread -std=gnu99 -g3 -ggdb -Wall -Wextra -pedantic")
add_definitions(-D_GNU_SOURCE)

add_executable(httpd httpd.c cares-st.c http_message.c http_stream.c)
target_link_libraries(httpd glib-2.0 st cares uri http11 http11client)
add_dependencies(httpd st cares uri http11 http11client)

add_executable(http_proxy http_proxy.c cares-st.c http_message.c http_stream.c)
target_link_libraries(http_proxy glib-2.0 st cares uri http11 http11client)
add_dependencies(http_proxy st cares uri http11 http11client)

add_executable(test-http-message test_http_message.c http_message.c)
target_link_libraries(test-http-message glib-2.0 http11 http11client)

#add_executable(adns-st adns-st.c)
#target_link_libraries(adns-st glib-2.0 st adns)

add_executable(test-cares-st test-cares-st.c cares-st.c)
target_link_libraries(test-cares-st glib-2.0 st cares)

add_executable(fget fget.c cares-st.c http_message.c http_stream.c)
target_link_libraries(fget glib-2.0 st cares uri http11 http11client)
add_dependencies(fget st cares uri http11 http11client)

add_executable(app app.c)
target_link_libraries(app glib-2.0 st)
add_dependencies(app st)

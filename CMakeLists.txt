cmake_minimum_required(VERSION 2.6)
project(fw)

add_subdirectory(extern)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/extern)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/extern/st-1.9)
include_directories(/usr/include/glib-2.0/ /usr/lib/glib-2.0/include/)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread -std=gnu99 -g3 -ggdb -Wall -Wextra -pedantic")

add_executable(httpd httpd.c http_message.c)
target_link_libraries(httpd glib-2.0 st http11 http11client)

add_executable(test-http-message test_http_message.c http_message.c)
target_link_libraries(test-http-message glib-2.0 http11 http11client)

add_executable(adns-st adns-st.c)
target_link_libraries(adns-st glib-2.0 st adns)

add_executable(cares-st cares-st.c)
target_link_libraries(cares-st glib-2.0 st cares)


cmake_minimum_required(VERSION 2.8)
project(fw)

add_subdirectory(extern)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/extern)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/extern/st-1.9)
include_directories(/usr/include/glib-2.0/ /usr/lib/glib-2.0/include/)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread -std=gnu99 -g3 -ggdb -Wall -Wextra")

add_executable(httpd httpd.c http_message.c)
target_link_libraries(httpd glib-2.0 st http11)
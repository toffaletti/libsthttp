cmake_minimum_required(VERSION 2.6)
project(libsthttp)

add_subdirectory(http11)
add_subdirectory(http11_client)

# if these don't exist, we expect the user to provide them another way
if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/extern/libguri/CMakeLists.txt)
    add_subdirectory(extern/libguri)
endif (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/extern/libguri/CMakeLists.txt)
if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/extern/state-threads/CMakeLists.txt)
    add_subdirectory(extern/state-threads)
endif (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/extern/state-threads/CMakeLists.txt)

# st_dns and st_ssl extensions are now here
if (NOT STX_DIR)
    set(STX_DIR ${CMAKE_CURRENT_SOURCE_DIR}/extern/state-threads/extensions)
    message("STX_DIR not set, setting to ${STX_DIR}")
else (NOT STX_DIR)
    message("found STX_DIR set to ${STX_DIR}")
endif (NOT STX_DIR)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/extern)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/extern/libguri)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/extern/state-threads)
include_directories(${STX_DIR})
include_directories(/usr/include/glib-2.0/ /usr/lib/glib-2.0/include/)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread -std=gnu99 -g3 -ggdb -Wall -Wextra -pedantic")

add_library(sthttp ${STX_DIR}/cares-st.c http_message.c http_stream.c)
target_link_libraries(sthttp glib-2.0 st cares guri http11 http11client)

add_executable(httpd httpd.c)
target_link_libraries(httpd sthttp)
#add_dependencies(httpd st cares guri http11 http11client)

add_executable(http_proxy http_proxy.c)
target_link_libraries(http_proxy sthttp)
#add_dependencies(http_proxy st cares guri http11 http11client)

add_executable(test-http-message test_http_message.c)
target_link_libraries(test-http-message sthttp)

add_executable(fget fget.c)
target_link_libraries(fget sthttp)


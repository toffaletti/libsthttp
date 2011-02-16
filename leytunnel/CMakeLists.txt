cmake_minimum_required(VERSION 2.6)
project(leytunnel)

add_subdirectory(extern/state-threads)

# st_dns and st_ssl extensions are now here
set(STX_DIR ${CMAKE_CURRENT_SOURCE_DIR}/extern/state-threads/extensions)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/extern/state-threads)
include_directories(${STX_DIR})
include_directories(/usr/include/glib-2.0/ /usr/lib/glib-2.0/include/)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread -std=gnu99 -g3 -ggdb -Wall -Wextra -pedantic")

add_executable(leytunnel tunnel.c ${STX_DIR}/cares-st.c ${STX_DIR}/bio_netfd.c)
target_link_libraries(leytunnel glib-2.0 gthread-2.0 st cares z ssl)
add_dependencies(leytunnel st)

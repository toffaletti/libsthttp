find_program(RAGEL "ragel")

function(ragel_gen in_rl)
    add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${in_rl}.c
      COMMAND ${RAGEL} -o ${CMAKE_CURRENT_BINARY_DIR}/${in_rl}.c ${CMAKE_CURRENT_SOURCE_DIR}/${in_rl}.rl -I ${CMAKE_CURRENT_SOURCE_DIR}
      DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${in_rl}.rl
      )
endfunction(ragel_gen)

if(RAGEL)
    message("ragel found at: ${RAGEL}")
    include_directories(${CMAKE_CURRENT_SOURCE_DIR})
    ragel_gen(http11_parser)

    add_library(http11client STATIC ${CMAKE_CURRENT_BINARY_DIR}/http11_parser.c)
else(RAGEL)
    message("ragel not found. not building libhttp11")
endif(RAGEL)


cmake_minimum_required(VERSION 2.6)
project(zlib C)

file(GLOB ZLIB_SRC *.c *.h)

add_library(zlib STATIC ${ZLIB_SRC})

target_include_directories(zlib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
set_target_properties(zlib PROPERTIES FOLDER "third_party")
set_target_properties(zlib PROPERTIES POSITION_INDEPENDENT_CODE ON)
set_target_properties(zlib PROPERTIES OUTPUT_NAME z PREFIX "lib" CLEAN_DIRECT_OUTPUT 1)

set(ZLIB_LIBRARIES zlib PARENT_SCOPE)

target_link_libraries(zlib PUBLIC ${ZLIB_LIBRARIES})

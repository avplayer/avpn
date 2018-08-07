file(GLOB SRCS *.c)

include_directories(../crypto/)
add_library(eay32 STATIC ${SRCS})

target_link_libraries(eay32 crypto)

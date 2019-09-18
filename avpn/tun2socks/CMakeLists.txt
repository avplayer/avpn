include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}/include/
	${CMAKE_CURRENT_BINARY_DIR}
)

file(GLOB tun2socks_SRCS
	src/*.cpp
)

add_executable(tun2socks
	${tun2socks_SRCS}
)

if(UNIX AND NOT APPLE)
	target_link_libraries(tun2socks netlink)
endif()

if(WIN32)
	SET_TARGET_PROPERTIES(tun2socks PROPERTIES LINK_FLAGS " /MANIFESTUAC:\"level='requireAdministrator'\" /level='requireAdministrator'")
endif()

install(TARGETS tun2socks DESTINATION bin)
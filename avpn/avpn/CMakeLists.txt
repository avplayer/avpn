include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}/include/
	${CMAKE_CURRENT_BINARY_DIR}
)

file(GLOB vpncore_SRCS
	src/*.cpp
)

add_executable(avpn
	${vpncore_SRCS}
)
if(WIN32)
	target_link_libraries(avpn Cfgmgr32.lib)
endif()
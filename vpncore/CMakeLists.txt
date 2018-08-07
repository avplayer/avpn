include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}/include/
	${CMAKE_CURRENT_SOURCE_DIR}/include/vpncore/
	${CMAKE_CURRENT_BINARY_DIR}
)

file(GLOB vpncore_SRCS
	src/*.cpp
	src/*.c
	include/vpncore/*.hpp
	include/vpncore/*.h
)

add_executable(avpn
	${vpncore_SRCS}
	#${ODB_GENERATED}
)

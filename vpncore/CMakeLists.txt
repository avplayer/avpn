include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}/include/
	${CMAKE_CURRENT_SOURCE_DIR}/include/vpncore/
	${CMAKE_CURRENT_BINARY_DIR}
)

file(GLOB vpncore_SRCS
	include/vpncore/*.hpp
	include/vpncore/*.h
)

file(GLOB tun2socks_SRCS
	include/tun2socks/*.hpp
)

file(GLOB crypto_SRCS
	include/crypto/*.hpp
)

file(GLOB vpn_SRCS
	include/vpn/*.hpp
)

add_library(vpncore STATIC ${vpncore_SRCS} ${tun2socks_SRCS} ${crypto_SRCS} ${vpn_SRCS})

source_group("Header Files\\tun2socks" FILES ${tun2socks_SRCS})
source_group("Header Files\\vpncore" FILES ${vpncore_SRCS})
source_group("Header Files\\crypto" FILES ${crypto_SRCS})
source_group("Header Files\\vpn" FILES ${vpn_SRCS})

target_include_directories(vpncore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include/)
set(VPNCORE_LIBRARIES vpncore PARENT_SCOPE)
set(VPNCORE_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include/ PARENT_SCOPE)
target_link_libraries(vpncore PUBLIC ${VPNCORE_LIBRARIES})

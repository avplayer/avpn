include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}/include/
	${CMAKE_CURRENT_SOURCE_DIR}/include/vpncore/
	${CMAKE_CURRENT_BINARY_DIR}
)

file(GLOB vpncore_SRCS
	include/vpncore/*.hpp
	include/vpncore/*.h
)

add_library(vpncore STATIC ${vpncore_SRCS})

target_include_directories(vpncore PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include/)
set(VPNCORE_LIBRARIES vpncore PARENT_SCOPE)
set(VPNCORE_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include/ PARENT_SCOPE)
target_link_libraries(vpncore PUBLIC ${VPNCORE_LIBRARIES})

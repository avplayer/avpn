cmake_minimum_required(VERSION 2.8)

project(openssl C)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_subdirectory(crypto)
add_subdirectory(ssl)

set(OPENSSL_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include PARENT_SCOPE)

set(OPENSSL_LIBRARIES crypto eay32 PARENT_SCOPE)
set(OPENSSL_VERSION "1.0.1j" PARENT_SCOPE)
set(OPENSSL_FOUND TRUE PARENT_SCOPE)

set(LIB_EAY_LIBRARY crypto PARENT_SCOPE)
set(SSL_EAY_LIBRARY eay32 PARENT_SCOPE)

set(OPENSSL_SSL_LIBRARY eay32 PARENT_SCOPE)
set(OPENSSL_CRYPTO_LIBRARY crypto PARENT_SCOPE)

target_include_directories(crypto PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}/include
)

set_target_properties(eay32 PROPERTIES FOLDER "third_party")
set_target_properties(crypto PROPERTIES FOLDER "third_party")

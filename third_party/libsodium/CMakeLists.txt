cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

################### Variables. ####################
# Change if you want modify path or other values. #
###################################################

set(PROJECT_NAME libsodium)
# Output Variables

#set(OUTPUT_DEBUG libsodium.cmake/${CMAKE_BUILD_TYPE})
#set(OUTPUT_REL libsodium.cmake/${CMAKE_BUILD_TYPE})

# Folders files
set(CPP_DIR_1 src/libsodium/crypto_generichash)
set(CPP_DIR_2 src/libsodium/crypto_generichash/blake2b)
set(CPP_DIR_3 src/libsodium/crypto_generichash/blake2b/ref)
set(CPP_DIR_4 src/libsodium/crypto_kx)
set(CPP_DIR_5 src/libsodium/crypto_sign)
set(CPP_DIR_6 src/libsodium/crypto_sign/ed25519)
set(CPP_DIR_7 src/libsodium/crypto_sign/ed25519/ref10)
set(CPP_DIR_8 src/libsodium/crypto_secretbox)
set(CPP_DIR_9 src/libsodium/crypto_secretbox/xsalsa20poly1305)
set(CPP_DIR_10 src/libsodium/crypto_secretbox/xchacha20poly1305)
set(CPP_DIR_11 src/libsodium/crypto_pwhash)
set(CPP_DIR_12 src/libsodium/crypto_pwhash/argon2)
set(CPP_DIR_13 src/libsodium/crypto_pwhash/scryptsalsa208sha256)
set(CPP_DIR_14 src/libsodium/crypto_pwhash/scryptsalsa208sha256/nosse)
set(CPP_DIR_15 src/libsodium/crypto_pwhash/scryptsalsa208sha256/sse)
set(CPP_DIR_16 src/libsodium/crypto_verify/sodium)
set(CPP_DIR_17 src/libsodium/crypto_auth)
set(CPP_DIR_18 src/libsodium/crypto_auth/hmacsha512)
set(CPP_DIR_19 src/libsodium/crypto_auth/hmacsha512256)
set(CPP_DIR_20 src/libsodium/crypto_auth/hmacsha256)
set(CPP_DIR_21 src/libsodium/crypto_kdf)
set(CPP_DIR_22 src/libsodium/crypto_kdf/blake2b)
set(CPP_DIR_23 src/libsodium/crypto_shorthash)
set(CPP_DIR_24 src/libsodium/crypto_shorthash/siphash24)
set(CPP_DIR_25 src/libsodium/crypto_shorthash/siphash24/ref)
set(CPP_DIR_26 src/libsodium/crypto_scalarmult)
set(CPP_DIR_27 src/libsodium/crypto_scalarmult/ed25519/ref10)
set(CPP_DIR_28 src/libsodium/crypto_scalarmult/curve25519)
set(CPP_DIR_29 src/libsodium/crypto_scalarmult/curve25519/sandy2x)
set(CPP_DIR_30 src/libsodium/crypto_scalarmult/curve25519/ref10)
set(CPP_DIR_31 src/libsodium/crypto_onetimeauth)
set(CPP_DIR_32 src/libsodium/crypto_onetimeauth/poly1305)
set(CPP_DIR_33 src/libsodium/crypto_onetimeauth/poly1305/donna)
set(CPP_DIR_34 src/libsodium/crypto_onetimeauth/poly1305/sse2)
set(CPP_DIR_35 src/libsodium/randombytes)
set(CPP_DIR_36 src/libsodium/randombytes/sysrandom)
set(CPP_DIR_37 src/libsodium/randombytes/salsa20)
set(CPP_DIR_38 src/libsodium/randombytes/nativeclient)
set(CPP_DIR_39 src/libsodium/crypto_box)
set(CPP_DIR_40 src/libsodium/crypto_box/curve25519xsalsa20poly1305)
set(CPP_DIR_41 src/libsodium/crypto_box/curve25519xchacha20poly1305)
set(CPP_DIR_42 src/libsodium/sodium)
set(CPP_DIR_43 src/libsodium/crypto_stream)
set(CPP_DIR_44 src/libsodium/crypto_stream/xchacha20)
set(CPP_DIR_45 src/libsodium/crypto_stream/chacha20)
set(CPP_DIR_46 src/libsodium/crypto_stream/chacha20/ref)
set(CPP_DIR_47 src/libsodium/crypto_stream/chacha20/dolbeau)
set(CPP_DIR_48 src/libsodium/crypto_stream/salsa20)
set(CPP_DIR_49 src/libsodium/crypto_stream/salsa20/ref)
set(CPP_DIR_50 src/libsodium/crypto_stream/salsa20/xmm6int)
set(CPP_DIR_51 src/libsodium/crypto_stream/salsa20/xmm6)
set(CPP_DIR_52 src/libsodium/crypto_stream/salsa2012)
set(CPP_DIR_53 src/libsodium/crypto_stream/salsa2012/ref)
set(CPP_DIR_54 src/libsodium/crypto_stream/salsa208)
set(CPP_DIR_55 src/libsodium/crypto_stream/salsa208/ref)
set(CPP_DIR_56 src/libsodium/crypto_stream/xsalsa20)
set(CPP_DIR_57 src/libsodium/crypto_hash)
set(CPP_DIR_58 src/libsodium/crypto_hash/sha512)
set(CPP_DIR_59 src/libsodium/crypto_hash/sha512/cp)
set(CPP_DIR_60 src/libsodium/crypto_hash/sha256)
set(CPP_DIR_61 src/libsodium/crypto_hash/sha256/cp)
set(CPP_DIR_62 src/libsodium/crypto_aead/xchacha20poly1305/sodium)
set(CPP_DIR_63 src/libsodium/crypto_aead/aes256gcm/aesni)
set(CPP_DIR_64 src/libsodium/crypto_aead/chacha20poly1305/sodium)
set(CPP_DIR_65 src/libsodium/crypto_secretstream/xchacha20poly1305)
set(CPP_DIR_66 src/libsodium/crypto_core/salsa/ref)
set(CPP_DIR_67 src/libsodium/crypto_core/hchacha20)
set(CPP_DIR_68 src/libsodium/crypto_core/hsalsa20)
set(CPP_DIR_69 src/libsodium/crypto_core/hsalsa20/ref2)
set(CPP_DIR_70 src/libsodium/crypto_core/ed25519)
set(CPP_DIR_71 src/libsodium/crypto_core/ed25519/ref10)
set(HEADER_DIR_1 src/libsodium/crypto_generichash/blake2b/ref)
set(HEADER_DIR_2 src/libsodium/crypto_sign/ed25519/ref10)
set(HEADER_DIR_3 src/libsodium/include)
set(HEADER_DIR_4 src/libsodium/include/sodium)
set(HEADER_DIR_5 src/libsodium/include/sodium/private)
set(HEADER_DIR_6 src/libsodium/crypto_pwhash/argon2)
set(HEADER_DIR_7 src/libsodium/crypto_pwhash/scryptsalsa208sha256)
set(HEADER_DIR_8 src/libsodium/crypto_shorthash/siphash24/ref)
set(HEADER_DIR_9 src/libsodium/crypto_scalarmult/curve25519)
set(HEADER_DIR_10 src/libsodium/crypto_scalarmult/curve25519/sandy2x)
set(HEADER_DIR_11 src/libsodium/crypto_scalarmult/curve25519/ref10)
set(HEADER_DIR_12 src/libsodium/crypto_onetimeauth/poly1305)
set(HEADER_DIR_13 src/libsodium/crypto_onetimeauth/poly1305/donna)
set(HEADER_DIR_14 src/libsodium/crypto_onetimeauth/poly1305/sse2)
set(HEADER_DIR_15 src/libsodium/crypto_stream/chacha20)
set(HEADER_DIR_16 src/libsodium/crypto_stream/chacha20/ref)
set(HEADER_DIR_17 src/libsodium/crypto_stream/chacha20/dolbeau)
set(HEADER_DIR_18 src/libsodium/crypto_stream/salsa20)
set(HEADER_DIR_19 src/libsodium/crypto_stream/salsa20/ref)
set(HEADER_DIR_20 src/libsodium/crypto_stream/salsa20/xmm6int)
set(HEADER_DIR_21 src/libsodium/crypto_stream/salsa20/xmm6)
set(HEADER_DIR_22 src/libsodium/crypto_core/ed25519/ref10/fe_25_5)
set(HEADER_DIR_23 src/libsodium/crypto_core/ed25519/ref10/fe_51)
#set(HEADER_DIR_24 ../..)

############## CMake Project ################
#        The main options of project        #
#############################################

project(${PROJECT_NAME} C)

# Define Release by default.
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release")
  message(STATUS "Build type not specified: Use Release by default.")
endif(NOT CMAKE_BUILD_TYPE)

############## Artefacts Output #################
# Defines outputs , depending Debug or Release. #
#################################################

#if(CMAKE_BUILD_TYPE STREQUAL "Debug")
#  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${OUTPUT_DEBUG}")
#  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${OUTPUT_DEBUG}")
#  set(CMAKE_EXECUTABLE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${OUTPUT_DEBUG}")
#else()
#  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${OUTPUT_REL}")
#  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${OUTPUT_REL}")
#  set(CMAKE_EXECUTABLE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/${OUTPUT_REL}")
#endif()

################# Flags ################
# Defines Flags for Windows and Linux. #
########################################

if(MSVC)
   set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /EHsc")
   set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /EHsc")
endif(MSVC)
if(NOT MSVC)
   set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
   if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
       set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")
   endif()
endif(NOT MSVC)

add_definitions(-DSODIUM_STATIC)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium/include/sodium/)

################ Files ################
#   --   Add files to project.   --   #
#######################################

file(GLOB SRC_FILES
    ${CPP_DIR_1}/*.c
    ${CPP_DIR_2}/*.c
    ${CPP_DIR_3}/*.c
    ${CPP_DIR_4}/*.c
    ${CPP_DIR_5}/*.c
    ${CPP_DIR_6}/*.c
    ${CPP_DIR_7}/*.c
    ${CPP_DIR_8}/*.c
    ${CPP_DIR_9}/*.c
    ${CPP_DIR_10}/*.c
    ${CPP_DIR_11}/*.c
    ${CPP_DIR_12}/*.c
    ${CPP_DIR_13}/*.c
    ${CPP_DIR_14}/*.c
    ${CPP_DIR_15}/*.c
    ${CPP_DIR_16}/*.c
    ${CPP_DIR_17}/*.c
    ${CPP_DIR_18}/*.c
    ${CPP_DIR_19}/*.c
    ${CPP_DIR_20}/*.c
    ${CPP_DIR_21}/*.c
    ${CPP_DIR_22}/*.c
    ${CPP_DIR_23}/*.c
    ${CPP_DIR_24}/*.c
    ${CPP_DIR_25}/*.c
    ${CPP_DIR_26}/*.c
    ${CPP_DIR_27}/*.c
    ${CPP_DIR_28}/*.c
    ${CPP_DIR_29}/*.c
    ${CPP_DIR_30}/*.c
    ${CPP_DIR_31}/*.c
    ${CPP_DIR_32}/*.c
    ${CPP_DIR_33}/*.c
    ${CPP_DIR_34}/*.c
    ${CPP_DIR_35}/*.c
    ${CPP_DIR_36}/*.c
    ${CPP_DIR_37}/*.c
    ${CPP_DIR_38}/*.c
    ${CPP_DIR_39}/*.c
    ${CPP_DIR_40}/*.c
    ${CPP_DIR_41}/*.c
    ${CPP_DIR_42}/*.c
    ${CPP_DIR_43}/*.c
    ${CPP_DIR_44}/*.c
    ${CPP_DIR_45}/*.c
    ${CPP_DIR_46}/*.c
    ${CPP_DIR_47}/*.c
    ${CPP_DIR_48}/*.c
    ${CPP_DIR_49}/*.c
    ${CPP_DIR_50}/*.c
    ${CPP_DIR_51}/*.c
    ${CPP_DIR_52}/*.c
    ${CPP_DIR_53}/*.c
    ${CPP_DIR_54}/*.c
    ${CPP_DIR_55}/*.c
    ${CPP_DIR_56}/*.c
    ${CPP_DIR_57}/*.c
    ${CPP_DIR_58}/*.c
    ${CPP_DIR_59}/*.c
    ${CPP_DIR_60}/*.c
    ${CPP_DIR_61}/*.c
    ${CPP_DIR_62}/*.c
    ${CPP_DIR_63}/*.c
    ${CPP_DIR_64}/*.c
    ${CPP_DIR_65}/*.c
    ${CPP_DIR_66}/*.c
    ${CPP_DIR_67}/*.c
    ${CPP_DIR_68}/*.c
    ${CPP_DIR_69}/*.c
    ${CPP_DIR_70}/*.c
    ${CPP_DIR_71}/*.c
    ${HEADER_DIR_1}/*.h
    ${HEADER_DIR_2}/*.h
    ${HEADER_DIR_3}/*.h
    ${HEADER_DIR_4}/*.h
    ${HEADER_DIR_5}/*.h
    ${HEADER_DIR_6}/*.h
    ${HEADER_DIR_7}/*.h
    ${HEADER_DIR_8}/*.h
    ${HEADER_DIR_9}/*.h
    ${HEADER_DIR_10}/*.h
    ${HEADER_DIR_11}/*.h
    ${HEADER_DIR_12}/*.h
    ${HEADER_DIR_13}/*.h
    ${HEADER_DIR_14}/*.h
    ${HEADER_DIR_15}/*.h
    ${HEADER_DIR_16}/*.h
    ${HEADER_DIR_17}/*.h
    ${HEADER_DIR_18}/*.h
    ${HEADER_DIR_19}/*.h
    ${HEADER_DIR_20}/*.h
    ${HEADER_DIR_21}/*.h
    ${HEADER_DIR_22}/*.h
    ${HEADER_DIR_23}/*.h
#    ${HEADER_DIR_24}/*.h
)

# Add library to build.
add_library(${PROJECT_NAME} STATIC
   ${SRC_FILES}
)

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium/include)
set_target_properties(${PROJECT_NAME} PROPERTIES FOLDER "third_party")
set_target_properties(${PROJECT_NAME} PROPERTIES POSITION_INDEPENDENT_CODE ON)
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME sodium PREFIX "lib" CLEAN_DIRECT_OUTPUT 1)

set(SODIUM_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium/include PARENT_SCOPE)
set(SODIUM_LIBRARIES ${PROJECT_NAME} PARENT_SCOPE)

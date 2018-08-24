cmake_minimum_required(VERSION 2.6)
project(libsodium C)

# Folders files
set(SRC_DIR_1 src/libsodium/crypto_generichash)
set(SRC_DIR_2 src/libsodium/crypto_generichash/blake2b)
set(SRC_DIR_3 src/libsodium/crypto_generichash/blake2b/ref)
set(SRC_DIR_4 src/libsodium/crypto_kx)
set(SRC_DIR_5 src/libsodium/crypto_sign)
set(SRC_DIR_6 src/libsodium/crypto_sign/ed25519)
set(SRC_DIR_7 src/libsodium/crypto_sign/ed25519/ref10)
set(SRC_DIR_8 src/libsodium/crypto_secretbox)
set(SRC_DIR_9 src/libsodium/crypto_secretbox/xsalsa20poly1305)
set(SRC_DIR_10 src/libsodium/crypto_secretbox/xchacha20poly1305)
set(SRC_DIR_11 src/libsodium/crypto_pwhash)
set(SRC_DIR_12 src/libsodium/crypto_pwhash/argon2)
set(SRC_DIR_13 src/libsodium/crypto_pwhash/scryptsalsa208sha256)
set(SRC_DIR_14 src/libsodium/crypto_pwhash/scryptsalsa208sha256/nosse)
set(SRC_DIR_15 src/libsodium/crypto_pwhash/scryptsalsa208sha256/sse)
set(SRC_DIR_16 src/libsodium/crypto_verify/sodium)
set(SRC_DIR_17 src/libsodium/crypto_auth)
set(SRC_DIR_18 src/libsodium/crypto_auth/hmacsha512)
set(SRC_DIR_19 src/libsodium/crypto_auth/hmacsha512256)
set(SRC_DIR_20 src/libsodium/crypto_auth/hmacsha256)
set(SRC_DIR_21 src/libsodium/crypto_kdf)
set(SRC_DIR_22 src/libsodium/crypto_kdf/blake2b)
set(SRC_DIR_23 src/libsodium/crypto_shorthash)
set(SRC_DIR_24 src/libsodium/crypto_shorthash/siphash24)
set(SRC_DIR_25 src/libsodium/crypto_shorthash/siphash24/ref)
set(SRC_DIR_26 src/libsodium/crypto_scalarmult)
set(SRC_DIR_27 src/libsodium/crypto_scalarmult/ed25519/ref10)
set(SRC_DIR_28 src/libsodium/crypto_scalarmult/curve25519)
set(SRC_DIR_29 src/libsodium/crypto_scalarmult/curve25519/sandy2x)
set(SRC_DIR_30 src/libsodium/crypto_scalarmult/curve25519/ref10)
set(SRC_DIR_31 src/libsodium/crypto_onetimeauth)
set(SRC_DIR_32 src/libsodium/crypto_onetimeauth/poly1305)
set(SRC_DIR_33 src/libsodium/crypto_onetimeauth/poly1305/donna)
set(SRC_DIR_34 src/libsodium/crypto_onetimeauth/poly1305/sse2)
set(SRC_DIR_35 src/libsodium/randombytes)
set(SRC_DIR_36 src/libsodium/randombytes/sysrandom)
set(SRC_DIR_37 src/libsodium/randombytes/salsa20)
set(SRC_DIR_38 src/libsodium/randombytes/nativeclient)
set(SRC_DIR_39 src/libsodium/crypto_box)
set(SRC_DIR_40 src/libsodium/crypto_box/curve25519xsalsa20poly1305)
set(SRC_DIR_41 src/libsodium/crypto_box/curve25519xchacha20poly1305)
set(SRC_DIR_42 src/libsodium/sodium)
set(SRC_DIR_43 src/libsodium/crypto_stream)
set(SRC_DIR_44 src/libsodium/crypto_stream/xchacha20)
set(SRC_DIR_45 src/libsodium/crypto_stream/chacha20)
set(SRC_DIR_46 src/libsodium/crypto_stream/chacha20/ref)
set(SRC_DIR_47 src/libsodium/crypto_stream/chacha20/dolbeau)
set(SRC_DIR_48 src/libsodium/crypto_stream/salsa20)
set(SRC_DIR_49 src/libsodium/crypto_stream/salsa20/ref)
set(SRC_DIR_50 src/libsodium/crypto_stream/salsa20/xmm6int)
set(SRC_DIR_51 src/libsodium/crypto_stream/salsa20/xmm6)
set(SRC_DIR_52 src/libsodium/crypto_stream/salsa2012)
set(SRC_DIR_53 src/libsodium/crypto_stream/salsa2012/ref)
set(SRC_DIR_54 src/libsodium/crypto_stream/salsa208)
set(SRC_DIR_55 src/libsodium/crypto_stream/salsa208/ref)
set(SRC_DIR_56 src/libsodium/crypto_stream/xsalsa20)
set(SRC_DIR_57 src/libsodium/crypto_hash)
set(SRC_DIR_58 src/libsodium/crypto_hash/sha512)
set(SRC_DIR_59 src/libsodium/crypto_hash/sha512/cp)
set(SRC_DIR_60 src/libsodium/crypto_hash/sha256)
set(SRC_DIR_61 src/libsodium/crypto_hash/sha256/cp)
set(SRC_DIR_62 src/libsodium/crypto_aead/xchacha20poly1305/sodium)
set(SRC_DIR_63 src/libsodium/crypto_aead/aes256gcm/aesni)
set(SRC_DIR_64 src/libsodium/crypto_aead/chacha20poly1305/sodium)
set(SRC_DIR_65 src/libsodium/crypto_secretstream/xchacha20poly1305)
set(SRC_DIR_66 src/libsodium/crypto_core/salsa/ref)
set(SRC_DIR_67 src/libsodium/crypto_core/hchacha20)
set(SRC_DIR_68 src/libsodium/crypto_core/hsalsa20)
set(SRC_DIR_69 src/libsodium/crypto_core/hsalsa20/ref2)
set(SRC_DIR_70 src/libsodium/crypto_core/ed25519)
set(SRC_DIR_71 src/libsodium/crypto_core/ed25519/ref10)
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

add_definitions(-DSODIUM_STATIC)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium/include/sodium/)

file(GLOB SRC_FILES
    ${SRC_DIR_1}/*.c
    ${SRC_DIR_2}/*.c
    ${SRC_DIR_3}/*.c
    ${SRC_DIR_4}/*.c
    ${SRC_DIR_5}/*.c
    ${SRC_DIR_6}/*.c
    ${SRC_DIR_7}/*.c
    ${SRC_DIR_8}/*.c
    ${SRC_DIR_9}/*.c
    ${SRC_DIR_10}/*.c
    ${SRC_DIR_11}/*.c
    ${SRC_DIR_12}/*.c
    ${SRC_DIR_13}/*.c
    ${SRC_DIR_14}/*.c
    ${SRC_DIR_15}/*.c
    ${SRC_DIR_16}/*.c
    ${SRC_DIR_17}/*.c
    ${SRC_DIR_18}/*.c
    ${SRC_DIR_19}/*.c
    ${SRC_DIR_20}/*.c
    ${SRC_DIR_21}/*.c
    ${SRC_DIR_22}/*.c
    ${SRC_DIR_23}/*.c
    ${SRC_DIR_24}/*.c
    ${SRC_DIR_25}/*.c
    ${SRC_DIR_26}/*.c
    ${SRC_DIR_27}/*.c
    ${SRC_DIR_28}/*.c
    ${SRC_DIR_29}/*.c
    ${SRC_DIR_30}/*.c
    ${SRC_DIR_31}/*.c
    ${SRC_DIR_32}/*.c
    ${SRC_DIR_33}/*.c
    ${SRC_DIR_34}/*.c
    ${SRC_DIR_35}/*.c
    ${SRC_DIR_36}/*.c
    ${SRC_DIR_37}/*.c
    ${SRC_DIR_38}/*.c
    ${SRC_DIR_39}/*.c
    ${SRC_DIR_40}/*.c
    ${SRC_DIR_41}/*.c
    ${SRC_DIR_42}/*.c
    ${SRC_DIR_43}/*.c
    ${SRC_DIR_44}/*.c
    ${SRC_DIR_45}/*.c
    ${SRC_DIR_46}/*.c
    ${SRC_DIR_47}/*.c
    ${SRC_DIR_48}/*.c
    ${SRC_DIR_49}/*.c
    ${SRC_DIR_50}/*.c
    ${SRC_DIR_51}/*.c
    ${SRC_DIR_52}/*.c
    ${SRC_DIR_53}/*.c
    ${SRC_DIR_54}/*.c
    ${SRC_DIR_55}/*.c
    ${SRC_DIR_56}/*.c
    ${SRC_DIR_57}/*.c
    ${SRC_DIR_58}/*.c
    ${SRC_DIR_59}/*.c
    ${SRC_DIR_60}/*.c
    ${SRC_DIR_61}/*.c
    ${SRC_DIR_62}/*.c
    ${SRC_DIR_63}/*.c
    ${SRC_DIR_64}/*.c
    ${SRC_DIR_65}/*.c
    ${SRC_DIR_66}/*.c
    ${SRC_DIR_67}/*.c
    ${SRC_DIR_68}/*.c
    ${SRC_DIR_69}/*.c
    ${SRC_DIR_70}/*.c
    ${SRC_DIR_71}/*.c
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
)

add_library(libsodium STATIC ${SRC_FILES})

target_include_directories(libsodium PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium/include)
set_target_properties(libsodium PROPERTIES FOLDER "third_party")
set_target_properties(libsodium PROPERTIES POSITION_INDEPENDENT_CODE ON)
set_target_properties(libsodium PROPERTIES OUTPUT_NAME sodium PREFIX "lib" CLEAN_DIRECT_OUTPUT 1)

set(SODIUM_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/src/libsodium/include PARENT_SCOPE)
set(SODIUM_LIBRARIES libsodium PARENT_SCOPE)

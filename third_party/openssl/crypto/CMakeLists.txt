include_directories(${CMAKE_CURRENT_SOURCE_DIR})

include_directories(asn1)
include_directories(evp)
include_directories(modes)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include/)

file(GLOB SRCS
	aes/*.c
	asn1/*.c
	bf/*.c
	bio/*.c
	bn/*.c
	buffer/*.c
	camellia/*.c
	cast/*.c
	cmac/*.c
	cms/*.c
	conf/*.c
	dh/*.c

	des/cbc_cksm.c
	des/cbc_enc.c
	des/cfb_enc.c
	des/cfb64ede.c
	des/cfb64enc.c
	des/des_enc.c
	des/des_old.c
	des/des_old2.c
	des/ecb_enc.c
	des/ecb3_enc.c
	des/ede_cbcm_enc.c
	des/enc_read.c
	des/enc_writ.c
	des/fcrypt.c
	des/fcrypt_b.c
	des/ofb_enc.c
	des/ofb64ede.c
	des/ofb64enc.c
	des/pcbc_enc.c
	des/qud_cksm.c
	des/rand_key.c
	des/read2pwd.c
	des/rpc_enc.c
	des/set_key.c
	des/str2key.c
	des/xcbc_enc.c

	dsa/*.c
	dso/*.c
	ec/*.c
	ecdsa/*.c
	ecdh/*.c
	err/*.c
	evp/*.c
	hmac/*.c
	idea/*.c
	lhash/*.c
	md5/*.c
	modes/*.c
	objects/*.c
	ocsp/*.c
	pem/*.c
	pqueue/*.c
	pkcs7/*.c
	pkcs12/*.c
	rand/*.c
	rc4/*.c
	rsa/*.c
	seed/*.c
	sha/*.c
	srp/*.c
	stack/*.c
	ts/*.c
	txt_db/*.c
	ui/*.c
	x509/*.c
	x509v3/*.c
	o_init.c o_dir.c o_str.c o_time.c ex_data.c cpt_err.c cryptlib.c mem.c mem_dbg.c mem_clr.c  cversion.c uid.c
)

add_library(crypto STATIC ${SRCS})

target_compile_definitions(crypto PUBLIC
	-DOPENSSL_NO_ASM
	-DOPENSSL_NO_ENGINE
	-DOPENSSL_NO_RC1
	-DOPENSSL_NO_RC2
	-DOPENSSL_NO_RC3
	-DOPENSSL_NO_MD1
	-DOPENSSL_NO_MD2
	-DOPENSSL_NO_MD3
	-DOPENSSL_NO_MD4
	-DOPENSSL_NO_MDC2
	-DOPENSSL_NO_WHIRLPOOL
	-DOPENSSL_NO_RIPEMD
	-DOPENSSL_NO_COMP
	-DOPENSSL_NO_OCSP
)

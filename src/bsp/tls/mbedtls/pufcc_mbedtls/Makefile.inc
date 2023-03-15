THIRDPARTY_DIR = $(dir $(lastword $(MAKEFILE_LIST)))
THIRDPARTY_DIR_PATH = $(patsubst %/,%,${THIRDPARTY_DIR})
THIRDPARTY_INC_DIR = $(THIRDPARTY_DIR_PATH)/include
THIRDPARTY_SRC_DIR = $(THIRDPARTY_DIR_PATH)/src
THIRDPARTY_LIB_PATH = $(THIRDPARTY_DIR_PATH)/../../../../../third_party/pufcc/lib

#Define PUF_TLS_ALT for mbedtls/library/Makefile
PUF_TLS_ALT=1

THIRDPARTY_INCLUDES += -I$(THIRDPARTY_INC_DIR)

# add pufcc library
THIRDPARTY_INCLUDES += -L$(THIRDPARTY_LIB_PATH) -lpufcc

THIRDPARTY_CRYPTO_OBJECTS += \
    $(THIRDPARTY_SRC_DIR)/sha256_alt.o \
    $(THIRDPARTY_SRC_DIR)/pufcc_mbedtls_sha256.o \
    $(THIRDPARTY_SRC_DIR)/ecdsa_alt.o \
    $(THIRDPARTY_SRC_DIR)/pufcc_mbedtls_ecdsa.o	\
    $(THIRDPARTY_SRC_DIR)/ecdh_alt.o	\
    $(THIRDPARTY_SRC_DIR)/pufcc_mbedtls_ecdh.o \
    $(THIRDPARTY_SRC_DIR)/gcm_alt.o	\
    $(THIRDPARTY_SRC_DIR)/pufcc_mbedtls_gcm.o    

	
    


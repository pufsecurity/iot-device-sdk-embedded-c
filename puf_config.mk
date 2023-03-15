PUF=YES
PUF_CROSS_COMPILE=YES

# DEBUG Flag
PUF_IOTC_DEBUG=NO
PUF_TLS_DEBUG=NO

# PUF DEMO LOG
# When PUF_DEMO_LOG=YES, 
# flags PUF_DEMO_LOG_MQTT and PUF_DEMO_LOG_TLS are defined.
PUF_DEMO_LOG=YES



# PUF_CRYPTO_TLS is used to enable/disable tls pufcc hw crypto replacement. 
# Used in 
# 1. mt-tls.mk to include PUFCC_xxx_DIR related folders and c files 
#                         ($(LIBIOTC)/third_party/pufcc/ )
# 2. mt-tls.mk to define MBEDTLS_CONFIG_FILE_NAME and assign IOTC_BSP_TLS_BUILD_ARGS for build_mbedtls_puf.sh
# 3. mt-config to include IOTC_BSP_TLS_PUFCC_xxx related source, header and config files 
#    (e.g.:IOTC_BSP_TLS_PUFCC_SRC = $(IOTC_BSP_DIR)/tls/$(IOTC_BSP_TLS)/pufcc_mbedtls/src)
PUF_CRYPTO_TLS=YES

# PUF_CRYPTO is used in makefile and examples/common/rules.mk to include puf crypto related folders and c files.
ifeq ($(PUF), YES)
    PUF_CRYPTO=YES
else
    PUF_CRYPTO=NO
    PUF_CRYPTO_TLS=NO
endif


# Note :
#
# When using ARM_10_3, the client example code execution will show below error
#./iot_core_mqtt_client: /lib/libc.so.6: version `GLIBC_2.28' not found (required by ./iot_core_mqtt_client)
#./iot_core_mqtt_client: /lib/libc.so.6: version `GLIBC_2.33' not found (required by ./iot_core_mqtt_client)
#
# Need to use gcc-linaro-6.2.1-2016.11-x86_64_arm-linux-gnueabihf.tar.xz (from below url)
# https://releases.linaro.org/components/toolchain/binaries/6.2-2016.11/arm-linux-gnueabihf/gcc-linaro-6.2.1-2016.11-x86_64_arm-linux-gnueabihf.tar.xz
# (gcc version 6.2.1 20161016 (Linaro GCC 6.2-2016.11))
#

#CROSS_COMPILE_VER=ARM_10_3
CROSS_COMPILE_VER=ARM_6_2

ifeq ($(PUF_CROSS_COMPILE), YES)
    ifeq ($(CROSS_COMPILE_VER), ARM_10_3)
        GCC_DIR=~/Downloads/gcc-arm-10.3-2021.07-x86_64-arm-none-linux-gnueabihf
        GCC_BIN_DIR=~/Downloads/gcc-arm-10.3-2021.07-x86_64-arm-none-linux-gnueabihf/bin
    else
       GCC_DIR=~/Downloads/gcc-linaro-6.2.1-2016.11-x86_64_arm-linux-gnueabihf
       GCC_BIN_DIR=~/Downloads/gcc-linaro-6.2.1-2016.11-x86_64_arm-linux-gnueabihf/bin
    endif
endif

ifeq ($(PUF), YES)
    PUF_FLAGS=-DPUF
endif

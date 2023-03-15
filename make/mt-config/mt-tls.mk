# Copyright 2018-2020 Google LLC
#
# This is part of the Google Cloud IoT Device SDK for Embedded C.
# It is licensed under the BSD 3-Clause license; you may not use this file
# except in compliance with the License.
#
# You may obtain a copy of the License at:
#  https://opensource.org/licenses/BSD-3-Clause
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# PUF +++
include puf_config.mk
# PUF ---

# pick the proper configuration file for TLS library

ifneq ($(IOTC_USE_EXTERNAL_TLS_LIB),1)

#If using IOTC_USE_EXTERNAL_TLS_LIB, you'll need to provide IOTC_TLS_LIB_INC_DIR
IOTC_TLS_LIB_CONFIG_FNAME ?= make/mt-config/mt-tls-$(IOTC_BSP_TLS).mk
include $(IOTC_TLS_LIB_CONFIG_FNAME)

TLS_LIB_PATH := $(LIBIOTC)/third_party/$(IOTC_BSP_TLS)
endif

IOTC_INCLUDE_FLAGS += -I$(IOTC_TLS_LIB_INC_DIR)

IOTC_LIB_FLAGS += $(foreach d, $(IOTC_TLS_LIB_NAME), -l$d)
IOTC_LIB_FLAGS += -L$(IOTC_TLS_LIB_DIR)

# PUF +++
# pufcc library and include file
ifeq ($(PUF_CRYPTO), YES)
    PUFCC_INC_DIR=$(LIBIOTC)/third_party/pufcc/include
    PUFCC_INC_INT_DIR=$(LIBIOTC)/third_party/pufcc/include_internal
    PUFCC_LIB_DIR=$(LIBIOTC)/third_party/pufcc/lib
endif
# PUF ---


# PUF +++
ifeq ($(PUF_CRYPTO_TLS), YES)
    MBEDTLS_CONFIG_FILE_NAME=\"$(IOTC_BSP_TLS_PUFCC_CFG)/pufcc_mbedtls_config.h\"
    #PUFCC include header file and libpufcc library
    IOTC_BSP_TLS_BUILD_ARGS += -I$(PUFCC_INC_DIR) -I$(PUFCC_INC_INT_DIR) 
    #PUFCC mbedtls alternative
    IOTC_BSP_TLS_BUILD_ARGS += -DPUF_CRYPTO_TLS -I$(IOTC_BSP_TLS_PUFCC_INC) -I$(IOTC_BSP_TLS_PUFCC_CFG) -DMBEDTLS_CONFIG_FILE='$(MBEDTLS_CONFIG_FILE_NAME)'
endif

ifeq ($(PUF_TLS_DEBUG), YES) 
    IOTC_BSP_TLS_BUILD_ARGS += -DPUF_TLS_DEBUG
endif

ifeq ($(PUF_DEMO_LOG), YES)
    IOTC_BSP_TLS_BUILD_ARGS += -DPUF_DEMO_LOG_TLS
endif
# PUF ---

ifneq (,$(findstring Windows,$(IOTC_HOST_PLATFORM)))
    TLS_LIB_PREPARE_CMD :=
else ifeq ($(IOTC_USE_EXTERNAL_TLS_LIB),1)
    TLS_LIB_PREPARE_CMD :=
else
    # PUF +++
    ifeq ($(PUF_CROSS_COMPILE), YES)
        ifeq ($(PUF), YES)  # Use PUFCC
            BUILD_TLS_SCRIPT=build_$(IOTC_BSP_TLS)_puf.sh
        else
            BUILD_TLS_SCRIPT=build_$(IOTC_BSP_TLS).sh
        endif
        ifeq ($(CROSS_COMPILE_VER), ARM_10_3)
            TLS_LIB_PREPARE_CMD = (cd $(LIBIOTC)/res/tls && ./$(BUILD_TLS_SCRIPT) -DARM103 $(IOTC_BSP_TLS_BUILD_ARGS))
        else
            TLS_LIB_PREPARE_CMD = (cd $(LIBIOTC)/res/tls && ./$(BUILD_TLS_SCRIPT) -UARM103 $(IOTC_BSP_TLS_BUILD_ARGS))
        endif
    else
    # PUF ---
    TLS_LIB_PREPARE_CMD = (cd $(LIBIOTC)/res/tls && ./build_$(IOTC_BSP_TLS).sh $(IOTC_BSP_TLS_BUILD_ARGS))
    # PUF +++
    endif
    # PUF ---
endif

$(IOTC_TLS_LIB_DEP):
	$(info #  )
	$(info # NOTE! Makefile executing 3rd Party TLS build: )
	$(info # )
	$(info )
	$(info The build configuration you're using includes a dependency )
	$(info on a third party TLS implementation defined with the build )
	$(info variable IOTC_BSP_TLS: $(IOTC_BSP_TLS) )
	$(info )
	$(info The Google IoT Core Embedded C Client make system is )
	$(info executing a custom shell script in res/tls to configure )
	$(info and build this TLS library for you. )
	$(info )
	$(info Please see ./README.md for more information.)
	$(info )
	$(TLS_LIB_PREPARE_CMD)

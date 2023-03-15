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

IOTC_EXAMPLE_NAME := iot_core_mqtt_client

# PUF +++
include ../../puf_config.mk
ifeq ($(PUF_CROSS_COMPILE), YES)
    IOTC_TARGET_PLATFORM = arm-linux

    ifeq ($(CROSS_COMPILE_VER), ARM_10_3)
        # in puf_config.mk
        #GCC_DIR=~/Downloads/gcc-arm-1 0.3-2021.07-x86_64-arm-none-linux-gnueabihf
        GCC_BIN=$(GCC_BIN_DIR)
        CC=$(GCC_BIN)/arm-none-linux-gnueabihf-gcc
        AR=$(GCC_BIN)/arm-none-linux-gnueabihf-ar
    else
        #GCC_DIR=~/Downloads/gcc-linaro-6.2.1-2016.11-x86_64_arm-linux-gnueabihf
        GCC_BIN=$(GCC_BIN_DIR)
        CC=$(GCC_BIN)/arm-linux-gnueabihf-gcc
        AR=$(GCC_BIN)/arm-linux-gnueabihf-ar
     endif    
endif
# PUF ---

include ../common/rules.mk
include ../common/targets.mk

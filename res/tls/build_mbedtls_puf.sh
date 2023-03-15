#!/bin/bash
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
#
#--------------------------------------------------------------------------------
# Copyright 2022-2023 PUFsecurity
#
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


echo
echo "--------------------------"
echo "| mbedTLS LICENSE Notice |"
echo "--------------------------"
echo
echo "Unless specifically indicated otherwise in a file, files are licensed"
echo "under the Apache 2.0 license, as can be found in: apache-2.0.txt"
echo
echo "the apache-2.0.txt file can be accessed here:"
echo "   https://www.apache.org/licenses/LICENSE-2.0"
echo
echo "For more information about the mbedTLS license, please check the LICENSE"
echo "file of the mbedTLS directory after this auto-checkout procedure"
echo "completes, or check their github repository at the following address:"
echo "  https://github.com/ARMmbed/mbedtls"
echo
read -p "Continue to auto-download and build mbedTLS? [Y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    echo
    echo "exiting build."
    echo
    exit 1
fi


mkdir -p ../../third_party/tls
cd ../../third_party/tls

# PUF +++ : change mbedtls repo
# git clone -b mbedtls-2.12.0 https://github.com/ARMmbed/mbedtls.git
git clone -b mbedtls-2.12.0-pufcc https://github.com/pufsecurity/mbedtls.git
# PUF ---

cd mbedtls
# "-O2" comes from mbedtls/library/Makefile "CFLAGS ?= -O2" define

# PUF +++
echo "number of argument $#"
argc=$#
argv=("$@")
CFLAGS_INPUT=""

for (( j=0; j<(argc); j++ )); do
#    echo "${argv[j]}"
    CFLAGS_INPUT+="${argv[j]} "
done
echo "Mbedtls CFLAGS_INPUT : $CFLAGS_INPUT"

# PUF +++
# set marget target to programs only (all: programs tests)
MAKE_TARGET=programs
# PUF ---

if [ "$1" == "-DARM103" ];then
    ARM_GCC_BIN=~/Downloads/gcc-arm-10.3-2021.07-x86_64-arm-none-linux-gnueabihf/bin
    echo "input cmake toolchain"
    echo "pwd $PWD arm gcc $ARM_GCC_BIN"
    echo "PATH1 $PATH"

    make CFLAGS="-O2 -DMBEDTLS_PLATFORM_MEMORY -mcpu=cortex-a9 -mfpu=vfpv3 -mfloat-abi=hard -DCMAKE_TOOLCHAIN_FILE=toolchain.cmake $CFLAGS_INPUT" \
    $MAKE_TARGET \
    CC=$ARM_GCC_BIN/arm-none-linux-gnueabihf-gcc \
    GXX=$ARM_GCC_BIN/arm-none-linux-gnueabihf-gxx \
    AR=$ARM_GCC_BIN/arm-none-linux-gnueabihf-ar

elif [ "$1" == "-UARM103" ];then 
    ARM_GCC_BIN=~/Downloads/gcc-linaro-6.2.1-2016.11-x86_64_arm-linux-gnueabihf/bin   

    echo "input cmake toolchain"
    echo "pwd $PWD arm gcc $ARM_GCC_BIN"
    echo "PATH2 $PATH"

    make CFLAGS="-O2 -DMBEDTLS_PLATFORM_MEMORY -mcpu=cortex-a9 -mfpu=vfpv3 -mfloat-abi=hard -DCMAKE_TOOLCHAIN_FILE=toolchain.cmake $CFLAGS_INPUT" \
    $MAKE_TARGET \
    CC=$ARM_GCC_BIN/arm-linux-gnueabihf-gcc \
    AR=$ARM_GCC_BIN/arm-linux-gnueabihf-ar  \
    #GXX=$ARM_GCC_BIN/arm-linux-gnueabihf-gxx

else
    
# PUF ---
    echo "not input cmake toolchain"
    make CFLAGS="-O2 -DMBEDTLS_PLATFORM_MEMORY $1"

# PUF +++
fi
# PUF ---
echo "mbedTLS Build Complete."


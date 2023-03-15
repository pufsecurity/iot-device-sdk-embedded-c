# PUF +++
include puf_config.mk
# PUF ---

ifeq ($(IOTC_HOST_PLATFORM),Linux)
	# linux cross-compilation assumes tools downloaded and are on PATH

# PUF +++

ifeq ($(PUF_CROSS_COMPILE),YES)
    ifeq ($(CROSS_COMPILE_VER), ARM_10_3)
        IOTC_GCC_ARM_NONE_EABI_DOWNLOAD_FILE = ~/Downloads/gcc-arm-10.3-2021.07-x86_64-arm-none-linux-gnueabihf.tar.xz
        IOTC_GCC_ARM_NONE_EABI_PATH = ~/Downloads/gcc-arm-10.3-2021.07-x86_64-arm-none-linux-gnueabihf

        CC = $(IOTC_GCC_ARM_NONE_EABI_PATH)/bin/arm-none-linux-gnueabihf-gcc
        AR = $(IOTC_GCC_ARM_NONE_EABI_PATH)/bin/arm-none-linux-gnueabihf-ar
        IOTC_GCC_ARM_TOOLCHAIN_URL := https://developer.arm.com/-/media/Files/downloads/gnu-a/10.3-2021.07/binrel/gcc-arm-10.3-2021.07-x86_64-arm-none-linux-gnueabihf.tar.xz

    else
        IOTC_GCC_ARM_LINUX_EABI_PATH = ~/Downloads/gcc-linaro-6.2.1-2016.11-x86_64_arm-linux-gnueabihf
        IOTC_GCC_ARM_LINUX_EABI_DOWNLOAD_FILE = ~/Downloads/gcc-linaro-6.2.1-2016.11-x86_64_arm-linux-gnueabihf.tar.xz

        IOTC_GCC_ARM_TOOLCHAIN_URL := https://releases.linaro.org/components/toolchain/binaries/6.2-2016.11/arm-linux-gnueabihf/gcc-linaro-6.2.1-2016.11-x86_64_arm-linux-gnueabihf.tar.xz

        CC = $(IOTC_GCC_ARM_LINUX_EABI_PATH)/bin/arm-linux-gnueabihf-gcc
        AR = $(IOTC_GCC_ARM_LINUX_EABI_PATH)/bin/arm-linux-gnueabihf-ar

    endif


    #export PATH=$PATH:$(IOTC_GCC_ARM_NONE_EABI_PATH)/bin

    IOTC_BUILD_PRECONDITIONS := $(CC)
else
# PUF ---
	IOTC_GCC_ARM_NONE_EABI_DOWNLOAD_FILE = ~/Downloads/gcc-arm-none-eabi-5_4-2016q2-20160622-linux.tar.bz2
	IOTC_GCC_ARM_NONE_EABI_PATH = ~/Downloads/gcc-arm-none-eabi-5_4-2016q2

	CC = $(IOTC_GCC_ARM_NONE_EABI_PATH)/bin/arm-none-eabi-gcc
	AR = $(IOTC_GCC_ARM_NONE_EABI_PATH)/bin/arm-none-eabi-ar

	IOTC_GCC_ARM_TOOLCHAIN_URL := https://launchpad.net/gcc-arm-embedded/5.0/5-2016-q2-update/+download/gcc-arm-none-eabi-5_4-2016q2-20160622-linux.tar.bz2

	#export PATH=$PATH:$(IOTC_GCC_ARM_NONE_EABI_PATH)/bin

	IOTC_BUILD_PRECONDITIONS := $(CC)

# PUF +++
endif
# PUF ---

else ifeq ($(IOTC_HOST_PLATFORM),Darwin)
	# osx cross-compilation downloads arm-gcc

	IOTC_GCC_ARM_NONE_EABI_DOWNLOAD_FILE = ~/Downloads/gcc-arm-none-eabi-5_4-2016q2-20160622-mac.tar.bz2
	IOTC_GCC_ARM_NONE_EABI_PATH = ~/Downloads/gcc-arm-none-eabi-5_4-2016q2

	CC = $(IOTC_GCC_ARM_NONE_EABI_PATH)/bin/arm-none-eabi-gcc
	AR = $(IOTC_GCC_ARM_NONE_EABI_PATH)/bin/arm-none-eabi-ar

	IOTC_GCC_ARM_TOOLCHAIN_URL := https://launchpad.net/gcc-arm-embedded/5.0/5-2016-q2-update/+download/gcc-arm-none-eabi-5_4-2016q2-20160622-mac.tar.bz2

	IOTC_BUILD_PRECONDITIONS := $(CC)

else ifeq ($(IOTC_HOST_PLATFORM),Windows_NT)
	CC = arm-none-eabi-gcc
	AR = arm-none-eabi-ar
endif

$(IOTC_GCC_ARM_NONE_EABI_DOWNLOAD_FILE):
	@echo "IOTC ARM-GCC BUILD: downloading arm-gcc toolchain to file $(IOTC_GCC_ARM_NONE_EABI_DOWNLOAD_FILE)"
	@-mkdir -p $(dir $@)
	@curl -L -o $(IOTC_GCC_ARM_NONE_EABI_DOWNLOAD_FILE) $(IOTC_GCC_ARM_TOOLCHAIN_URL)


# PUF +++

ifeq ($(PUF_CROSS_COMPILE),YES)
ifeq ($(CROSS_COMPILE_VER), ARM_10_3)

$(CC): $(IOTC_GCC_ARM_NONE_EABI_DOWNLOAD_FILE)
	@echo "IOTC ARM-GCC BUILD: extracting arm-gcc toolchain"
	@tar -xf $(IOTC_GCC_ARM_NONE_EABI_DOWNLOAD_FILE) -C ~/Downloads
	@touch $@
	$@ --version

else

$(IOTC_GCC_ARM_LINUX_EABI_DOWNLOAD_FILE):
	@echo "IOTC ARM-GCC BUILD: downloading arm-gcc toolchain to file $(IOTC_GCC_ARM_LINUX_EABI_DOWNLOAD_FILE)"	
	@-mkdir -p $(dir $@)
	@curl -L -o $(IOTC_GCC_ARM_LINUX_EABI_DOWNLOAD_FILE) $(IOTC_GCC_ARM_TOOLCHAIN_URL)



$(CC): $(IOTC_GCC_ARM_LINUX_EABI_DOWNLOAD_FILE)
	@echo "IOTC ARM-GCC BUILD: extracting arm-gcc toolchain"
	@echo "GCC_DIR: $(GCC_DIR)"
	@echo "IOTC_GCC_ARM_LINUX_EABI_PATH: $(IOTC_GCC_ARM_LINUX_EABI_PATH)"
	@echo "CC: $(CC)"
	tar xf $(IOTC_GCC_ARM_LINUX_EABI_DOWNLOAD_FILE) -C ~/Downloads
#	tar xvfz $(IOTC_GCC_ARM_LINUX_EABI_DOWNLOAD_FILE) -C $(GCC_DIR) -P
	@touch $@
	$@ --version

endif
else
# PUF ---	

$(CC): $(IOTC_GCC_ARM_NONE_EABI_DOWNLOAD_FILE)
	@echo "IOTC ARM-GCC BUILD: extracting arm-gcc toolchain"
	@tar -xf $(IOTC_GCC_ARM_NONE_EABI_DOWNLOAD_FILE) -C ~/Downloads
	@touch $@
	$@ --version

# PUF +++
endif
# PUF ---	


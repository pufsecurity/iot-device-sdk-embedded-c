## Source
To get the source, clone from the `pufcc-dev` branch of the [PUFsecurity Google Cloud IoT
Device SDK for Embedded C GitHub
repository](https://github.com/pufsecurity/iot-device-sdk-embedded-c):

```
git clone -b pufcc-dev https://github.com/pufsecurity/iot-device-sdk-embedded-c --recurse-submodules
```
## Config
PUFSecurity related configs are put in puf_config.mk


## Build and Execute original client example (Not use PUFcc)
### Unset 'PUF' flag to not compile PUFcc related codes
- Set PUF=NO in pufs_config.mk

### Build on execution host (x86 or fpga)
- Set PUF_CROSS_COMPILE=NO in pufs_config.mk
- Build mbedtls/libiotc... libraries
```
# make clean is optional
make clean
make
```
- Build client iot example code
```
cd examples/iot_core_mqtt_client
make clean
make
```

## Build with cross-compiler
- Set PUF_CROSS_COMPILE=YES and CROSS_COMPILE_VER=ARM_6_2 in pufs_config.mk
- Build mbedtls/libiotc... libraries
- **Note** : The cross compile tool will be downloaded during compilation. 
   In the 1st build, the mbedtls build may by failed because the cross compile tool haven't be downloaed.
   Please rebuild (type 'make') after the tool has been downloaded.]
```
# make clean is optional
make clean
make
```
- Build client iot example code
```
cd examples/iot_core_mqtt_client
make clean
make
```


## Build libiotc library only
In iot-device-sdk-embedded-c folder
```
make libiotc
```

## Execute client example
- Make sure registry, device and topic are created in google iot core. The device keys are also created. 

- A pair of test keys are prepared for testing and located in iot-device-sdk-embedded-c/examples/iot_core_mqtt_client/ca_key.
(ec_private.pem and ec_public.pem)
These keys are for project "a-plus-project" registry "my-test2" and device "test2"

- In addition, the certificate for google MQTT server (root.pem) is also in iot-device-sdk-embedded-c/examples/iot_core_mqtt_client/ca_key.

- Run device test script
```
cd examples/iot_core_mqtt_client
./run_test.sh
```

- Content of test script run_test.sh
```
cd bin
./iot_core_mqtt_client_puf -p a-plus-project -d projects/a-plus-project/locations/asia-east1/registries/$REGISTRY_ID/devices/$DEVICE_ID -t /devices/$DEVICE_ID/events -e 5000
```

## Build and Execute client example with PUFcc (only cross-compilation is supported)
### Build
- Set PUF=YES in puf_config.mk
  (Define PUF will define PUF_CRYPTO automatically)

- Set PUF_CROSS_COMPILE=YES in pufs_config.mk to use cross-compiler

- Set PUF_CRYPTO_TLS=YES in pufs_config.mk if tls connection uses PUFcc crypto
  - Set enabled crypto alternative in [pufcc_mbedtls_accelerator_config.h](src/bsp/tls/mbedtls/pufcc_mbedtls/config/pufcc_mbedtls_accelerator_config.h)


- Build mbedtls/libiotc... libraries
```
# make clean is optional
make clean
make
```
- Build client iot example code
```
cd examples/iot_core_mqtt_client_puf
make clean
make
```

- Build libraries and example with one build script 
This build.sh will copy the necessary file (read_info.sh) for iot_core_mqtt_client_puf execution to bin folder after example code compliation.
```
./build.sh
```

## Enable Debug log
### MbedTLS debug log
- Set PUF_TLS_DEBUG=YES in pufs_config.mk \
The default debug log level is 3 ( DEBUG_LEVEL 3)

### BSP_IOTC debug log
- Set PUF_IOTC_DEBUG=YES in pufs_config.mk


## Enable PUFsecurity Demo log 
- Set PUF_DEMO_LOG=YES in pufs_config.mk \
When PUF_DEMO_LOG=YES, 
 - PUF_DEMO_LOG_TLS is defined in make\mt-config\mt-tls.mk (add to IOTC_BSP_TLS_BUILD_ARGS)
 - PUF_DEMO_LOG_MQTT is defined in makefile (add to IOTC_CONFIG_FLAGS)

## Scripts for Google IoT device init, run, and delete 
PUFsecurity provides bash scripts to init, run, and delete Google IoT device. \
For more information, see [examples/iot_core_mqtt_client_puf/README_GIOT_SCRIPT.md](examples/iot_core_mqtt_client_puf/README_GIOT_SCRIPT.md)


## Cross-compiler version

- gcc-linaro-6.2.1-2016.11-x86_64_arm-linux-gnueabihf.tar.xz (from below url)\
  https://releases.linaro.org/components/toolchain/binaries/6.2-2016.11/arm-linux-gnueabihf/gcc-linaro-6.2.1-2016.11-x86_64_arm-linux-gnueabihf.tar.xz \
  (gcc version 6.2.1 20161016 (Linaro GCC 6.2-2016.11))

# GIOT_SCRIPT
giot_script is the google iot device init/delete script, use PUFsecurity giot_util to generate key pair, and use gcloud to create device.

## auth

gcloud auth (service-account.json)
```
gcloud auth activate-service-account --key-file=/etc/puf/a.json
```

## Setup
1. Contact [PUFsecurity](https://www.pufsecurity.com/zh-hans/contact/) for the pufcc_giot_util binary.

2. Create a base folder (e.g., giot_demo) for giot_utils and pufcc_giot_util and iot_core_mqtt_client_puf binaries.

3. Enter the created base folder 
   - Create a bin folder in the base folder. 
   - Create an iot_core_mqtt_client_puf folder in the bin folder
   - Put pufcc_giot_util from PUFsecurity in the base folder.   
   - Put the generated bin folder in iot-device-sdk-embedded-c/examples/iot_core_mqtt_client_puf after compilation to base/iot_core_mqtt_client_puf.
   - An example of the file structure of the base folder 
   ```
   ├── bin
   │   ├── iot_core_mqtt_client_puf
   │   │   └── bin   
   │   │       ├── iot_core_mqtt_client_puf
   │   │       ├── read_info.sh
   │   │       └── roots.pem
   │   └── pufcc_giot_util
   └── giot_script
       ├── env.json
       ├── puf-device-delete
       ├── puf-device-init
       └── puf-device-mqtt
   ```

## Execution 
1. Enter base/giot_script folder.
2. Create env.json to define Google IoT environment.
```
{
    "registry":"c1-fpgacluster",
    "device":"pufsecurity",
    "topic":"c1-usage-topic",
    "subscriptions":"c1-usage-sub",
    "public_key":"certs/pub.pem"
}

```

2. IoT device init
```
./puf-device-init env.json
```

3. IoT device MQTT
```
./puf-device-mqtt env.json
```

4. IoT device delete (option).
```
./puf-device-delete env.json
```


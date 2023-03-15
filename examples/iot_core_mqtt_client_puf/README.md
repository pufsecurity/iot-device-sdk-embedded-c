# MQTT client example

This example uses the Google Cloud IoT Device SDK for Embedded C to connect a native Linux application to the [Google Cloud IoT Core MQTT bridge](https://cloud.google.com/iot/docs/how-tos/mqtt-bridge#iot-core-mqtt-auth-run-cpp).
In this example, pufcc crypto functions are used for sha256 and ecc signature generation.

## Getting started

1. Precondition \*.sh files in ./res/tls folder are executable and in linux line endings.
```
chmod +x *.sh
fromdos *.sh
```

2. Run `make` in the root directory of the repository.

3. From the root directory, generate the native example application.

```
cd examples/iot_core_mqtt_client_puf \
make
```
4. Copy ./iot_core_mqtt_client_puf to 7100 fpga board.

## Execution options

```
--project_id                : (p) Provide the project_id your device is registered in Cloud IoT Core.
--device_path               : (d) Provide the full path of your device.For example:
                                   projects/<project_id>/locations/<cloud_region>/registries/<registry_id>/devices/<device_id>
--publish_topic             : (t) The topic on which to subscribe.
--publish_message           : (m) The message to publish. A shell quoted string of characters.
--private_key_filename      : (f) The filename, including path from cwd,
                                   of the device identifying private_key. Defaults to: priv.bin
--jwt_expired_time          : (e) Set JWT expired time(secs). Defaults to 3600 secs
--iotc_puf_config_filename  : (c) Parse connection_timeout(Defaults:10), keepalive_timeout(Defaults:20),
                                   publish_period(Defaults:5), nonce_len(Defaults:16). Defaults to:config.txt
```


## Execution example

Run the following commands, substituting in your device and project information.

<pre>
make \
cd bin \
./iot_core_mqtt_client_puf -p <i><b>PROJECT_ID</b></i> -d projects/<i><b>PROJECT_ID</b></i>/locations/<i><b>REGION</b></i>/registries/<i><b>REGISTRY_ID</b></i>/devices/<i><b>DEVICE_ID</b></i> -t /devices/<i><b>DEVICE_ID</b></i>/events -e 60 -c config.txt
</pre>

## Note

1. Need to set PUF_CRYPTO=YES in [iot-device-sdk-embedded-c/puf_config.mk](puf_config.mk)
2. Sample config.txt
```
{
    #Maximum time interval the client will wait for the network connection to the MQTT server to be established(0~60)
    connection_timeout = 25,
    #Defines the maximum time interval between messages sent or received.(0~65535)
    keepalive_timeout = 10,
    #Random num added to JWT for unique, we can adjust its length(0-150)
    nonce_len = 8,
    #Create a timed task to publish every x seconds(1-3600)
    publish_period = 7

}
```

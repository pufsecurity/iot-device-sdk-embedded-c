#!/bin/bash
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

REGISTRY_ID=my-test2
DEVICE_ID=test2
PROJECT=a-plus-project

#./iot_core_mqtt_client -p PROJECT_ID -d projects/PROJECT_ID/locations/REGION/registries/REGISTRY_ID/devices/DEVICE_ID -t /devices/DEVICE_ID/state

cd bin
#./iot_core_mqtt_client -p a-plus-project -d projects/a-plus-project/locations/asia-east1/registries/my-test2/devices/test2 -m "test" -t /devices/test2/state -f ../ca_key/ec_private.pem 2>&1 | tee log.txt

./iot_core_mqtt_client -p a-plus-project -d projects/a-plus-project/locations/asia-east1/registries/my-test2/devices/test2 -m "test" -t /devices/test2/state -f ../ca_key/ec_private.pem

#gdb --args ./iot_core_mqtt_client -p a-plus-project -d projects/a-plus-project/locations/asia-east1/registries/my-test2/devices/test2 -t /devices/test2/my-test

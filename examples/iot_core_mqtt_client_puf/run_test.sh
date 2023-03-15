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

REGISTRY_ID=c1-fpgacluster
DEVICE_ID=puf_000a35001e88_4768418ee32618c6ddce00bbcb67f896c3fc0087639219c7ca3240949be47a37
PROJECT=a-plus-project


cd bin

#./iot_core_mqtt_client_puf -p a-plus-project -d projects/a-plus-project/locations/asia-east1/registries/$REGISTRY_ID/devices/$DEVICE_ID -m "test" -t /devices/$DEVICE_ID/state


./iot_core_mqtt_client_puf -p a-plus-project -d projects/a-plus-project/locations/asia-east1/registries/$REGISTRY_ID/devices/$DEVICE_ID -t /devices/$DEVICE_ID/events -e 5000

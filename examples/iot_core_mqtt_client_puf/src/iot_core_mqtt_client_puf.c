/* Copyright 2018-2020 Google LLC
 *
 * This is part of the Google Cloud IoT Device SDK for Embedded C.
 * It is licensed under the BSD 3-Clause license; you may not use this file
 * except in compliance with the License.
 *
 * You may obtain a copy of the License at:
 *  https://opensource.org/licenses/BSD-3-Clause
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * This example application connects to the GCP IoT Core Service with
 * a credentials you mus specify on the command line.   It then publishes
 * test messages to a topic that you also must specify.
 *
 * Run the example with the flag --help for more information.
 */

/***********************************************************************************
 * 
 *  Copyright (c) 2022-2023, PUFsecurity
 *  All rights reserved.
 *  
 *  Redistribution and use in source and binary forms, with or without modification, 
 *  are permitted provided that the following conditions are met:
 *  
 *  1. Redistributions of source code must retain the above copyright notice, this 
 *     list of conditions and the following disclaimer.
 *  
 *  2. Redistributions in binary form must reproduce the above copyright notice, 
 *     this list of conditions and the following disclaimer in the documentation 
 *     and/or other materials provided with the distribution.
 *  
 *  3. Neither the name of PUFsecurity nor the names of its contributors may be 
 *     used to endorse or promote products derived from this software without 
 *     specific prior written permission.
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ¡§AS IS¡¨ AND 
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
 *  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
 *  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY 
 *  OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, 
 *  EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 **************************************************************************************/


#include <iotc.h>
#include "../../common/src/commandline.h"
#include "../../common/src/example_utils.h"


#include <iotc_error.h>
#include <iotc_jwt.h>
#include <stdio.h>

#include "pufcc_sec.h"
#include "iotc_bsp_time.h"
#include "puf_cfg.h"
#include "puf_info.h"

extern int jwt_exp_time;
extern int connection_timeout;
extern int keepalive_timeout;
extern const char *iotc_puf_config_filename;


/* Application variables. */
iotc_crypto_key_data_t iotc_connect_private_key_data;
char ec_private_key_pem[PRIVATE_KEY_BUFFER_SIZE] = {0};
iotc_context_handle_t iotc_context = IOTC_INVALID_CONTEXT_HANDLE;

/*  -main-
    The main entry point for this example binary.

    For information on creating the credentials required for your device to the
    GCP IoT Core Service during development then please see the service's
    quick start guide. */

int main(int argc, char *argv[])
{
    if (0 != iotc_puf_read_command_line(argc, argv))
    {
        return -1;
    }

    if (iotc_puf_config_filename != NULL)
    {
        puf_cfg_read_config(iotc_puf_config_filename);
    }

    pufcc_sec_module_init();
    puf_sec_enroll();

    /* This example assumes the private key to be used to  sign the IoT Core
       Connect JWT credential is a PEM encoded ES256 private key,
       and passes it IoT Core Device Client functions as a byte array.
       There are other ways of passing key data to the client, including
       passing Key Slot IDs for using keys stored in secure elements.
       For more information, please see the iotc_crypto_key_data_t
       documentation in include/iotc_types.h. */

    printf("[IoTC] Generate private key for google iot device.\n");
    if (0 != puf_sec_gen_ecdsa_priv_key())
    {
        printf("puf_generate_key error\n");
    }

    //Private key slot for import wrapped key
    uint8_t priv_slot_idx = 15; //PRK_1(private key pos)

    /* Format the key type descriptors so the client understands
       which type of key is being reprenseted. In this case, a PEM encoded
       byte array of a ES256 key. */
    iotc_connect_private_key_data.crypto_key_signature_algorithm =
        IOTC_CRYPTO_KEY_SIGNATURE_ALGORITHM_ES256;
    iotc_connect_private_key_data.crypto_key_union_type =
        IOTC_CRYPTO_KEY_UNION_TYPE_SLOT_ID;
    iotc_connect_private_key_data.crypto_key_union.key_slot.slot_id =
        priv_slot_idx;

    /* Initialize iotc library and create a context to use to connect to the
     * GCP IoT Core Service. */
    const iotc_state_t error_init = iotc_initialize();

    if (IOTC_STATE_OK != error_init)
    {
        printf(" iotc failed to initialize, error: %d\n", error_init);
        return -1;
    }

    /*  Create a connection context. A context represents a Connection
        on a single socket, and can be used to publish and subscribe
        to numerous topics. */
    iotc_context = iotc_create_context();
    if (IOTC_INVALID_CONTEXT_HANDLE >= iotc_context)
    {
        printf(" iotc failed to create context, error: %d\n", -iotc_context);
        return -1;
    }

    /*  Queue a connection request to be completed asynchronously.
        The 'on_connection_state_changed' parameter is the name of the
        callback function after the connection request completes, and its
        implementation should handle both successful connections and
        unsuccessful connections as well as disconnections. */



    /* Generate the client authentication JWT, which will serve as the MQTT
     * password. */
    char jwt[IOTC_JWT_SIZE] = {0};
    size_t bytes_written = 0;

    char *nonce = NULL;
    nonce = calloc(nonce_len, sizeof(char));
    printf("\n[IoTC] Generate %d bytes nonce for JWT token\n", nonce_len / 2);
    puf_get_nonce(nonce);
    iotc_state_t state = iotc_puf_create_iotcore_jwt(
                             iotc_project_id,
                             /*jwt_expiration_period_sec=*/jwt_exp_time, &iotc_connect_private_key_data, jwt,
                             IOTC_JWT_SIZE, &bytes_written, nonce);

    free(nonce);
#ifdef PUF_PRINT_JWT_EXP
    printf("EXP= %d\n\n", jwt_exp_time);
#endif

    if (IOTC_STATE_OK != state)
    {
        printf("iotc_create_iotcore_jwt returned with error: %ul : %s\n", state,
               iotc_get_state_string(state));
        return -1;
    }

    iotc_connect(iotc_context, /*username=*/NULL, /*password=*/jwt,
                 /*client_id=*/iotc_device_path, (uint16_t)connection_timeout,
                 (uint16_t)keepalive_timeout, &on_connection_state_changed);


    /* The IoTC Client was designed to be able to run on single threaded devices.
       As such it does not have its own event loop thread. Instead you must
       regularly call the function iotc_events_process_blocking() to process
       connection requests, and for the client to regularly check the sockets for
       incoming data. This implementation has the loop operate endlessly. The loop
       will stop after closing the connection, using iotc_shutdown_connection() as
       defined in on_connection_state_change logic, and exit the event handler
       handler by calling iotc_events_stop(); */
    iotc_events_process_blocking();

    /*  Cleanup the default context, releasing its memory */
    iotc_delete_context(iotc_context);

    /* Cleanup internal allocations that were created by iotc_initialize. */
    iotc_shutdown();

    return 0;
}

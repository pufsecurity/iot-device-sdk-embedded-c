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
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND 
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


/*!*************************************************************************************
 *
 *@file        pufcc_mbedtls.c
 *
 *@brief       Pufcc mbedtls API
 *
 *@copyright   2022-2023 PUFsecurity 
 *
 ***************************************************************************************/

#include <stdio.h>
#include <string.h>
#include "pufs_rt.h"
#include "pufcc_mbedtls.h"


/*****************************************************************************
 * Define
 ****************************************************************************/
#define PUFCC_TLS_ERR_INPUT_PARAMETER_ERROR     -0x0001
#define PUFCC_TLS_SUCCESS                             0

#define RNG_READ_BLOCK_SIZE                          16

/*****************************************************************************
 * Macro Define
 ****************************************************************************/

/*****************************************************************************
 * Variable Define
 ****************************************************************************/

#ifdef MBEDTLS_PUFCC_TLS_RNG_ALT

/*****************************************************************************/
/**
 * @fn    pufcc_mbedtls_trng_random
 * @brief pufcc mbedtls get random from true random number generator ()
 *
 * @return  0 or PUFCC_TLS_ERR_INPUT_PARAMETER_ERROR
 *
 ****************************************************************************/
int pufcc_mbedtls_trng_random( void *p_rng, unsigned char *output, size_t output_len )
{

    int ret = PUFCC_TLS_SUCCESS;
    unsigned char *p = output;
    size_t use_len = 0;
    uint8_t tmp_buf[RNG_READ_BLOCK_SIZE];

    if ((output_len <= 0) || (p == NULL))
    {
        return PUFCC_TLS_ERR_INPUT_PARAMETER_ERROR;
    }

    PUFCC_MBEDTLS_UNUSED(p_rng);
    PUFCC_LOG_FUNC("pufcc_mbedtls_trng_random - request %d bytes\n", output_len);

    if (p_rng != NULL)
    {
        PUFCC_LOG_INF("pufcc_mbedtls_trng_random p_rng != NULL p_rng:%p\n", p_rng);
    }

    PUFCC_LOG_FUNC("pufcc_mbedtls_trng_random output:%p, output_len:%d\n", output, output_len);

    memset(tmp_buf, 0, RNG_READ_BLOCK_SIZE);

    while ( output_len > 0 )
    {
        pufs_rand(tmp_buf, RNG_READ_BLOCK_SIZE / 4);

        use_len = ( output_len > RNG_READ_BLOCK_SIZE ) ? RNG_READ_BLOCK_SIZE :
                  output_len;
        /*
         * Copy random block to destination
         */
        memcpy( p, tmp_buf, use_len );
        p += use_len;
        output_len -= use_len;
    }

    return ( ret );
}
#endif /* MBEDTLS_PUFCC_TLS_RNG_ALT */



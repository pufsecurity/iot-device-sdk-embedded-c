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
 *@file        iotc_bsp_crypto_pufsecurity.c
 *
 *@brief       iotc_bsp function implementation of pufsecurity secure module
 *
 *@copyright   2022-2023 PUFsecurity 
 *
 ***************************************************************************************/


#include "sys/types.h"
#include "iotc_bsp_crypto.h"
#include "iotc_bsp_mem.h"
#include "iotc_debug.h"
#include "iotc_macros.h"



#include "mbedtls/base64.h"
#include "pufs_hmac.h" //pufs_hash
#include "pufs_ecc.h"  //pufs_ecdsa_sig_st
#include "pufs_ecp.h"  //pufs_ecp_ecdsa_sign_dgst


#include <stdio.h>

#define IOTC_CHECK_DEBUG_FORMAT(cnd, fmt, ...) \
  if ((cnd)) {                                 \
    iotc_debug_format(fmt, __VA_ARGS__);       \
    goto err_handling;                         \
  }



static iotc_bsp_crypto_state_t _iotc_bsp_base64_encode(
    unsigned char* dst_string, size_t dst_string_size, size_t* bytes_written,
    const uint8_t* src_buf, size_t src_buf_size) 
{
    const int result = mbedtls_base64_encode(
        dst_string, dst_string_size, bytes_written, src_buf, src_buf_size);
    switch (result) 
    {
        case 0:
            return IOTC_BSP_CRYPTO_STATE_OK;
        
        case MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL:
            return IOTC_BSP_CRYPTO_BUFFER_TOO_SMALL_ERROR;
        
        default:
            return IOTC_BSP_CRYPTO_BASE64_ERROR;
    }
}

iotc_bsp_crypto_state_t iotc_bsp_base64_encode_urlsafe(
    unsigned char* dst_string, size_t dst_string_size, size_t* bytes_written,
    const uint8_t* src_buf, size_t src_buf_size) 
{
    const iotc_bsp_crypto_state_t b64_result = _iotc_bsp_base64_encode(
        dst_string, dst_string_size, bytes_written, src_buf, src_buf_size);
  
    if (b64_result != IOTC_BSP_CRYPTO_STATE_OK) 
    {
        return b64_result;
    }
  
    // Translate to url-safe alphabet
    size_t i = 0;
    for (; i < *bytes_written; i++) 
    {
        switch (dst_string[i]) 
        {
            case '+':
                dst_string[i] = '-';
                break;
            
            case '/':
                dst_string[i] = '_';
                break;
            
            default:
                break;
        }
    }
  
    return IOTC_BSP_CRYPTO_STATE_OK;
}


iotc_bsp_crypto_state_t iotc_bsp_sha256(uint8_t* dst_buf_32_bytes,
                                        const uint8_t* src_buf,
                                        uint32_t src_buf_size) 
{
    pufs_status_t check = SUCCESS;
    pufs_dgst_st md;
    memset(&md, 0, sizeof(pufs_dgst_st));
    md.dlen = 32; 
    
    if ((dst_buf_32_bytes == NULL) || (src_buf == NULL) || (src_buf_size == 0))
    {
        iotc_debug_logger("HASH input parameter errors !\n");            
        goto err_handling;   
    }

    if ((check = pufs_hash(&md, src_buf, src_buf_size, SHA_256)) != SUCCESS)
    {  
        iotc_debug_printf("HASH pufs_hash return failed [%d]\n", check);            
        goto err_handling;          
    }
  
    memcpy(dst_buf_32_bytes, &(md.dgst), 32);
    
    return IOTC_BSP_CRYPTO_STATE_OK;
  
err_handling:

    return IOTC_BSP_CRYPTO_SHA256_ERROR;
}

iotc_bsp_crypto_state_t iotc_bsp_ecc(
    const iotc_crypto_key_data_t* private_key_data, uint8_t* dst_buf,
    size_t dst_buf_size, size_t* bytes_written, const uint8_t* src_buf,
    size_t src_buf_size) 
{

    pufs_status_t rt = SUCCESS;
    pufs_ecdsa_sig_st sig;
    pufs_dgst_st md;
    uint8_t slot_id;  

    if (NULL == private_key_data || NULL == dst_buf || NULL == bytes_written ||
        NULL == src_buf) 
    {
        return IOTC_BSP_CRYPTO_INVALID_INPUT_PARAMETER_ERROR;
    }
        
    if (IOTC_CRYPTO_KEY_UNION_TYPE_SLOT_ID !=
        private_key_data->crypto_key_union_type) 
    {
        iotc_debug_format(
            "Cryptoauthlib impl of iotc_bsp_ecc() only supports slot ID keys. "
            "Got key type %d",
            private_key_data->crypto_key_union_type);
    
        return IOTC_BSP_CRYPTO_ERROR;
    }
      
    IOTC_CHECK_DEBUG_FORMAT(64 > dst_buf_size,
                            "dst_buf_size must be >= %zu: was %zu", 64,
                            dst_buf_size);
  
    IOTC_CHECK_DEBUG_FORMAT(32 != src_buf_size,
                            "src_buf_size must be %zu: was %zu", 32,
                            src_buf_size);

    memset(&md, 0, sizeof(pufs_dgst_st));
    memset(&sig, 0, sizeof(pufs_ecdsa_sig_st));        

    //slot format : pufs_ka_slot_t (PRK_1)
    slot_id = private_key_data->crypto_key_union.key_slot.slot_id;
    md.dlen = src_buf_size;
    memcpy(md.dgst, src_buf, src_buf_size);
              
    // input message is 32 bytes, output is 64 bytes
    // two 32 byte integers build up a JWT ECC signature: r and s
    // see https://tools.ietf.org/html/rfc7518#section-3.4
    // dst_buf : r (32 bytes) || s (32 bytes)
    rt = pufs_ecp_ecdsa_sign_dgst(&sig, md, PRKEY, slot_id, NULL);
  
    //IOTC_CHECK_DEBUG_FORMAT(SUCCESS != rt, "pufs_sign returned %d", rt);
    if(SUCCESS != rt){
        printf("pufs_sign returned %d\n", rt);
        goto err_handling;
    }

    memcpy(dst_buf, sig.r, sig.qlen);
    memcpy(dst_buf + sig.qlen, sig.s, sig.qlen);
    *bytes_written = 2* sig.qlen;
    
    return IOTC_BSP_CRYPTO_STATE_OK;

err_handling:    
    return IOTC_BSP_CRYPTO_ERROR;

}

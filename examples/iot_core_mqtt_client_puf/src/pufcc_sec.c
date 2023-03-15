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
 *@file        pufcc_sec.c
 *
 *@brief       Pufcc secure module related function
 *
 *@copyright   2022-2023 PUFsecurity 
 *
 ***************************************************************************************/

#include <stdio.h>
#include <string.h>
#include "pufs_memory_map.h"
#include "pufs_common.h"
#include "pufs_crypto.h"
#include "pufs_sp38a.h"
#include "pufs_sp38c.h"
#include "pufs_sp38d.h"
#include "pufs_sp38e.h"
#include "pufs_cmac.h"
#include "pufs_ecp.h"
#include "pufs_kdf.h"
#include "pufs_sp90a.h"
#include "pufs_rt.h"
#include "pufs_ka.h"

#include "pufcc_sec.h"
#include "pufs_ka_internal.h" //for ka_regs
#include "../../common/src/commandline.h"




/*****************************************************************************
 * Define
 ****************************************************************************/
#define UID_SLOT                 PUFSLOT_0

//Used Key slot define
#define PRIV_KEY_SLOT            PRK_1
#define PUF_SLOT_FOR_KPRV_GEN    PUFSLOT_1   //Slot used for static private key generation
#define PUF_SLOT_FOR_WRAP        PUFSLOT_2   //Slot used for wrap private key

#define KEK_LEN                  (32*8)       //in bits
#define KEK_KEY_SLOT             SK256_1
#define KDK_LEN                  (32*8)       //in bits
#define WRAP_KEY_LEN             (32*8)       //in bits



//Key slot information bit
#define KEY_VALID_BITMASK        0x00000001 //BIT 0, 
#define KEY_VALID_FLAG           0x01UL     // 0: null

#define KEY_ORIGIN_BITMASK       0x0000000E //BIT [3:1]
#define KEY_LEN_BITMASK          0x00007FF0 //BIT [14:4]
#define KEY_LEN_BIT_SHIFT        0x04 //BIT [14:4]

// PK REGISTER BIT MASKS
#define PK_KEY_VAILD_MASK               0x00000001
#define PK_KEY_ORIGIN_MASK              0x0000000e
#define PK_KEY_SIZE_MASK                0x00007ff0

#define PIF_00_ENROLL_BITS              16
#define PTM_STATUS_BUSY_MASK            0x00000001
extern int nonce_len;

const char *iotc_private_key_filename;


/*****************************************************************************
 * Macro Define
 ****************************************************************************/
#define GET_PRIV_KEY_SLOT_IDX(slot) \
    (((slot >=PRK_0) && (slot <= PRK_2))? (slot-PRK_0) : (0xFE))

#define GET_SK256_KEY_SLOT_IDX(slot) \
    (((slot >=SK256_0) && (slot <= SK256_3))? ((slot-SK256_0)<<1) : (0xFE))

#define GET_SK128_KEY_SLOT_IDX(slot) \
    (((slot >=SK128_0) && (slot <= SK128_7))? ((slot-SK128_0)<<1) : (0xFE))


/*****************************************************************************
 * Variable Define
 ****************************************************************************/
extern struct pufs_rt_regs *rt_regs;


/**
 * @fn    giot_init_pufs_sec_module_init
 * @brief pufsecurity module initilization
 */
void pufcc_sec_module_init()
{
    pufs_module_init(PUFIOT_ADDR_START, PUFIOT_MAP_SIZE);
    pufs_dma_module_init(DMA_ADDR_OFFSET);
    pufs_rt_module_init(RT_ADDR_OFFSET);
    pufs_ka_module_init(KA_ADDR_OFFSET);
    pufs_kwp_module_init(KWP_ADDR_OFFSET);
    pufs_crypto_module_init(CRYPTO_ADDR_OFFSET);
    pufs_hmac_module_init(HMAC_HASH_ADDR_OFFSET);
    pufs_sp38a_module_init(SP38A_ADDR_OFFSET);
    pufs_sp38c_module_init(SP38C_ADDR_OFFSET);
    pufs_sp38d_module_init(SP38D_ADDR_OFFSET);
    pufs_sp38e_module_init(SP38E_ADDR_OFFSET);
    pufs_cmac_module_init(CMAC_ADDR_OFFSET);
    pufs_kdf_module_init(KDF_ADDR_OFFSET);
    pufs_pkc_module_init(PKC_ADDR_OFFSET);
    pufs_drbg_module_init(SP90A_ADDR_OFFSET);

}

static bool check_enable(uint32_t value)
{
    value &= 0xF;
    switch (value)
    {
        case PUFRT_VALUE4(0x0):
        case PUFRT_VALUE4(0x1):
        case PUFRT_VALUE4(0x2):
        case PUFRT_VALUE4(0x4):
            return true;
        default:
            return false;
    }
}

void print_value(uint8_t *ptr_to_print, uint32_t size)
{
    uint32_t i;
    uint8_t *tmpPtr = ptr_to_print;
    for (i = 0; i < size; i++, tmpPtr++)
    {
        printf("0x%02x ", *tmpPtr);
        if ((i % 16) == 15)
        {
            printf("\n");
        }
    }
    printf("\n");
}

/**
 * @fn    puf_sec_enroll
 * @brief check puf enroll status and enroll puf if puf has not been enrolled.
 *
 */

void puf_sec_enroll(void)
{
    if (check_enable(rt_regs->pif[0] >> PIF_00_ENROLL_BITS))
    {
        printf("[PUFS] PUF Already enroll\n");
        return;
    }
    printf("PUF_ENROLL\n");
    rt_regs->puf_enroll = 0xa7;
    //wait PUFrt busy status
    while ((rt_regs->status & PTM_STATUS_BUSY_MASK) != 0);
}


/*****************************************************************************/
/**
 * @fn    puf_sec_gen_ecdsa_priv_key
 * @brief puf module generate key
 *
 * @return  0
 *
 ****************************************************************************/
int puf_sec_gen_ecdsa_priv_key(void)
{
    pufs_status_t check = SUCCESS;
    pufs_ka_slot_t prvslot = PRK_1;
    pufs_rt_slot_t pufslot = PUF_SLOT_FOR_KPRV_GEN;  //PUFSLOT_1
    const char *salt = "pufsecurity salt";
    pufs_uid_st uid;
    uint32_t status = 0;
    uint8_t  pk_idx = GET_PRIV_KEY_SLOT_IDX(PRIV_KEY_SLOT);

    printf("       ");
    printf("puf_generate_private_key (ECDSA P256)\n");


    //check private key slot status
    status = ka_regs->pk[pk_idx];

    if ((status & KEY_VALID_BITMASK) ==  KEY_VALID_FLAG )
    {
        check = pufs_clear_key(PRKEY, PRIV_KEY_SLOT, 256);

        if (check != SUCCESS)
        {
            printf("Private key clear failed (err:%d) !!\n", check);
            return -1;
        }
        status = ka_regs->pk[pk_idx];

    }

    //1. Generate Private Key
    pufs_ecp_set_curve_byname(NISTP256);

    memset(&uid, 0, sizeof(uid));

    pufs_get_uid(&uid, UID_SLOT);
    check = pufs_ecp_gen_sprk(prvslot, pufslot, (uint8_t *)salt, 16, (uint8_t *)uid.uid, UIDLEN, HASH_DEFAULT);

    status = ka_regs->pk[pk_idx];

    if (check != SUCCESS)
    {
        printf("Private key generation failed (err:%d) !!\n", check);
        return -1;
    }

    status = ka_regs->pk[pk_idx];

    return 0;

}

/*****************************************************************************/
/**
 * @fn    uint8_to_char
 * @brief uint8 to char
 * @param[in]  str       Pointer output string
 * @param[in]  pos       char position in the output string
 * @param[in]  num       input number
 * @return  void
 *
 ****************************************************************************/
void uint8_to_char(char *str, int pos, int num)
{
    switch (num)
    {
        case 0 :
            str[pos] = '0';
            break;
        case 1 :
            str[pos] = '1';
            break;
        case 2 :
            str[pos] = '2';
            break;
        case 3 :
            str[pos] = '3';
            break;
        case 4 :
            str[pos] = '4';
            break;
        case 5 :
            str[pos] = '5';
            break;
        case 6 :
            str[pos] = '6';
            break;
        case 7 :
            str[pos] = '7';
            break;
        case 8 :
            str[pos] = '8';
            break;
        case 9 :
            str[pos] = '9';
            break;
        case 10 :
            str[pos] = 'A';
            break;
        case 11 :
            str[pos] = 'B';
            break;
        case 12 :
            str[pos] = 'C';
            break;
        case 13 :
            str[pos] = 'D';
            break;
        case 14 :
            str[pos] = 'E';
            break;
        case 15 :
            str[pos] = 'F';
            break;
        default:
            break;
    }

}

/*****************************************************************************/
/**
 * @fn         puf_get_nonce
 * @brief      get nonce with nonce_len
 * @param[out] nonce             Pointer of nonce string
 * @return     void
 *
 ******************************************************************************/
void puf_get_nonce(char *nonce)
{
    uint8_t rand_num[nonce_len + 4];

    printf("       puf_get_nonce\n");
    pufs_rand(rand_num, (nonce_len + 3) / 4);

    for (int i = 0; i < nonce_len / 2; i++)
    {
        uint8_to_char(nonce, 2 * i, (int)rand_num[i] / 16);
        uint8_to_char(nonce, 2 * i + 1, (int)rand_num[i] % 16);
    }
}


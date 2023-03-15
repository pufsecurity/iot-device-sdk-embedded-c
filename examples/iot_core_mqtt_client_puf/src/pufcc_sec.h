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
 *@file        pufcc_sec.h
 *
 *@brief       pufcc secure module related functions
 *
 *@copyright   2022-2023 PUFsecurity 
 *
 ***************************************************************************************/


#ifndef __PUFCC_SEC_H__
#define __PUFCC_SEC_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "pufs_common.h"
#include "pufs_ecp.h" //pufs_ec_point_st


/*****************************************************************************
 * Enumerations
 ****************************************************************************/


/*****************************************************************************
 * Structure definition
 ****************************************************************************/
struct pufs_rt_regs
{
    volatile uint32_t pif[64];
    uint32_t _pad1[64];
    volatile uint32_t ptr[16];
    volatile uint32_t ptc[16];
    volatile uint32_t ptm[2];
    uint32_t _pad2[6];
    volatile uint32_t rn;
    volatile uint32_t rn_status;
    volatile uint32_t healthcfg;
    volatile uint32_t feature;
    volatile uint32_t interrupt;
    volatile uint32_t otp_psmsk[2];
    volatile uint32_t puf_psmsk; // puf_psmsk & lck_psmsk
    volatile uint32_t version;
    volatile uint32_t status;
    volatile uint32_t cfg;
    volatile uint32_t set_pin;
    volatile uint32_t auto_repair;
    volatile uint32_t ini_off_chk;
    volatile uint32_t repair_pgn;
    volatile uint32_t repair_reg;
    volatile uint32_t puf_qty_chk;
    volatile uint32_t puf_enroll;
    volatile uint32_t puf_zeroize;
    volatile uint32_t set_flag;
    volatile uint32_t otp_zeroize;
    uint32_t _pad3[3];
    volatile uint32_t puf[64];
    volatile uint32_t otp[256];
};

/*****************************************************************************
 * API functions
 ****************************************************************************/


/*****************************************************************************
 * Function Declaration
 ****************************************************************************/
void pufcc_sec_module_init(void);
void uint8_to_char(char *str, int pos, int num);
void puf_sec_enroll(void);
void puf_get_nonce(char *nonce);
int puf_sec_gen_ecdsa_priv_key(void);



#ifdef __cplusplus
} // closing brace for extern "C"
#endif

#endif /* __PUFCC_SEC_H__ */


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
 *@file        puf_cfg.c
 *
 *@brief       PUFsecurity coonfig related functions
 *
 *@copyright   2022-2023 PUFsecurity 
 *
 ***************************************************************************************/

#include <stdio.h>
#include <string.h>
#include "puf_cfg.h"
#include "../../common/src/commandline.h"

#include<stdlib.h>
#include<unistd.h>

/*****************************************************************************
 * Define
 ****************************************************************************/
//#define CONFIG_DEBUG    //check parse contect

/*****************************************************************************
 * Macro Define
 ****************************************************************************/




/*****************************************************************************
 * Variable Define
 ****************************************************************************/
extern int jwt_exp_time;
extern int nonce_len;
extern int connection_timeout;
extern int keepalive_timeout;
extern int publish_period;




/*****************************************************************************/
/**
 * @fn    puf_cfg_read_config
 * @brief Read config file
 *
 * @return  0
 *
 ****************************************************************************/
int puf_cfg_read_config(const char *filename)
{

    FILE *fp = NULL;
    char buff[255];
    int num;
    fp = fopen(filename, "r");
    fscanf(fp, "%s", buff);
    while (strcmp(buff, "}") != 0)
    {
        fscanf(fp, "%s = %d", buff, &num);
        //printf("%s %d\n", buff,num );
        if (strcmp(buff, "connection_timeout") == 0)
        {
            connection_timeout = num;
        }
        else if (strcmp(buff, "nonce_len") == 0)
        {
            nonce_len = num;
        }
        else if (strcmp(buff, "keepalive_timeout") == 0)
        {
            keepalive_timeout = num;
        }
        else if (strcmp(buff, "publish_period") == 0)
        {
            publish_period = num;
        }
    }
#ifdef CONFIG_DEBUG
    printf("connection_timeout= %d,\nkeepalive_timeout= %d,\npublish_period= %d,\nnonce_len=%d\n", connection_timeout,
           keepalive_timeout, publish_period, nonce_len);
#endif
    fclose(fp);
    return 0;

}

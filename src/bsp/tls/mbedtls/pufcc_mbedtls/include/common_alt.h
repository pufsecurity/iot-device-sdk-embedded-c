/*
 * Copyright (c) 2022-2023, PUFsecurity. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef COMMON_ALT_H
#define COMMON_ALT_H

#include <stdio.h>
#define LOG_LEVEL   LOG_LEVEL_INFO
//#define LOG_WRAP_INFO  //If wapper info log enabled

#include "pufcc_mbedtls_pufs_log.h"

#ifdef MBEDTLS_CONFIG_FILE
#include MBEDTLS_CONFIG_FILE
#endif

#define MBEDTLS_ERR_PUFCC_HW_ACCEL_FAILED   -0x0037 /**< PUFcc hardware accelerator failed */


#define PUFCC_LOG_PRINT(level, str, ...) PRINT("[%s] "str, level, ## __VA_ARGS__)

#if LOG_LEVEL <= LOG_LEVEL_INFO
#define PUFCC_LOG_INF(...)     PUFCC_LOG_PRINT("INF", __VA_ARGS__)
#define PUFCC_LOG_FUNC(...)    PUFCC_LOG_PRINT("PUFS", __VA_ARGS__)
#else
#define PUFCC_LOG_FUNC(...)
#define PUFCC_LOG_INF(...)
#endif


#if LOG_LEVEL <= LOG_LEVEL_DEBUG
#define PUFCC_LOG_DBG(...)     PUFCC_LOG_PRINT("DBG", __VA_ARGS__)
#else
#define PUFCC_LOG_DBG(...)
#endif

#if LOG_LEVEL <= LOG_LEVEL_WARN
#define PUFCC_LOG_WRN(...)     PUFCC_LOG_PRINT("WRN", __VA_ARGS__)
#else
#define PUFCC_LOG_WRN(...)
#endif

#if LOG_LEVEL <= LOG_LEVEL_WARN
#define PUFCC_LOG_ERR(...)     PUFCC_LOG_PRINT("ERR", __VA_ARGS__)
#else
#define PUFCC_LOG_ERR(...)
#endif


#ifdef LOG_WRAP_INFO
#define PUFCC_LOG_WRAP_FUNC(...)    PUFCC_LOG_INF(__VA_ARGS__)
#else
#define PUFCC_LOG_WRAP_FUNC(...)
#endif



#define PUFCC_INFO_RET(...) \
    do { \
        LOG_INFO(__VA_ARGS__); \
        return 0; \
    } while (0)

#define PUFCC_ERR_RET(...) \
    do { \
        LOG_ERROR(__VA_ARGS__); \
        return MBEDTLS_ERR_PUFCC_HW_ACCEL_FAILED; \
    } while (0)

#define PUFCC_CALL_ERR(ret, func, ...) \
    do { \
        if ((ret = func(__VA_ARGS__)) != SUCCESS) \
            PUFCC_ERR_RET("%s: %d", #func, ret); \
    } while (0)

#define PUFCC_CALL_WARN(ret, func, ...) \
    do { \
        if ((ret = func(__VA_ARGS__)) != SUCCESS) \
            LOG_WARN("%s: %d", #func, ret); \
    } while (0)


//For unused variable compile warning
#define PUFCC_MBEDTLS_UNUSED(x) (void)(x)

#endif /* COMMON_ALT_H */

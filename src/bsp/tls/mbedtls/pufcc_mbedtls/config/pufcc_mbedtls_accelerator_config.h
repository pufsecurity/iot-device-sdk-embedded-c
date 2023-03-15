/*
 * Copyright (c) 2022-2023, PUFsecurity. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef PUFCC_MBEDTLS_ACCELERATOR_CONF_H
#define PUFCC_MBEDTLS_ACCELERATOR_CONF_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* RNG Config */
#undef MBEDTLS_ENTROPY_NV_SEED
#undef MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES

//#define MBEDTLS_ENTROPY_HARDWARE_ALT
//#define MBEDTLS_ENTROPY_FORCE_SHA256

//////* Main Config */

#define MBEDTLS_SHA256_ALT
#define MBEDTLS_ECDSA_VERIFY_ALT
#define MBEDTLS_ECDH_GEN_PUBLIC_ALT
#define MBEDTLS_ECDH_COMPUTE_SHARED_ALT
#define MBEDTLS_GCM_ALT

// TLS PRF and CALC functions alternative
#define MBEDTLS_PUFCC_TLS_PRF_CALC_ALT

//TLS RNG Alternative
#define MBEDTLS_PUFCC_TLS_RNG_ALT




#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* PUFCC_MBEDTLS_ACCELERATOR_CONF_H */

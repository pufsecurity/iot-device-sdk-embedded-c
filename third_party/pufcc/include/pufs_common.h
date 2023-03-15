/**
 * @file      pufs_common.h
 * @brief     PUFsecurity common API interface
 * @copyright 2022-2023 PUFsecurity
 */
/* THIS SOFTWARE IS SUPPLIED BY PUFSECURITY ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. TO THE FULLEST
 * EXTENT ALLOWED BY LAW, PUFSECURITY'S TOTAL LIABILITY ON ALL CLAIMS IN
 * ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES,
 * IF ANY, THAT YOU HAVE PAID DIRECTLY TO PUFSECURITY FOR THIS SOFTWARE.
 */

#ifndef __PUFS_COMMON_H__
#define __PUFS_COMMON_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <inttypes.h>

/*****************************************************************************
 * Macros
 ****************************************************************************/
/**
 * @brief Convert number of bits to number of bytes
 *
 * @param[in] bits  Number of bits.
 * @return          Number of bytes.
 */
#define b2B(bits) (((bits) + 7) / 8)
/**
 * @brief Convert number of bytes to number of bits
 *
 * @param[in] len  Number of bytes.
 * @return         Number of bits.
 */
#define B2b(len) (8 * (len))
/**
 * @brief Convert test cases parameters
 *
 * @param[in] type  Type of test cases.
 * @param[in] var   Test case variable.
 * @return          num, var
 */
#define TCPARAM(type, var) (sizeof(var) / sizeof(type)), (var)
/**
 * @brief Block size in bytes of block cipher algorithms
 */
#define BC_BLOCK_SIZE 16

/*****************************************************************************
 * Enumerations
 ****************************************************************************/
/**
 * @brief Status code
 */
typedef enum {
    SUCCESS,     ///< Success.
    E_ALIGN,     ///< Address alignment mismatch.
    E_OVERFLOW,  ///< Space overflow.
    E_UNDERFLOW, ///< Size too small.
    E_INVALID,   ///< Invalid argument.
    E_BUSY,      ///< Resource is occupied.
    E_UNAVAIL,   ///< Resource is unavailable.
    E_FIRMWARE,  ///< Firmware error.
    E_VERFAIL,   ///< Invalid public key or digital signature.
    E_ECMPROG,   ///< Invalid ECC microprogram.
    E_DENY,      ///< Access denied.
    E_UNSUPPORT, ///< Not support.
    E_INFINITY,  ///< Point at infinity.
    E_ERROR,     ///< Unspecific error.
} pufs_status_t;
/**
 * @brief Block cipher algorithm.
 */
typedef enum {
    AES,        ///< AES
    SM4,        ///< SM4
    CHACHA,     ///< CHACHA
    N_CIPHER_T, // keep in the last one
} pufs_cipher_t;

/*****************************************************************************
 * Structures
 ****************************************************************************/
/**
 * @brief Maximum message digest length in bytes.
 */
#ifndef DLEN_MAX
#define DLEN_MAX 64
#endif
/**
 * @brief Message digest structure.
 */
typedef struct {
    uint32_t dlen;                ///< Current message digest length in bytes.
    uint8_t dgst[DLEN_MAX]; ///< Message digest.
} pufs_dgst_st;

/*****************************************************************************
 * API functions
 ****************************************************************************/

/**
 * @brief Initialize PUFs module
 *
 * @param[in] base_addr  base address of PUFs memory map
 * @param[in] size  total size of PUFs memory map
 */
pufs_status_t pufs_module_init(uintptr_t base_addr, size_t size);

/**
 * @brief Release PUFs module
 *
 */
void pufs_release(void);

/**
 * @brief Return status message
 *
 */
char *pufs_strstatus(pufs_status_t status);

#ifdef __cplusplus
} // closing brace for extern "C"
#endif

#endif /*__PUFS_COMMON_H__*/

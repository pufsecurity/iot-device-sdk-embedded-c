/**
 * @file      pufs_dma.h
 * @brief     PUFsecurity DMA interface
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

#ifndef __PUFS_DMA_H__
#define __PUFS_DMA_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "pufs_common.h"

typedef enum {
    ALGO_TYPE_HKDF = 0,
    ALGO_TYPE_HMAC,
    ALGO_TYPE_CMAC,
    ALGO_TYPE_KLB = 4,
    ALGO_TYPE_SM2ENC = 7,
    ALGO_TYPE_SP38A,
    ALGO_TYPE_GCM,
    ALGO_TYPE_XTS,
    ALGO_TYPE_CCM,
    ALGO_TYPE_CHACHA,
    ALGO_TYPE_CYPT_REG_IO,
    ALGO_TYPE_KEY_EXPORT,
    ALGO_TYPE_NONE,
} pufs_algo_type_t;

/*****************************************************************************
 * Structs
 ****************************************************************************/
/**
 * @brief Memory attributes for DMA
 */
typedef struct dma_dsc_attrs
{
    bool    fix_read_addr; ///< Enable dma fixed read address (read output data)
    bool    fix_write_addr; ///< Enable dma fixed write address (write input data)
    uint8_t read_protect; ///< Memory protection of read address for DMA
    uint8_t write_protect; ///< Memory protection of write address for DMA
} pufs_dma_dsc_attr_st;

/**
 * @brief SGDMA descriptor structure. 
 */
typedef struct dma_sg_desc
{
    uintptr_t             write_addr; ///< Address of input data
    uintptr_t             read_addr; ///< Address of output result
    uint32_t              length; ///< The length of data
    pufs_dma_dsc_attr_st  attr; ///< Memory attributes
} pufs_dma_sg_desc_st;

/*****************************************************************************
 * API functions
 ****************************************************************************/
/**
 * @brief Initialize DMA module
 *
 * @param[in] dma_offset   DMA offset of memory map
 */
pufs_status_t pufs_dma_module_init(uintptr_t dma_offset);

/**
 * @brief Release DMA module
 */
void pufs_dma_module_release(void);
/**
 * @brief Setup DMA attributes for normal DMA mode.
 * 
 * @param[in] attr DMA attribute
 */
void pufs_dma_set_dsc_attr(pufs_dma_dsc_attr_st *attr);
/**
 * @brief Initialize SGDMA feature
 * 
 * @param[in] base_addr a base address for SGDMA descriptor's memory area
 */
pufs_status_t pufs_dma_sg_start(void);
/**
 * @brief Release allocated memory for SGDMA
 */
void pufs_dma_sg_release(void);
/*****************************************************************************
 * Test functions
 ****************************************************************************/
#ifndef DOXYGEN
pufs_status_t pufs_dump_rand_dma(uint8_t *rand, uint32_t len, bool entropy);
pufs_status_t pufs_dma_read_write(uint8_t *out, uint32_t outlen,
                                  const uint8_t *data, const uint32_t data_length,
                                  pufs_dma_dsc_attr_st *attr);
pufs_status_t pufs_dma_read_write_sg( pufs_dma_sg_desc_st *descs);
// a helper function for testing units to read the output from the fixed address.
void pufs_dma_read_output(uint8_t* addr, uint32_t len);

#endif /* DOXYGEN */
#ifdef __cplusplus
} // closing brace for extern "C"
#endif

#endif /*__PUFS_DMA_H__*/

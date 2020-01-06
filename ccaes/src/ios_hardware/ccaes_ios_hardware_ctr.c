/*
 * Copyright (c) 2017,2018 Apple Inc. All rights reserved.
 *
 * corecrypto Internal Use License Agreement
 *
 * IMPORTANT:  This Apple corecrypto software is supplied to you by Apple Inc. ("Apple")
 * in consideration of your agreement to the following terms, and your download or use
 * of this Apple software constitutes acceptance of these terms.  If you do not agree
 * with these terms, please do not download or use this Apple software.
 *
 * 1.    As used in this Agreement, the term "Apple Software" collectively means and
 * includes all of the Apple corecrypto materials provided by Apple here, including
 * but not limited to the Apple corecrypto software, frameworks, libraries, documentation
 * and other Apple-created materials. In consideration of your agreement to abide by the
 * following terms, conditioned upon your compliance with these terms and subject to
 * these terms, Apple grants you, for a period of ninety (90) days from the date you
 * download the Apple Software, a limited, non-exclusive, non-sublicensable license
 * under Apple’s copyrights in the Apple Software to make a reasonable number of copies
 * of, compile, and run the Apple Software internally within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software; provided
 * that you must retain this notice and the following text and disclaimers in all
 * copies of the Apple Software that you make. You may not, directly or indirectly,
 * redistribute the Apple Software or any portions thereof. The Apple Software is only
 * licensed and intended for use as expressly stated above and may not be used for other
 * purposes or in other contexts without Apple's prior written permission.  Except as
 * expressly stated in this notice, no other rights or licenses, express or implied, are
 * granted by Apple herein.
 *
 * 2.    The Apple Software is provided by Apple on an "AS IS" basis.  APPLE MAKES NO
 * WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION THE IMPLIED WARRANTIES
 * OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, REGARDING
 * THE APPLE SOFTWARE OR ITS USE AND OPERATION ALONE OR IN COMBINATION WITH YOUR PRODUCTS,
 * SYSTEMS, OR SERVICES. APPLE DOES NOT WARRANT THAT THE APPLE SOFTWARE WILL MEET YOUR
 * REQUIREMENTS, THAT THE OPERATION OF THE APPLE SOFTWARE WILL BE UNINTERRUPTED OR
 * ERROR-FREE, THAT DEFECTS IN THE APPLE SOFTWARE WILL BE CORRECTED, OR THAT THE APPLE
 * SOFTWARE WILL BE COMPATIBLE WITH FUTURE APPLE PRODUCTS, SOFTWARE OR SERVICES. NO ORAL
 * OR WRITTEN INFORMATION OR ADVICE GIVEN BY APPLE OR AN APPLE AUTHORIZED REPRESENTATIVE
 * WILL CREATE A WARRANTY.
 *
 * 3.    IN NO EVENT SHALL APPLE BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT, INCIDENTAL
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) ARISING
 * IN ANY WAY OUT OF THE USE, REPRODUCTION, COMPILATION OR OPERATION OF THE APPLE
 * SOFTWARE, HOWEVER CAUSED AND WHETHER UNDER THEORY OF CONTRACT, TORT (INCLUDING
 * NEGLIGENCE), STRICT LIABILITY OR OTHERWISE, EVEN IF APPLE HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * 4.    This Agreement is effective until terminated. Your rights under this Agreement will
 * terminate automatically without notice from Apple if you fail to comply with any term(s)
 * of this Agreement.  Upon termination, you agree to cease all use of the Apple Software
 * and destroy all copies, full or partial, of the Apple Software. This Agreement will be
 * governed and construed in accordance with the laws of the State of California, without
 * regard to its choice of law rules.
 *
 * You may report security issues about Apple products to product-security@apple.com,
 * as described here:  https://www.apple.com/support/security/.  Non-security bugs and
 * enhancement requests can be made via https://bugreport.apple.com as described
 * here: https://developer.apple.com/bug-reporting/
 *
 * EA1350
 * 10/5/15
 */
#include <corecrypto/cc_config.h>

#if CCAES_MUX
#include "ccaes_ios_hardware.h"
#include "cc_debug.h"
#include "cc_macros.h"
#include "ccmode_internal.h"

int
ccaes_ios_hardware_ctr_init(const struct ccmode_ctr *mode, ccctr_ctx *key,
                            size_t rawkey_len, const void *rawkey,const void *iv)
{
    int status = 0;
    ccaes_hardware_aes_ctx_t ctx = (ccaes_hardware_aes_ctx_t) key;
    status = ccaes_ios_hardware_common_init(CCAES_HW_CTR,ctx,rawkey_len,rawkey);
    cc_require(status==0,errOut);
    status = ccaes_ios_hardware_ctr_setctr(mode, key, iv);
    ctx->padLength=0;
errOut:
    return status;
}

int
ccaes_ios_hardware_ctr_setctr(const struct ccmode_ctr *mode CC_UNUSED, ccctr_ctx *key, const void *ctr)
{
    ccaes_hardware_aes_ctx_t ctx = (ccaes_hardware_aes_ctx_t) key;
    CC_MEMCPY(&ctx->ctrBytes[0], ctr, sizeof(ctx->ctrBytes));
    // Discard the remaining pad if any
    ctx->padLength=0;
    cc_clear(sizeof(ctx->padBytes),ctx->padBytes);
    return 0;
}

int
ccaes_ios_hardware_ctr_crypt(ccctr_ctx *ctrctx, size_t nbytes,
                             const void *in, void *out) {

    const int operation = CCAES_HW_CTR | CCAES_HW_ENCRYPT;
    ccaes_hardware_aes_ctx_t ctx = (ccaes_hardware_aes_ctx_t)ctrctx;
    // First, process from the precomputed pad (key stream)
    size_t read_from_pad_nbytes = CC_MIN(nbytes,ctx->padLength);
    if (read_from_pad_nbytes>sizeof(ctx->padBytes)) {
        read_from_pad_nbytes=0; // Defensive check, should not happen.
    }
    cc_xor(read_from_pad_nbytes,out,in,&ctx->padBytes[sizeof(ctx->padBytes)-ctx->padLength]);
    ctx->padLength -= read_from_pad_nbytes;

    // Move pointers forward
    in = (const uint8_t *)in + read_from_pad_nbytes;
    out = (uint8_t *)out + read_from_pad_nbytes;
    nbytes -= read_from_pad_nbytes;

    // Process whole blocks
    size_t process_blocks = nbytes / CCAES_BLOCK_SIZE;
    process_blocks = ccaes_ios_hardware_crypt(operation,ctx,ctx->ctrBytes,in,out,process_blocks);

    // Process what is left
    size_t process_blocks_nbytes = (process_blocks*CCAES_BLOCK_SIZE);
    cc_assert(process_blocks_nbytes<=nbytes);
    
    // Move pointers forward
    in = (const uint8_t *)in + process_blocks_nbytes;
    out = (uint8_t *)out + process_blocks_nbytes;
    nbytes -= process_blocks_nbytes;

    // If more to process, we use the pad buffer
    cc_assert(ccaes_hardware_block_threshold*CCAES_BLOCK_SIZE<=sizeof(ctx->padBytes));
    if (nbytes>0) {
        // Fill up pad buffer
        cc_assert(ctx->padLength==0);
        cc_assert((sizeof(ctx->padBytes) % CCAES_BLOCK_SIZE) == 0);
        cc_zero(sizeof(ctx->padBytes),ctx->padBytes);
        process_blocks=ccaes_ios_hardware_crypt(operation,ctx,ctx->ctrBytes,ctx->padBytes,ctx->padBytes,(sizeof(ctx->padBytes)/CCAES_BLOCK_SIZE));

        ctx->padLength = process_blocks*CCAES_BLOCK_SIZE;

        // Process from pad buffer
        read_from_pad_nbytes = CC_MIN(nbytes,ctx->padLength);
        cc_xor(read_from_pad_nbytes,out,in,&ctx->padBytes[sizeof(ctx->padBytes)-ctx->padLength]);
        ctx->padLength -= read_from_pad_nbytes;
        nbytes -= read_from_pad_nbytes;
    }
    return (nbytes==0)?0:CCMODE_INTERNAL_ERROR;
}



#endif /* CCAES_MUX */


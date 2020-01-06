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

#include "ccaes_ios_mux_ctr.h"
#include "ccaes_vng_ctr.h"

const struct ccmode_ctr *small_ctr_crypt = NULL; // Set at runtime
const struct ccmode_ctr *large_ctr_crypt = &ccaes_ios_hardware_ctr_crypt_mode;

static int
ccaes_ios_mux_crypt_init(const struct ccmode_ctr *ctr CC_UNUSED, ccctr_ctx *key,
                               size_t rawkey_len, const void *rawkey,const void *iv)
{
    int rc;
    
    ccctr_ctx *smallctx = key;
    ccctr_ctx *largectx = (ccctr_ctx *) ((uint8_t *)key + small_ctr_crypt->size);
    
    rc =  small_ctr_crypt->init(small_ctr_crypt, smallctx, rawkey_len, rawkey, iv);
    rc |= large_ctr_crypt->init(large_ctr_crypt, largectx, rawkey_len, rawkey, iv);
    
    return rc;
}

// This routine now calls the ios hardware routine directly so it can use the number of
// blocks processed in cases of failure to open the device or partial decryption.
static int
ccaes_ios_mux_ctr_crypt(ccctr_ctx *ctrctx, size_t nbytes, const void *in, void *out)
{
    if (0 == nbytes) return 0;
    ccctr_ctx *smallctx = ctrctx;
    ccctr_ctx *largectx = (ccctr_ctx *) ((uint8_t *)ctrctx + small_ctr_crypt->size);
    // First use the existing pad
    size_t  pad_offset = CCMODE_CTR_KEY_PAD_OFFSET(smallctx);
    uint8_t *pad = (uint8_t *)CCMODE_CTR_KEY_PAD(smallctx);
    while ((nbytes>0)&&(pad_offset<CCAES_BLOCK_SIZE)) {
        *(uint8_t*)out++ = *(const uint8_t*)in++ ^ pad[pad_offset++];
        --nbytes;
    };
    CCMODE_CTR_KEY_PAD_OFFSET(smallctx) = pad_offset;

    // Use HW if over the cutover
    if((nbytes > AES_CTR_SWHW_CUTOVER*CCAES_BLOCK_SIZE)) {
        ccaes_hardware_aes_ctx_const_t ctx = (ccaes_hardware_aes_ctx_const_t) largectx;
        size_t processed = ccaes_ios_hardware_crypt(CCAES_HW_ENCRYPT|CCAES_HW_CTR, ctx, (uint8_t *)CCMODE_CTR_KEY_CTR(smallctx), in, out, nbytes/CCAES_BLOCK_SIZE);
        nbytes -= (processed*CCAES_BLOCK_SIZE);
        in = (uint8_t*)in + (processed*CCAES_BLOCK_SIZE);
        out = (uint8_t*)out + (processed*CCAES_BLOCK_SIZE);
    }

    // Finish with the SW
    if(nbytes) {
        small_ctr_crypt->ctr(smallctx, nbytes, in, out);
    }
    
    return 0;
}


const struct ccmode_ctr *ccaes_ios_mux_ctr_crypt_mode()
{
    static struct ccmode_ctr ccaes_ios_mux_ctr_crypt_mode;
    static struct ccmode_ctr sw_mode;
    ccaes_vng_ctr_crypt_mode_setup(&sw_mode);
    small_ctr_crypt = &sw_mode;

    // Check support and performance of HW
    if (!ccaes_ios_hardware_enabled(CCAES_HW_DECRYPT|CCAES_HW_CTR)) return small_ctr_crypt;

    ccaes_ios_mux_ctr_crypt_mode.size = small_ctr_crypt->size + large_ctr_crypt->size + CCAES_BLOCK_SIZE;
    ccaes_ios_mux_ctr_crypt_mode.block_size = 1;
    ccaes_ios_mux_ctr_crypt_mode.ecb_block_size = CCAES_BLOCK_SIZE;
    ccaes_ios_mux_ctr_crypt_mode.init = ccaes_ios_mux_crypt_init;
    ccaes_ios_mux_ctr_crypt_mode.setctr = ccmode_ctr_setctr;
    ccaes_ios_mux_ctr_crypt_mode.ctr = ccaes_ios_mux_ctr_crypt;
    ccaes_ios_mux_ctr_crypt_mode.custom = NULL;
    return &ccaes_ios_mux_ctr_crypt_mode;
}


#endif /* CCAES_MUX */

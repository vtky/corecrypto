/*
 * Copyright (c) 2010,2011,2014,2015,2016,2017,2018 Apple Inc. All rights reserved.
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

#include <corecrypto/cc_runtime_config.h>
#include "ccmode_internal.h"

int ccmode_gcm_encrypt(ccgcm_ctx *key, size_t nbytes, const void *in, void *out)
{
    const uint8_t *ptext = in;
    uint8_t *ctext = out;

    uint8_t *X = CCMODE_GCM_KEY_X(key);
    uint8_t *pad = CCMODE_GCM_KEY_PAD(key);

    // X and the pad are always in sync with regards to offsets
    uint32_t Xpad_nbytes = _CCMODE_GCM_KEY(key)->text_nbytes % CCGCM_BLOCK_NBYTES;
    uint32_t Xpad_nbytes_needed = CCGCM_BLOCK_NBYTES - Xpad_nbytes;

    ccmode_gcm_aad_finalize(key);
    cc_require(_CCMODE_GCM_KEY(key)->state == CCMODE_GCM_STATE_TEXT, callseq_out);
    cc_require(UINT64_MAX - _CCMODE_GCM_KEY(key)->text_nbytes >= nbytes, input_out);
    cc_require(_CCMODE_GCM_KEY(key)->text_nbytes + nbytes <= CCGCM_TEXT_MAX_NBYTES, input_out);

    // finish a partial block, if possible
    if (Xpad_nbytes > 0 && nbytes >= Xpad_nbytes_needed) {
        cc_xor(Xpad_nbytes_needed, ctext, ptext, pad + Xpad_nbytes);
        cc_xor(Xpad_nbytes_needed, X + Xpad_nbytes, X + Xpad_nbytes, ctext);
        ccmode_gcm_mult_h(key, X);

        nbytes -= Xpad_nbytes_needed;
        ptext += Xpad_nbytes_needed;
        ctext += Xpad_nbytes_needed;
        _CCMODE_GCM_KEY(key)->text_nbytes += Xpad_nbytes_needed;
        Xpad_nbytes = 0;

        ccmode_gcm_update_pad(key);
    }

    // process full blocks, if any
    if (Xpad_nbytes == 0) {
        while (nbytes >= CCGCM_BLOCK_NBYTES) {
            xor_128bits(ctext, ptext, pad);
            xor_128bits(X, X, ctext);
            ccmode_gcm_mult_h(key, X);

            nbytes -= CCGCM_BLOCK_NBYTES;
            ptext += CCGCM_BLOCK_NBYTES;
            ctext += CCGCM_BLOCK_NBYTES;
            _CCMODE_GCM_KEY(key)->text_nbytes += CCGCM_BLOCK_NBYTES;

            ccmode_gcm_update_pad(key);
        }
    }

    // process the remainder
    if (nbytes > 0) {
        cc_xor(nbytes, ctext, ptext, pad + Xpad_nbytes);
        cc_xor(nbytes, X + Xpad_nbytes, X + Xpad_nbytes, ctext);

        _CCMODE_GCM_KEY(key)->text_nbytes += nbytes;
    }

    return 0;

 callseq_out:
    return CCMODE_INVALID_CALL_SEQUENCE;

 input_out:
    return CCMODE_INVALID_INPUT;
}

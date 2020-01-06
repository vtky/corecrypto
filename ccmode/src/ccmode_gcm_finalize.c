/*
 * Copyright (c) 2011,2015,2016,2018 Apple Inc. All rights reserved.
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

#include "ccmode_internal.h"

int ccmode_gcm_finalize(ccgcm_ctx *key, size_t tag_nbytes, void *tag)
{
    uint8_t *X = CCMODE_GCM_KEY_X(key);
    uint8_t *pad = CCMODE_GCM_KEY_PAD(key);
    uint8_t out_tag[16];
    int rc = 0;
    
    ccmode_gcm_aad_finalize(key);
    cc_require(_CCMODE_GCM_KEY(key)->state == CCMODE_GCM_STATE_TEXT, errOut);
    
    if (_CCMODE_GCM_KEY(key)->text_nbytes % CCGCM_BLOCK_NBYTES > 0) {
        ccmode_gcm_mult_h(key, X);
    }
    
    uint64_t aad_nbits = _CCMODE_GCM_KEY(key)->aad_nbytes * 8;
    uint64_t text_nbits = _CCMODE_GCM_KEY(key)->text_nbytes * 8;
    
    // briefly repurposing the pad to hold the length block
    CC_STORE64_BE(aad_nbits, pad);
    CC_STORE64_BE(text_nbits, pad + 8);
    xor_128bits(X, X, pad);
    ccmode_gcm_mult_h(key, X);
    
    /* encrypt original counter */
    CCMODE_GCM_KEY_ECB(key)->ecb(CCMODE_GCM_KEY_ECB_KEY(key), 1,
                                 CCMODE_GCM_KEY_Y_0(key),
                                 pad);
    
    xor_128bits(out_tag, X, pad);
    
    tag_nbytes = CC_MIN(tag_nbytes, sizeof out_tag); //make sure we don't go out of bound
    
    if (_CCMODE_GCM_ECB_MODE(key)->encdec == CCMODE_GCM_DECRYPTOR) {
        rc = cc_cmp_safe(tag_nbytes, out_tag, tag) == 0 ? 0 : CCMODE_INTEGRITY_FAILURE;
    }
    
    //this should be removed for CCMODE_GCM_DECRYPTOR
    //it is here to keep compatibility with the previous usage that
    //returned tag on decryption by mistake
    CC_MEMCPY(tag, out_tag, tag_nbytes);
    
    _CCMODE_GCM_KEY(key)->state = CCMODE_GCM_STATE_FINAL;

    return rc;
errOut:
    return CCMODE_INVALID_CALL_SEQUENCE;
}
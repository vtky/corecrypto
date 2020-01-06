/*
 * Copyright (c) 2015,2016,2017,2018 Apple Inc. All rights reserved.
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

#include "corecrypto/fipspost_trace.h"

int ccgcm_one_shot(const struct ccmode_gcm *mode,
                             size_t key_nbytes, const void *key,
                             size_t iv_nbytes, const void *iv,
                             size_t adata_nbytes, const void *adata,
                             size_t nbytes, const void *in, void *out,
                             size_t tag_nbytes, void *tag)
{
    FIPSPOST_TRACE_EVENT;

    int rc = 0;

    ccgcm_ctx_decl(mode->size, ctx);
    rc=ccgcm_init (mode, ctx, key_nbytes   ,key); cc_require(rc==0, errOut);
    rc=ccgcm_set_iv(mode, ctx, iv_nbytes ,iv); cc_require(rc==0, errOut);
    rc=ccgcm_aad     (mode, ctx, adata_nbytes ,adata); cc_require(rc==0, errOut);
    rc=ccgcm_update  (mode, ctx, nbytes    , in, out); cc_require(rc==0, errOut);
    rc=ccgcm_finalize(mode, ctx, tag_nbytes   ,tag); cc_require(rc==0, errOut);

errOut:
    ccgcm_ctx_clear(mode->size, ctx);
    return rc;

}


//ccgcm_one_shot_legacy() is created because in the previous implementation of aes-gcm
//set_iv() could be skipped.
//In the new version of aes-gcm set_iv() cannot be skipped and IV length cannot
//be zero, as specified in FIPS.
//do not call ccgcm_one_shot_legacy() in any new application
int ccgcm_set_iv_legacy(const struct ccmode_gcm *mode, ccgcm_ctx *key, size_t iv_nbytes, const void *iv)
{
    int rc = -1;

    if(iv_nbytes == 0 || iv == NULL){
        /* must be in IV state */
        cc_require(_CCMODE_GCM_KEY(key)->state == CCMODE_GCM_STATE_IV, errOut); /* CRYPT_INVALID_ARG */
        
        // this is the net effect of setting IV to the empty string
        cc_zero(CCGCM_BLOCK_NBYTES, CCMODE_GCM_KEY_Y(key));
        ccmode_gcm_update_pad(key);
        cc_zero(CCGCM_BLOCK_NBYTES, CCMODE_GCM_KEY_Y_0(key));
        
        _CCMODE_GCM_KEY(key)->state = CCMODE_GCM_STATE_AAD;
        rc = 0;
    }else
        rc = ccgcm_set_iv(mode, key, iv_nbytes, iv);

errOut:
    return rc;
}

int ccgcm_one_shot_legacy(const struct ccmode_gcm *mode,
                              size_t key_nbytes, const void *key,
                              size_t iv_nbytes, const void *iv,
                              size_t adata_nbytes, const void *adata,
                              size_t nbytes, const void *in, void *out,
                              size_t tag_nbytes, void *tag)
{
    int rc = 0;

    ccgcm_ctx_decl(mode->size, ctx);
    rc=ccgcm_init (mode, ctx, key_nbytes   ,key); cc_require(rc==0, errOut);
    rc=ccgcm_set_iv_legacy (mode, ctx, iv_nbytes ,iv); cc_require(rc==0, errOut);
    rc=ccgcm_aad     (mode, ctx, adata_nbytes ,adata); cc_require(rc==0, errOut);
    rc=ccgcm_update  (mode, ctx, nbytes    , in, out); cc_require(rc==0, errOut);
    rc=ccgcm_finalize(mode, ctx, tag_nbytes   ,tag);  cc_require(rc==0, errOut);

errOut:
    ccgcm_ctx_clear(mode->size, ctx);
    return rc;
}


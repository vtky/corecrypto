/*
 * Copyright (c) 2016,2017,2018 Apple Inc. All rights reserved.
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

#include <corecrypto/ccec_priv.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccn.h>
#include <corecrypto/cczp.h>
#include <corecrypto/ccrng_drbg.h>
#include <corecrypto/ccrng_sequence.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/cc_macros.h>
#include "cc_debug.h"

int ccec_generate_key_deterministic(ccec_const_cp_t cp,
                                    size_t entropy_len,         const uint8_t *entropy,
                                    struct ccrng_state *rng, // For masking and signature
                                    uint32_t flags,
                                    ccec_full_ctx_t key)
{
    int result=CCEC_GENERATE_KEY_DEFAULT_ERR;

    ccec_ctx_init(cp,key);
    cc_unit *tmp=ccec_ctx_x(key);

    //==========================================================================
    // Key generation
    //==========================================================================

    if ((CCEC_GENKEY_DETERMINISTIC_SECBKP&flags)==CCEC_GENKEY_DETERMINISTIC_SECBKP) {
        struct ccrng_sequence_state seq_rng;
        // Discard some bytes to be compatible with previous behavior of corecrypto
        // functions
        size_t discarded_len=ccn_sizeof(ccec_cp_prime_bitlen(cp)-1);
        entropy += discarded_len;
        entropy_len -= discarded_len;
        // Retry takes a non deterministic number of byte, to reduce the probability
        // of failure, we need extra bytes
        cc_require_action(entropy_len>=10*(ccn_sizeof(ccec_cp_order_bitlen(cp))),errOut,result=CCERR_OUT_OF_ENTROPY);
        cc_require((result = ccrng_sequence_non_repeat_init(&seq_rng,entropy_len, entropy))==0,errOut);
        cc_require((result = ccec_generate_scalar_fips_retry(cp,
                                                             (struct ccrng_state*)&seq_rng,
                                                             ccec_ctx_k(key),tmp))==0,errOut);
    }
    else if ((CCEC_GENKEY_DETERMINISTIC_FIPS&flags)==CCEC_GENKEY_DETERMINISTIC_FIPS) {
        // Use entropy directly in the extrabits method, requires more bytes
        cc_require((result = ccec_generate_scalar_fips_extrabits(cp,
                                                                 entropy_len, entropy,
                                                                 ccec_ctx_k(key),tmp))==0,errOut);
    }
    // Use entropy with the legacy method, to reconstruct previously generated
    // keys
    else if ((CCEC_GENKEY_DETERMINISTIC_LEGACY&flags)==CCEC_GENKEY_DETERMINISTIC_LEGACY) {
        cc_require((result = ccec_generate_scalar_legacy(cp,
                                                         entropy_len, entropy,
                                                         ccec_ctx_k(key)))==0,errOut);
    }
    // Use entropy as done in the PKA
    else if ((CCEC_GENKEY_DETERMINISTIC_PKA&flags)==CCEC_GENKEY_DETERMINISTIC_PKA) {
        cc_require((result = ccec_generate_scalar_pka(cp,
                                                         entropy_len, entropy,
                                                         ccec_ctx_k(key),tmp))==0,errOut);
    } else {
        result=CCEC_GENERATE_NOT_SUPPORTED;
        goto errOut;
    }

    //==========================================================================
    // Calculate the public key for k
    //==========================================================================
    cc_require(((result=ccec_make_pub_from_priv(cp, rng,ccec_ctx_k(key),NULL,ccec_ctx_pub(key)))==0),errOut);

    //==========================================================================
    // Transform the key to support compact export/import format
    //==========================================================================
    if ((CCEC_GENKEY_DETERMINISTIC_COMPACT&flags)==CCEC_GENKEY_DETERMINISTIC_COMPACT) {
        cc_require(((result=ccec_compact_transform_key(key))==0),errOut);
    }

    //==========================================================================
    // Pairwise consistency check
    //==========================================================================
    result = ccec_pairwise_consistency_check(key, rng) ? 0 : CCEC_GENERATE_KEY_CONSISTENCY;
#if CCEC_DEBUG
    if (result) {
        uint8_t computed_x963_full_key[ccec_x963_export_size(1,ccec_ctx_pub(key))];
        ccec_x963_export(1, computed_x963_full_key, key);
        cc_print("exported_key: ",sizeof(computed_x963_full_key),computed_x963_full_key);
    }
#endif
errOut:
    return result;
}




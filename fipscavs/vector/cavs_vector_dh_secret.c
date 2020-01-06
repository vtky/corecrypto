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

#include "cavs_common.h"

#include "cavs_vector_dh_secret.h"

#include <corecrypto/ccdh.h>
#include <corecrypto/ccsha2.h>

int cavs_vector_dh_secret(
        size_t p_len, const uint8_t *p,
        size_t g_len, const uint8_t *g,
        size_t q_len, const uint8_t *q,
        size_t y_len, const uint8_t *y,
        size_t xiut_len, const uint8_t *xiut,       /* Only for Validity tests. */
        size_t yiut_len, const uint8_t *yiut,       /* Only for Validity tests. */
        uint8_t *out_y, uint8_t *out_hash)
{
    cc_size n = ccn_nof(2048);
    size_t s = ccn_sizeof_n(n);
    ccdh_gp_decl(s, gp);

    ccdh_full_ctx_decl(s, key);
    ccdh_pub_ctx_decl(s, pub_key);

    size_t secret_len = s;
    uint8_t secret[secret_len];
    uint8_t hash[CCSHA256_OUTPUT_SIZE];

    /* Initialize the group. */
    if (ccdh_init_gp_from_bytes(gp, n, p_len, p, g_len, g, q_len, q, 0) != 0) {
        errorf("Unable to initialize gp");
        return CAVS_STATUS_FAIL;
    }

    if (out_hash == NULL) {
        return (int)ccdh_ccn_size(gp);
    }

    /* Create the key. */
    if (xiut_len > 0 && yiut_len > 0) {
        /* Validity tests. */
        if (ccdh_import_full(gp, xiut_len, xiut, yiut_len, yiut, key) != 0) {
            errorf("unable to import");
            return CAVS_STATUS_FAIL;
        }
    } else {
        /* Functional tests. */
        if (ccdh_generate_key(gp, ccrng(NULL), key) != 0) {
            errorf("unable to generate");
            return CAVS_STATUS_FAIL;
        }
    }

    if (ccdh_import_pub(gp, y_len, y, pub_key) != 0) {
        errorf("unable to import");
        return CAVS_STATUS_FAIL;
    }

    /* Compute the shared secret. */
    if (ccdh_compute_shared_secret(key, pub_key, &secret_len, secret, ccrng(NULL)) != 0) {
        errorf("unable to compute shared secret");
        return CAVS_STATUS_FAIL;
    }

    /* Left-pad the output with null bytes. */
    memmove(&secret[s-secret_len], secret, secret_len);
    memset(secret, 0, s - secret_len);

    /* Create hash. */
    ccdigest(ccsha256_di(), s, secret, hash);

    /* Return the y component of the key and the hash. */
    ccn_write_uint_padded(ccdh_gp_n(gp), ccdh_ctx_y(key), ccdh_ccn_size(gp), out_y);
    memcpy(out_hash, hash, CCSHA256_OUTPUT_SIZE);

    return CAVS_STATUS_OK;
}

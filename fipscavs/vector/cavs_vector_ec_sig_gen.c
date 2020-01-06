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

#include "cavs_vector_ec_sig_gen.h"

#include <corecrypto/ccec.h>
#include <corecrypto/ccec_priv.h>
#include <corecrypto/ccder.h>

/* Realistically, around 2*66+10 for DER, with a bit of padding. */
#define CAVS_VECTOR_SIG_MAXLEN 200

/* Currently identical to vector/cavs_vector_ec_sig_gen_comp.c. */
int cavs_vector_ec_sig_gen(cavs_vector vector, int key_sz, cavs_digest digest,
        uint32_t msg_len, const uint8_t *msg, size_t *output_len,
        uint8_t *output)
{
    int ret = CAVS_STATUS_FAIL;
    bool valid = false;
    struct ccrng_state *rng;
    ccec_const_cp_t const_cp;
    size_t d_len;

    const struct ccdigest_info *di;

    const uint8_t *der_end;
    const uint8_t *an_end;

    /* Choose the correct CP and create the necessary ccunit objects. */
    switch (key_sz) {
        case 256: const_cp = ccec_cp_256(); break;
        case 384: const_cp = ccec_cp_384(); break;
        default: errorf("invalid keysize"); return CAVS_STATUS_FAIL;
    }

    cc_unit r_ccunit[ccec_cp_n(const_cp)];
    cc_unit s_ccunit[ccec_cp_n(const_cp)];

    /* Find the digest object and create an appropriately sized buffer. */
    di = cavs_find_digest_info(CAVS_SHA_IS_GEN, digest);
    if (di == NULL) {
        errorf("failed to acquire digest: %s", cavs_digest_to_string(digest));
        return CAVS_STATUS_FAIL;
    }
    d_len = di->output_size;
    uint8_t digest_buf[d_len];
    size_t sig_len = CAVS_VECTOR_SIG_MAXLEN;
    uint8_t sig[sig_len];
    memset(digest_buf, 0, d_len);
    size_t hs;

    /* Generate the key. */
    rng = ccrng(NULL);
    ccec_full_ctx_decl_cp(const_cp, priv_key);
    if (ccec_generate_key_fips(const_cp, rng, priv_key)) {
        errorf("could not generate keys");
        goto clear;
    }

    /* Calculate the digest, or use the supplied message. */
    if (vector == CAVS_VECTOR_EC_SIG_GEN) {
        ccdigest(di, msg_len, msg, digest_buf);
    } else if (vector == CAVS_VECTOR_EC_SIG_GEN_COMP) {
        if (msg_len != di->output_size) {
            errorf("invalid message length: %d", msg_len);
            goto clear;
        }

        CC_MEMCPY(digest_buf, msg, msg_len);
    }

    hs = (vector == CAVS_VECTOR_EC_SIG_GEN) ? d_len : msg_len;
    
    /* Sign the result. */
    if (ccec_sign(priv_key, hs, digest_buf, &sig_len, sig, rng)) {
        errorf("error creating a EC signature");
        goto clear;
    }

    /* Validate the correctness. */
    if (ccec_verify(ccec_ctx_pub(priv_key), hs, digest_buf, sig_len, sig, &valid)) {
        errorf("Failed ccec_verify");
        goto clear;
    }
    if (!valid)  {
        errorf("ccec_verify indicates invalid");
        goto clear;
    }

    /* Decompose the generated key parameters and the digest. */
    der_end = sig + sig_len;
    an_end = ccder_decode_seqii(ccec_cp_n(const_cp), r_ccunit, s_ccunit, sig, der_end);
    if (an_end != der_end) {
        errorf("decode error");
        goto clear;
    }

    /* Generate outputs - this should probably happen in the operation... */
    size_t used = 0;
    size_t len;

    /*
     * Write the cc_unit outputs as a set of:
     *   uint32_t len;
     *   uint8_t  buf[0];
     * for X, Y, R, and S.
     */
#define CAVS_EC_WRITE_UINT(SZ, UNIT)                                        \
    len = ccn_write_uint_size(SZ, UNIT);                                    \
    *(uint32_t *)(output + used) = (uint32_t)len;                           \
    used += sizeof(uint32_t);                                               \
    ccn_write_uint(SZ, UNIT, *output_len - used, output + used);            \
    used += len;

    CAVS_EC_WRITE_UINT(ccec_cp_n(ccec_ctx_cp(priv_key)), ccec_ctx_x(priv_key));
    CAVS_EC_WRITE_UINT(ccec_cp_n(ccec_ctx_cp(priv_key)), ccec_ctx_y(priv_key));
    CAVS_EC_WRITE_UINT(ccec_cp_n(const_cp), r_ccunit);
    CAVS_EC_WRITE_UINT(ccec_cp_n(const_cp), s_ccunit);

#undef CAVS_EC_WRITE_UINT

    ret = CAVS_STATUS_OK;
    *output_len = used;

clear:
    ccec_full_ctx_clear_cp(const_cp, priv_key);
    return ret;
}

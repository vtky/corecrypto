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

#include "cavs_vector_ec.h"

#include <corecrypto/ccec.h>
#include <corecrypto/ccec_priv.h>
#include <corecrypto/ccder.h>
#include <corecrypto/ccsha2.h>

const size_t cavs_vector_ec_get_key_len(int key_sz)
{
    /* Get the supported SHA hash object. */
    const struct ccdigest_info *di;
    if      (key_sz == 224) di = ccsha256_di();
    else if (key_sz == 256) di = ccsha256_di();
    else if (key_sz == 384) di = ccsha384_di();
    else if (key_sz == 521) di = ccsha512_di();
    else {
        errorf("invalid key size supplied");
        return CAVS_STATUS_FAIL;
    }

    return di->output_size;
}

size_t cavs_vector_ec_get_prime_len(int key_sz)
{
    ccec_const_cp_t cp = ccec_get_cp(key_sz);
    return ccec_cp_prime_size(cp);
}

const struct ccdigest_info *cavs_vector_ec_get_digest(int key_sz)
{
    /* Get the supported SHA hash object. */
    const struct ccdigest_info *di;
    if      (key_sz == 224) di = ccsha256_di();
    else if (key_sz == 256) di = ccsha256_di();
    else if (key_sz == 384) di = ccsha384_di();
    else if (key_sz == 521) di = ccsha512_di();
    else {
        errorf("invalid key size supplied");
        return NULL;
    }
    return di;
}

int cavs_vector_ec_generate_priv(struct ccrng_state *rng,
        ccec_pub_ctx_t pub_key, ccec_full_ctx_t priv_key)
{
    ccec_const_cp_t cp = ccec_ctx_cp(pub_key);
    ccec_ctx_init(cp, priv_key);
    return ccec_generate_key_fips(cp, rng, priv_key);
}

int cavs_vector_ec_compute_priv(int key_sz,
        ccec_pub_ctx_t pub_key, ccec_full_ctx_t priv_key,
        uint32_t x_len, const uint8_t *x, uint32_t y_len, const uint8_t *y,
        uint32_t k_len, const uint8_t *k)
{
    ccec_const_cp_t cp = ccec_ctx_cp(pub_key);
    ccec_ctx_init(cp, priv_key);
    return ccec_make_priv(key_sz, x_len, x, y_len, y, k_len, k, priv_key);
}

int cavs_vector_ec_compute_primes(int key_sz,
        ccec_pub_ctx_t pub_key, ccec_full_ctx_t priv_key,
        size_t digest_len, uint8_t *digest,
        size_t out_x_len, uint8_t *out_x_data,
        size_t out_y_len, uint8_t *out_y_data)
{
    const struct ccdigest_info *di = cavs_vector_ec_get_digest(key_sz);
    ccec_const_cp_t cp = ccec_ctx_cp(pub_key);
    if (digest_len != di->output_size) {
        errorf("invalid digest buffer supplied");
        return CAVS_STATUS_FAIL;
    }
    memset(digest, 0, digest_len);

    /* Compute the shared secret. */
    size_t shared_secret_size = ccec_ccn_size(cp);
    uint8_t shared_secret[shared_secret_size];

    /*
     * There is a bug in ccec_check_pub_and_projectify() that checks the z
     * coordinate of an affine point.
     *
     * ccn_set() is to one to cover that bug and is not needed in principle.
     */
    ccn_seti(ccec_ctx_n(pub_key), ccec_ctx_z(pub_key), 1);
    int ret = ccec_compute_key(priv_key, pub_key, &shared_secret_size, shared_secret);
    if (ret != 0) {
        errorf("cannot generate the share secret -- intentional?");
        return CAVS_STATUS_FAIL;
    }

    /* Record the digest. */
    ccdigest(di, shared_secret_size, shared_secret, digest);
    cc_size n = ccec_ctx_n(priv_key);

    /* Record the primes. */
    if (out_x_len) {
        if (out_x_len < ccec_cp_prime_size(cp)) {
            errorf("out_x_len is too small");
            return CAVS_STATUS_FAIL;
        }
        ccn_write_uint_padded(n, ccec_ctx_x(priv_key), out_x_len, out_x_data);
    }

    if (out_y_len) {
        if (out_y_len < ccec_cp_prime_size(cp)) {
            errorf("out_y_len is too small");
            return CAVS_STATUS_FAIL;
        }
        ccn_write_uint_padded(n, ccec_ctx_y(priv_key), out_y_len, out_y_data);
    }

    return CAVS_STATUS_OK;
}

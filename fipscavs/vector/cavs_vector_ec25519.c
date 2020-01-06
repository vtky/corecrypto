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

#include "cavs_vector_ec25519.h"

#include <stdint.h>

#include <corecrypto/ccsha2.h>
#include <corecrypto/ccec25519.h>
#include <corecrypto/ccec25519_priv.h>
#include <corecrypto/ccrng.h>

#include "cced25519priv.h"

#define SHA256_ONESHOT(data, size, hash) ccdigest(ccsha256_di(), size, data, hash)

struct cavs_ec25519_key_derivation {
    uint32_t counter;
    ccec25519secretkey shared_secret;
    ccec25519base pub_key_originator;
    ccec25519pubkey pub_key_recipient;
};

int cavs_vector_ec25519_gen_shared(const uint8_t *pub, const uint8_t *priv,
        uint8_t *eph_pub, uint8_t *eph_priv,
        uint8_t *wrapping1, uint8_t *wrapping2)
{
    struct ccrng_state *rng;
    struct cavs_ec25519_key_derivation key_derivation;

    const ccec25519pubkey *pub_key = (const ccec25519pubkey *)pub;
    const ccec25519secretkey *priv_key = (const ccec25519secretkey *)priv;
    ccec25519pubkey *eph_pub_key = (ccec25519pubkey *)eph_pub;
    ccec25519secretkey *eph_priv_key = (ccec25519secretkey *)eph_priv;
    ccec25519secretkey *wrapping_key1 = (ccec25519secretkey *)wrapping1;
    ccec25519secretkey *wrapping_key2 = (ccec25519secretkey *)wrapping2;

    // key derivation setup
    rng = ccrng(NULL);

    // Ensure Ephemeral Key Pairs and Derivation are zeroed first
    memset(&key_derivation, 0, sizeof(key_derivation));
    memset(*eph_pub_key, 0, sizeof(ccec25519pubkey));
    memset(*eph_priv_key, 0, sizeof(ccec25519secretkey));

    // Generate an Ephemeral Key Pair
    cccurve25519_make_key_pair(rng, *eph_pub_key, *eph_priv_key);

    key_derivation.counter = CC_H2BE32(1);
    memcpy(key_derivation.pub_key_originator, *eph_pub_key, sizeof(key_derivation.pub_key_originator));
    memcpy(key_derivation.pub_key_recipient, *pub_key, sizeof(key_derivation.pub_key_recipient));

    /* key exchange to produce secret (into derivation) */
    cccurve25519(key_derivation.shared_secret, *eph_priv_key, *pub_key);

    /* derive shared key from dh secret */
    SHA256_ONESHOT((const uint8_t*)&key_derivation, sizeof(key_derivation), wrapping_key1);

    // Ensure Ephemeral Key Pairs and Derivation are zeroed first
    key_derivation.counter = CC_H2BE32(1);
    memset(key_derivation.shared_secret, 0, sizeof(key_derivation.shared_secret));

    cccurve25519(key_derivation.shared_secret, *priv_key, *eph_pub_key);
    SHA256_ONESHOT((const uint8_t*)&key_derivation, sizeof(key_derivation), wrapping_key2);

    return CAVS_STATUS_OK;
}

int cavs_vector_ec25519_verify(const uint8_t *pub, const uint8_t *priv,
        const uint8_t *eph_pub, const uint8_t *eph_priv,
        const uint8_t *shared, uint32_t *valid)
{
    /* key derivation setup */
    struct cavs_ec25519_key_derivation key_derivation1, key_derivation2;
    ccec25519secretkey wrapping_key1;
    ccec25519secretkey wrapping_key2;

    const ccec25519pubkey *pub_key = (const ccec25519pubkey *)pub;
    const ccec25519secretkey *priv_key = (const ccec25519secretkey *)priv;
    const ccec25519pubkey *eph_pub_key = (const ccec25519pubkey *)eph_pub;
    const ccec25519secretkey *eph_priv_key = (const ccec25519secretkey *)eph_priv;
    const ccec25519secretkey *shared_key = (const ccec25519secretkey *)shared;

    // Ensure Derivation Key Pairs are zeroed first
    memset(&key_derivation1, 0x00, sizeof(key_derivation1));
    memset(&key_derivation2, 0x00, sizeof(key_derivation2));

    //
    // Initialize 1st derivation data
    //
    key_derivation1.counter = CC_H2BE32(1);
    memcpy(key_derivation1.pub_key_originator, *eph_pub_key, sizeof(key_derivation1.pub_key_originator));
    memcpy(key_derivation1.pub_key_recipient, *pub_key, sizeof(key_derivation1.pub_key_recipient));

    /* key exchange to produce secret (into derivation) */
    cccurve25519(key_derivation1.shared_secret, *eph_priv_key, *pub_key);

    /* derive shared key from dh secret */
    SHA256_ONESHOT((const uint8_t*)&key_derivation1, sizeof(key_derivation1), &wrapping_key1);

    //
    // Initialize 2nd derivation data
    //
    key_derivation2.counter = CC_H2BE32(1);
    memcpy(key_derivation2.pub_key_originator, *eph_pub_key, sizeof(key_derivation2.pub_key_originator));
    memcpy(key_derivation2.pub_key_recipient, *pub_key, sizeof(key_derivation2.pub_key_recipient));

    /* key exchange to produce secret (into derivation) */
    cccurve25519(key_derivation2.shared_secret, *priv_key, *eph_pub_key);

    /* derive shared key from dh secret */
    SHA256_ONESHOT((const uint8_t*)&key_derivation2, sizeof(key_derivation2), &wrapping_key2);

    /* valid if all of the wrapping keys and shared secret match */
    if (memcmp(&wrapping_key1, &wrapping_key2, sizeof(wrapping_key1)) == 0 &&
            memcmp(&wrapping_key1, shared_key, sizeof(wrapping_key1)) == 0) {
        *valid = 1;
    } else {
        *valid = 0;
    }

    return CAVS_STATUS_OK;
}

int cavs_vector_ec25519_verify_key(cavs_cipher_curve curve,
        const uint8_t *pub, const uint8_t *priv,
        uint8_t *eph_pub, uint32_t *valid)
{
    const struct ccdigest_info *di = ccsha512_di();
    ccec25519secretkey secret_key;

    const ccec25519pubkey *pub_key = (const ccec25519pubkey *)pub;
    const ccec25519secretkey *priv_key = (const ccec25519secretkey *)priv;
    ccec25519pubkey *eph_pub_key = (ccec25519pubkey *)eph_pub;

    memset(*eph_pub_key, 0, sizeof(ccec25519pubkey));
    memcpy(secret_key, *priv_key, sizeof(secret_key));

    switch (curve) {
    case CAVS_CIPHER_CURVE_25519:
        cccurve25519_make_pub(*eph_pub_key, secret_key);
        break;

    case CAVS_CIPHER_CURVE_ED25519:
        cced25519_make_pub(di, *eph_pub_key, secret_key);
        break;

    default:
        return CAVS_STATUS_FAIL;
    }

    if (memcmp(eph_pub_key, pub_key, 32) == 0) {
        *valid = 1;
    } else {
        *valid = 0;
    }

    return CAVS_STATUS_OK;
}

int cavs_vector_ec25519_generate_key(cavs_cipher_curve curve,
        struct ccrng_state *rng, uint8_t *pub, uint8_t *secret)
{
    const struct ccdigest_info *di = ccsha512_di();

    ccec25519pubkey *pub_key = (ccec25519pubkey *)pub;
    ccec25519secretkey *secret_key = (ccec25519secretkey *)secret;

    switch (curve) {
    case CAVS_CIPHER_CURVE_25519:
        cccurve25519_make_key_pair(rng, *pub_key, *secret_key);
        break;
    case CAVS_CIPHER_CURVE_ED25519:
        cced25519_make_key_pair(di, rng, *pub_key, *secret_key);
        break;
    default:
        errorf("Unknown cipher type");
        return CAVS_STATUS_FAIL;
    }
    return CAVS_STATUS_OK;
}

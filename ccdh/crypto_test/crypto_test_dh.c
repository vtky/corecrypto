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

#include "crypto_test_dh.h"
#include <corecrypto/ccdh.h>
#include <corecrypto/ccrng_sequence.h>
#include <corecrypto/cc_config.h>
#include "testmore.h"
#include <stdlib.h>

#define F false
#define P true

static const struct ccdh_compute_vector dh_compute_vectors[]=
{
#include "../test_vectors/DH.inc"
};

#define N_COMPUTE_VECTORS (sizeof(dh_compute_vectors)/sizeof(dh_compute_vectors[0]))


static int testDHCompute (void) {
    int rc=1;
    for(unsigned int i=0; i<N_COMPUTE_VECTORS; i++) {
        rc&=ok(0==ccdh_test_compute_vector(&dh_compute_vectors[i]),"testDHCompute Vector %d", i);
    }
    return rc;
}

#include <corecrypto/ccdh_gp.h>


/*
 This test generates 2 random key pairs for a given group and do the key exchange both way,
 Test fail if the generated secrets do not match
 */

static int testDHexchange(ccdh_const_gp_t gp) {
    int rc=1;
    struct ccrng_sequence_state seq_rng;
    struct ccrng_state *rng_dummy=(struct ccrng_state *)&seq_rng;
    struct ccrng_state *rng=global_test_rng;

    /* Key exchange with l */
    const cc_size n = ccdh_gp_n(gp);
    const size_t s = ccn_sizeof_n(n);
    uint8_t key_seed[s];
    ccdh_full_ctx_decl(s, a);
    ccdh_full_ctx_decl(s, b);
    uint8_t z1[s], z2[s];
    size_t z1_len=s,z2_len=s;
    size_t private_key_length;

    rc&=is(ccdh_gp_prime_bitlen(gp),ccn_bitsof_n(n), "Bitlength");

    rc&=is(ccdh_generate_key(gp, rng, a),0, "Computing first key");

    private_key_length=ccn_bitlen(n,ccdh_ctx_x(a));
    if (ccdh_gp_order_bitlen(gp)) {
        // Probabilistic test. Fails with prob < 2^-64
        rc&=ok((private_key_length<=ccdh_gp_order_bitlen(gp))
                      && (private_key_length>ccdh_gp_order_bitlen(gp)-64),
                      "Checking private key length is exactly l");
    }
    else if (ccdh_gp_l(gp)) {
        rc&=ok(private_key_length==ccdh_gp_l(gp),
                      "Checking private key length is exactly l");
    }

    rc&=is(ccdh_generate_key(gp, rng, b),0, "Computing second key");
    private_key_length=ccn_bitlen(n,ccdh_ctx_x(a));
    if (ccdh_gp_order_bitlen(gp)) {
        // Probabilistic test. Fails with prob < 2^-64
        rc&=ok((private_key_length<=ccdh_gp_order_bitlen(gp))
                      && (private_key_length>ccdh_gp_order_bitlen(gp)-64),
                      "Checking private key length is exactly l");
    }
    else if (ccdh_gp_l(gp)) {
        rc&=ok(private_key_length==ccdh_gp_l(gp),
                      "Checking private key length is exactly l");
    }
    memset(z1,'a',z1_len);
    memset(z2,'b',z2_len);
    rc&=is(ccdh_compute_shared_secret(a, ccdh_ctx_public(b), &z1_len, z1, rng),0, "Computing first secret");
    rc&=is(ccdh_compute_shared_secret(b, ccdh_ctx_public(a), &z2_len, z2, rng),0,"Computing second secret");
    rc&=is(z1_len,z2_len, "Shared key have same size");
    rc&=ok_memcmp(z1, z2, z2_len, "Computed secrets dont match");

    /* Key exchange without l, 4 steps. */
    ccdh_gp_decl(ccn_sizeof_n(n), gp2);
    ccdh_gp_t gp_local = (ccdh_gp_t)gp2;
    CCDH_GP_N(gp_local) = n;

    // a) encode / decode in gp_local
    size_t encSize = ccder_encode_dhparams_size(gp);
    uint8_t *encder = malloc(encSize);
    uint8_t *encder_end = encder + encSize;
    is(ccder_encode_dhparams(gp, encder, encder_end),encder,"Encode failed");
    isnt(ccder_decode_dhparams(gp_local, encder, encder_end),NULL,"Decode failed");
    free(encder);

    // b) Force l to 0
    CCDH_GP_L(gp_local)=0;

    // c) re-generate the key a
    rc&=is(ccdh_generate_key(gp_local, rng, a), 0, "Computing first key with l=0");
    rc&=ok((ccn_bitlen(n,ccdh_ctx_x(a))<=ccn_bitlen(n,ccdh_ctx_prime(a)))
                  && (ccn_bitlen(n,ccdh_ctx_x(a))>=ccn_bitlen(n,ccdh_ctx_prime(a)))-64,
                  "Checking private key length when l==0");


    // d) Key exchange
    z1_len=s;
    z2_len=s;
    memset(z1,'c',z1_len);
    memset(z2,'d',z2_len);
    rc&=is(ccdh_compute_shared_secret(a, ccdh_ctx_public(b), &z1_len, z1, rng),0, "Computing first secret");
    rc&=is(ccdh_compute_shared_secret(b, ccdh_ctx_public(a), &z2_len, z2, rng),0,"Computing second secret");
    rc&=is(z1_len,z2_len, "Shared key have same size");
    rc&=ok_memcmp(z1,z2,z2_len,"Computed secrets dont match");

    // e) re-generate the key a = p-2
    cc_unit p_minus_2[n];
    ccn_sub1(n,p_minus_2,ccdh_ctx_prime(a),2);
    memcpy(key_seed,p_minus_2,s);
    ccrng_sequence_init(&seq_rng,sizeof(key_seed),key_seed);

    rc&=is(ccdh_generate_key(gp_local, rng_dummy, a),0, "Private key with random = p-2");
    rc&=ok_memcmp(ccdh_ctx_x(a), p_minus_2,s, "Private key is p-2");

    // f) re-generate the key a = 1
    memset(key_seed,0x00,s);
    key_seed[0]=1;
    ccrng_sequence_init(&seq_rng,sizeof(key_seed),key_seed);
    rc&=is(ccdh_generate_key(gp_local, rng_dummy, a), 0, "Private key with random = 1");
    rc&=ok_memcmp(ccdh_ctx_x(a), key_seed, s, "Private key is 1");

    /* Negative testing */

    // 1) Bad random
    ccrng_sequence_init(&seq_rng,0,NULL);
    rc&=is(ccdh_generate_key(gp, rng_dummy, a),
                   CCERR_CRYPTO_CONFIG,
                   "Error random");

    // 2) Random too big
    uint8_t c=0xff;
    ccrng_sequence_init(&seq_rng,1,&c);
    rc&=is(ccdh_generate_key(gp_local, rng_dummy, a),
                   CCDH_GENERATE_KEY_TOO_MANY_TRIES,
                   "Value consistently too big (all FF)");

    // 3) Random too big p-1
    memcpy(key_seed,ccdh_ctx_prime(a),s);
    key_seed[0]^=1;
    ccrng_sequence_init(&seq_rng,1,&c);
    rc&=is(ccdh_generate_key(gp_local, rng_dummy, a),
                   CCDH_GENERATE_KEY_TOO_MANY_TRIES,
                   "Value consistently too big (p-1)");

    // 4) Random zero
    c=0;
    ccrng_sequence_init(&seq_rng,1,&c);
    rc&=is(ccdh_generate_key(gp_local, rng_dummy, a),
                   CCDH_GENERATE_KEY_TOO_MANY_TRIES,
                   "Value consistently zero");
    return rc;
}

struct {
    const char *name;
    char *data;
    size_t length;
    int pass;
} dhparams[] = {
    {
        .name = "no l",
        .data = "\x30\x06\x02\x01\x03\x02\x01\x04",
        .length = 8,
        .pass = 1
    },
    {
        .name = "with l",
        .data = "\x30\x09\x02\x01\x03\x02\x01\x04\x02\x01\x05",
        .length = 11,
        .pass = 1
    },
    {
        .name = "missing g",
        .data = "\x30\x03\x02\x01\x03",
        .length = 5,
        .pass = 0
    }
};
static int testDHParameter(void) {
    const uint8_t *der, *der_end;
    const size_t size = 2048;
    ccdh_gp_decl(size, gp);
    size_t n;
    int rc=1;
    ccdh_gp_t gpfoo = (ccdh_gp_t)gp;

    CCDH_GP_N(gpfoo) = ccn_nof_size(size);

    for (n = 0; n < sizeof(dhparams)/sizeof(dhparams[0]); n++) {
        der = (const uint8_t *)dhparams[n].data;
        der_end = (const uint8_t *)dhparams[n].data + dhparams[n].length;

        size_t nNew = ccder_decode_dhparam_n(der, der_end);
        rc&=is(nNew, (size_t)1, "cc_unit is small? these have really small integers tests");

        der = ccder_decode_dhparams(gp, der, der_end);
        if (der == NULL) {
            rc&=ok(!dhparams[n].pass, "not passing test is supposed to pass");
            break;
        }
        rc&=ok(dhparams[n].pass, "passing test is not supposed to pass");

        size_t encSize = ccder_encode_dhparams_size(gp);

        rc&=is(encSize, dhparams[n].length, "length wrong");

        uint8_t *encder = malloc(encSize);
        uint8_t *encder2, *encder_end;

        encder_end = encder + encSize;
        encder2 = ccder_encode_dhparams(gp, encder, encder_end);
        if (encder2 == NULL) {
            rc&=ok(false, "log foo");
            free(encder);
            break;
        }
        rc&=is(encder2, encder, "didn't encode the full length");
        rc&=ok_memcmp(encder, dhparams[n].data, dhparams[n].length, "length wrong");
        free(encder);
    }
    return rc;
}


#define TEST_GP(_name_)     diag("Test " #_name_); ok(testDHexchange(ccdh_gp_##_name_()), #_name_);
#define TEST_GP_SRP(_name_) diag("Test " #_name_); ok(testDHexchange(ccsrp_gp_##_name_()), #_name_);

int ccdh_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    plan_tests(478);

    diag("testDHCompute");
    ok(testDHCompute(),   "testDHCompute");

    diag("testDHParameter");
    ok(testDHParameter(), "testDHParameter");

#if CORECRYPTO_HACK_FOR_WINDOWS_DEVELOPMENT
    TEST_GP(rfc5114_MODP_1024_160)
    TEST_GP(rfc5114_MODP_2048_224)
    TEST_GP(rfc2409group02)
    TEST_GP(rfc3526group05)
    TEST_GP(rfc3526group14)
    TEST_GP(rfc3526group15)
    TEST_GP(rfc3526group16)
    TEST_GP_SRP(rfc5054_1024)
    TEST_GP_SRP(rfc5054_2048)
#else
    TEST_GP(apple768)
    TEST_GP(rfc5114_MODP_1024_160)
    TEST_GP(rfc5114_MODP_2048_224)
    TEST_GP(rfc5114_MODP_2048_256)
    TEST_GP(rfc2409group02)
    TEST_GP(rfc3526group05)
    TEST_GP(rfc3526group14)
    TEST_GP(rfc3526group15)
    TEST_GP(rfc3526group16)
    TEST_GP(rfc3526group17)
    TEST_GP(rfc3526group18)
    TEST_GP_SRP(rfc5054_1024)
    TEST_GP_SRP(rfc5054_2048)
    TEST_GP_SRP(rfc5054_3072)
    TEST_GP_SRP(rfc5054_4096)
    TEST_GP_SRP(rfc5054_8192)
#endif
    return 0;
}


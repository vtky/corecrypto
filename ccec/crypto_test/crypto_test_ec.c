/*
 * Copyright (c) 2012,2013,2014,2015,2016,2018 Apple Inc. All rights reserved.
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

#include "testmore.h"
#include "testbyteBuffer.h"
#include "testccnBuffer.h"

#if (CCEC == 0)
entryPoint(ccec_tests,"ccec")
#else

#include <corecrypto/ccec.h>
#include <corecrypto/ccec_priv.h>
#include <corecrypto/ccrng_test.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccrng_pbkdf2_prng.h>
#include <corecrypto/ccrng_sequence.h>
#include "crypto_test_ec.h"

static int verbose = 1;

static const int kTestTestCount = 3200;

static int saneKeySize(ccec_full_ctx_t fk) {
    switch(ccec_ctx_bitlen(fk)) {
        case 192:
        case 224:
        case 256:
        case 384:
        case 521: return 1;
        default: return 0;
    }
}

#define MAXKEYSPACE 8192

static int key_exchange(ccec_full_ctx_t key1, ccec_full_ctx_t key2)
{
    int status = 0; // fail
    byteBuffer shared_secret1 = mallocByteBuffer(MAXKEYSPACE);
    byteBuffer shared_secret2 = mallocByteBuffer(MAXKEYSPACE);
    size_t outlen1=shared_secret1->len;
    size_t outlen2=shared_secret2->len;

    ok_or_goto(ccec_compute_key(key1,ccec_ctx_pub(key2),&outlen1,shared_secret1->bytes)==0, "Compute secret 1", errout);

    ok_or_goto(ccecdh_compute_shared_secret(key1,ccec_ctx_pub(key2),&outlen1,shared_secret1->bytes,global_test_rng)==0, "Compute secret 1", errout);
    
    ok_or_goto(ccecdh_compute_shared_secret(key2,ccec_ctx_pub(key1),&outlen2,shared_secret2->bytes,global_test_rng)==0, "Compute secret 2", errout);

    ok_or_goto(outlen1 == outlen2, "Sign/Verify correct keysize", errout);
    ok_or_goto(memcmp(shared_secret1->bytes,shared_secret2->bytes,outlen1)==0, "Shared secrets match", errout);
    
    status = 1; // Success
    
errout:
    free(shared_secret1);
    free(shared_secret2);
    return status;
}

static int key_exchange_compact(ccec_full_ctx_t key1, ccec_full_ctx_t key2)
{
    int status = 0; // fail
    byteBuffer shared_secret1 = mallocByteBuffer(MAXKEYSPACE);
    byteBuffer shared_secret2 = mallocByteBuffer(MAXKEYSPACE);
    size_t outlen1=shared_secret1->len;

    size_t outlen2=shared_secret2->len;
    size_t export_pubsize1 = ccec_compact_export_size(0, ccec_ctx_pub(key1));
    size_t export_pubsize2 = ccec_compact_export_size(0, ccec_ctx_pub(key2));
    uint8_t exported_pubkey1[export_pubsize1];
    uint8_t exported_pubkey2[export_pubsize2];

    ccec_pub_ctx_decl_cp(ccec_ctx_cp(key1), reconstituted_pub1);
    ccec_pub_ctx_decl_cp(ccec_ctx_cp(key2), reconstituted_pub2);

    
    /* Export keys */
    ccec_compact_export(0, exported_pubkey2, key2);
    ccec_compact_export(0, exported_pubkey1, key1);
    
    /* Party 1 */
    ok_or_goto(ccec_compact_import_pub(ccec_ctx_cp(key2), export_pubsize2, exported_pubkey2, reconstituted_pub2)==0,
               "Import compact key", errout);
    ok_or_goto(ccecdh_compute_shared_secret(key1,reconstituted_pub2,&outlen2,shared_secret2->bytes,global_test_rng)==0, "Compute secret 1", errout);
    
    /* Party 2 */
    ok_or_goto(ccec_compact_import_pub(ccec_ctx_cp(key1), export_pubsize1, exported_pubkey1, reconstituted_pub1)==0,
               "Import compact key", errout);
    ok_or_goto(ccecdh_compute_shared_secret(key2,reconstituted_pub1,&outlen1,shared_secret1->bytes,global_test_rng)==0, "Compute secret 2", errout);
    
    /* Check both parties have the same key */
    ok_or_goto(outlen1 == outlen2, "Sign/Verify correct keysize", errout);
    ok_or_goto(memcmp(shared_secret1->bytes,shared_secret2->bytes,outlen1)==0, "Shared secrets match", errout);
    
    /* Party 2 tries again without the export/import */
    ok_or_goto(ccecdh_compute_shared_secret(key2,ccec_ctx_pub(key1),&outlen1,shared_secret1->bytes,global_test_rng)==0, "Compute secret 2", errout);
    
    /* Check both parties have the same key again */
    ok_or_goto(outlen1 == outlen2, "Sign/Verify correct keysize", errout);
    ok_or_goto(memcmp(shared_secret1->bytes,shared_secret2->bytes,outlen1)==0, "Shared secrets match", errout);
    
    status = 1; // Success
    
errout:
    free(shared_secret1);
    free(shared_secret2);
    return status;
}

static int sign_verify(ccec_full_ctx_t sign_key, ccec_full_ctx_t verify_key, struct ccrng_state *rng, const struct ccdigest_info *di)
{
    bool valid = true;
    byteBuffer signature = mallocByteBuffer(MAXKEYSPACE*2);
    byteBuffer hash = hexStringToBytes("000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f");
    int status = 0;
    
    if(hash->len < di->output_size) {
        diag("hash pattern is too small");
        fail("HASH PATTERN SIZE");
        status = 0;
        goto errout;
    }
    hash->len = di->output_size;
    


    // DER APIs
    ok_or_goto(ccec_ctx_bitlen(sign_key) == ccec_ctx_bitlen(sign_key), "Sign/Verify correct keysize", errout);
    ok_or_goto(ccec_sign(sign_key, hash->len, hash->bytes, &signature->len, signature->bytes, rng) == 0, "Signed Hash", errout);
    ok_or_goto(ccec_verify(ccec_ctx_pub(verify_key), hash->len, hash->bytes, signature->len, signature->bytes, &valid) == 0, "Verified Signed Hash", errout);
    ok_or_goto(valid == true, "Signature verifies", errout);

    // Composite APIs
    ok_or_goto(ccec_sign_composite(sign_key, hash->len, hash->bytes, &signature->bytes[0], &signature->bytes[ccec_signature_r_s_size(ccec_ctx_pub(sign_key))], rng) == 0, "Signed Hash", errout);
    ok_or_goto(ccec_verify_composite(ccec_ctx_pub(verify_key), hash->len, hash->bytes, &signature->bytes[0], &signature->bytes[ccec_signature_r_s_size(ccec_ctx_pub(sign_key))], &valid) == 0, "Verified Signed Hash", errout);
    ok_or_goto(valid == true, "Composite signature verifies", errout);

    status = 1;
    
errout:
    free(signature);
    free(hash);
    return status;
}

static int export_import(ccec_full_ctx_t fk, struct ccrng_state *rng)
{
    int status = 0;
    
    size_t keysize = ccec_ctx_bitlen(fk);
    
    size_t export_pubsize = ccec_x963_export_size(0, ccec_ctx_pub(fk));
    size_t export_privsize = ccec_x963_export_size(1, ccec_ctx_pub(fk));
    uint8_t exported_pubkey[export_pubsize];
    uint8_t exported_privkey[export_privsize];
    
    ccec_x963_export(0, exported_pubkey, fk);
    ccec_x963_export(1, exported_privkey, fk);
    
    size_t pub_keysize = ccec_x963_import_pub_size(export_pubsize);
    size_t priv_keysize = ccec_x963_import_priv_size(export_privsize);
    
    ok_or_goto(pub_keysize == keysize, "Package Keysize is the same as we started with", errout);
    ok_or_goto(priv_keysize == keysize, "Package Keysize is the same as we started with", errout);
    ok_or_goto(priv_keysize == pub_keysize, "Package Keysizes agree", errout);
    
    const ccec_const_cp_t cp = ccec_curve_for_length_lookup(keysize,
                ccec_cp_192(), ccec_cp_224(), ccec_cp_256(), ccec_cp_384(), ccec_cp_521());
    {
        ccec_full_ctx_decl_cp(cp, reconstituted_pub);
        ccec_full_ctx_decl_cp(cp, reconstituted_priv);
    
        ok_or_goto(ccec_x963_import_pub(cp, export_pubsize, exported_pubkey, ccec_ctx_pub(reconstituted_pub)) == 0,
               "Imported Public Key Successfully", errout);
        ok_or_goto(saneKeySize(reconstituted_pub), "Keysize is realistic", errout);

        ok_or_goto(ccec_x963_import_priv(cp, export_privsize, exported_privkey, reconstituted_priv) == 0,
               "Imported Private Key Successfully", errout);
        ok_or_goto(saneKeySize(reconstituted_priv), "Keysize is realistic", errout);

        ok_or_goto(sign_verify(reconstituted_priv, reconstituted_pub, rng, ccsha1_di()), "Can perform round-trip sign/verify", errout);

        //------ repeat for raw import funcs
        ccec_full_ctx_clear_cp(cp, reconstituted_pub);
        ccec_full_ctx_clear_cp(cp, reconstituted_priv);
        ok_or_goto(ccec_raw_import_pub(cp, export_pubsize-1, exported_pubkey+1, ccec_ctx_pub(reconstituted_pub)) == 0,
                   "Imported Public Key Successfully", errout);
        ok_or_goto(saneKeySize(reconstituted_pub), "Keysize is realistic", errout);
        size_t es = (export_privsize-1)/3;
        ok_or_goto(ccec_raw_import_priv_only(cp, es, exported_privkey+2*es+1, reconstituted_priv) == 0,
                   "Imported Private Key Successfully", errout);
        ok_or_goto(saneKeySize(reconstituted_priv), "Keysize is realistic", errout);

        ok_or_goto(sign_verify(reconstituted_priv, reconstituted_pub, rng, ccsha1_di()), "Can perform round-trip sign/verify", errout);
        
    }
    status = 1;
errout:
    return status;
    
}

static int export_import_compact(ccec_full_ctx_t fk, struct ccrng_state *rng)
{
    int status = 0;
    
    size_t keysize = ccec_ctx_bitlen(fk);
    
    size_t export_pubsize = ccec_compact_export_size(0, ccec_ctx_pub(fk));
    size_t export_privsize = ccec_compact_export_size(1, ccec_ctx_pub(fk));
    uint8_t exported_pubkey[export_pubsize];
    uint8_t exported_privkey[export_privsize];
    cc_zero(sizeof(exported_pubkey),exported_pubkey);
    cc_zero(sizeof(exported_privkey),exported_privkey);
    
    ccec_compact_export(0, exported_pubkey, fk);
    ccec_compact_export(1, exported_privkey, fk);
    
    size_t pub_keysize = ccec_compact_import_pub_size(export_pubsize);
    size_t priv_keysize = ccec_compact_import_priv_size(export_privsize);
    
    ok_or_goto(pub_keysize == keysize, "Compact package Keysize is the same as we started with", errout);
    ok_or_goto(priv_keysize == keysize, "Compact peysize is the same as we started with", errout);
    ok_or_goto(priv_keysize == pub_keysize, "Compact peysizes agree", errout);
    
    const ccec_const_cp_t cp = ccec_curve_for_length_lookup(keysize,
                ccec_cp_192(), ccec_cp_224(), ccec_cp_256(), ccec_cp_384(), ccec_cp_521());
    {
        ccec_full_ctx_decl_cp(cp, reconstituted_pub);  
        ccec_full_ctx_decl_cp(cp, reconstituted_priv);

        ok_or_goto(ccec_compact_import_pub(cp, export_pubsize, exported_pubkey, ccec_ctx_pub(reconstituted_pub)) == 0,
                   "Imported Compact Public Key Successfully", errout);
        ok_or_goto(saneKeySize(reconstituted_pub), "Compact Keysize is realistic", errout);
        
        ok_or_goto(ccec_compact_import_priv(cp, export_privsize, exported_privkey, reconstituted_priv) == 0,
                   "Imported Compact Private Key Successfully", errout);
        ok_or_goto(saneKeySize(reconstituted_priv), "Compact Keysize is realistic", errout);
        
        ok_or_goto(sign_verify(reconstituted_priv, reconstituted_pub, rng, ccsha1_di()), "Can perform round-trip sign/verify", errout);
    }
    status = 1;
errout:
    return status;
}



static int
round_trip_tests(ccec_full_ctx_t fk)
{
    struct ccrng_state *rng = global_test_rng;
    
    int status = 0;
    ok_or_goto(saneKeySize(fk), "Keysize is realistic", errout);
    // wrap-unwrap isn't working yet.
#ifdef PR_10568130
    ok_or_goto(wrapUnwrap(fk, ccsha1_di(), rng), "Can perform round-trip wrap/unwrap", errout);
#endif
    ok_or_goto(sign_verify(fk, fk, rng, ccsha1_di()), "Can perform round-trip SHA1 sign/verify", errout);
    ok_or_goto(sign_verify(fk, fk, rng, ccsha512_di()), "Can perform round-trip SHA512 sign/verify", errout);
    ok_or_goto(export_import(fk, rng), "Can perform round-trip import/export", errout);
    ok_or_goto(key_exchange(fk,fk), "Can perform key exchange", errout);
    status = 1;
errout:
    return status;    
}

static int construction(ccec_full_ctx_t fk)
{
    cc_size n = ccec_ctx_n(fk);
    size_t bufsiz = ccn_sizeof_n(n);
    uint8_t x[bufsiz], y[bufsiz], d[bufsiz];
    size_t nbits, xsize, ysize, dsize;
    xsize = ysize = dsize = bufsiz;
    ccec_const_cp_t cp = ccec_ctx_cp(fk);
    ccec_full_ctx_decl_cp(cp, newkey); ccec_ctx_init(cp, newkey);
    
    ok_or_goto(ccec_get_fullkey_components(fk, &nbits, x, &xsize, y, &ysize, d, &dsize) == 0, "Get Key Components", errout);
    ok_or_goto(ccec_make_priv(nbits, xsize, x, ysize, y, dsize, d, newkey) == 0, "Reconstruct Key", errout);
    ok_or_goto(round_trip_tests(newkey), "EC Round-Trip Key Tests", errout);
    
    return 1;
errout:
    return 0;
}

static int
ECZeroGenTest(size_t expected_keysize, ccec_const_cp_t cp)
{
    if(verbose) diag("Test with keysize %u", expected_keysize);
    ccec_full_ctx_decl_cp(cp, full_key1); ccec_ctx_init(cp, full_key1);
    struct ccrng_sequence_state sequence_prng;
    static uint8_t zerobuf[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, };
    ccrng_sequence_init(&sequence_prng, sizeof(zerobuf), zerobuf);
    struct ccrng_state *rng2 = (struct ccrng_state *)&sequence_prng;
    
    ok_or_fail(ccec_generate_key_legacy(cp, rng2, full_key1) != 0, "Don't create EC key with 0 for K");
    return 1;
}

static int
ECZeroGenFIPSTest(size_t expected_keysize, ccec_const_cp_t cp)
{
    if(verbose) diag("Test with keysize %u", expected_keysize);
    ccec_full_ctx_decl_cp(cp, full_key1); ccec_ctx_init(cp, full_key1);
    struct ccrng_sequence_state sequence_prng;
    struct ccrng_state *fake_rng = (struct ccrng_state *)&sequence_prng;
    uint8_t fake_rng_buf[MAXKEYSPACE];
    cc_unit order_minus_x[ccec_cp_n(cp)];

    // Rng always return 0
    memset(fake_rng_buf,0,sizeof(fake_rng_buf));
    ccrng_sequence_init(&sequence_prng, sizeof(fake_rng_buf), fake_rng_buf);
    ok_or_fail(ccec_generate_key_fips(cp, fake_rng, full_key1) == 0, "Ok to create key with 0");

    // Rng always returns ff: we will never get a scalar is in the appropriate range
    memset(fake_rng_buf,0xff,sizeof(fake_rng_buf));
    ccrng_sequence_init(&sequence_prng, sizeof(fake_rng_buf), fake_rng_buf);
    ok_or_fail(ccec_generate_key_fips(cp, fake_rng, full_key1) != 0, "Can't pickup scalar in range");

    // Rng always returns order, needs to fail.
    memcpy(fake_rng_buf,(const uint8_t *)cczp_prime(ccec_cp_zq(cp)),ccec_cp_order_size(cp));
    memset(fake_rng_buf+ccec_cp_order_size(cp),
           0,
           sizeof(fake_rng_buf)-ccec_cp_order_size(cp));
    ccrng_sequence_init(&sequence_prng,sizeof(fake_rng_buf),fake_rng_buf);
    ok_or_fail(ccec_generate_key_fips(cp, fake_rng, full_key1) != 0, "Can't pickup scalar in range");

    // Rng always returns order-1, needs to fail.
    memset(fake_rng_buf,0xff,sizeof(fake_rng_buf));
    ccn_sub1(ccec_cp_n(cp),order_minus_x,cczp_prime(ccec_cp_zq(cp)),1);
    memcpy(fake_rng_buf,order_minus_x,ccn_sizeof_n(ccec_cp_n(cp)));
    ccrng_sequence_init(&sequence_prng,sizeof(fake_rng_buf),fake_rng_buf);
    ok_or_fail(ccec_generate_key_fips(cp, fake_rng, full_key1) != 0, "EC key gen fips with q-1");

    // Rng always returns order-2, needs to work.
    memset(fake_rng_buf,0xff,sizeof(fake_rng_buf));
    ccn_sub1(ccec_cp_n(cp),order_minus_x,cczp_prime(ccec_cp_zq(cp)),2);
    memcpy(fake_rng_buf,order_minus_x,ccn_sizeof_n(ccec_cp_n(cp)));
    ccrng_sequence_init(&sequence_prng,sizeof(fake_rng_buf),fake_rng_buf);
    ok_or_fail(ccec_generate_key_fips(cp, fake_rng, full_key1) == 0, "EC key gen fips with q-2");

    return 1;
}

struct ccec_pbkdf2_keygen_vector {
    ccec_const_cp_t (*cp)(void);
    char *password;
    size_t iterations;
    char *str_salt;
    char *str_legacy_x963_full_key;
    char *str_fips_x963_full_key;
    char *str_compact_x963_full_key;
};

const struct ccec_pbkdf2_keygen_vector ccec_pbkdf2_keygen_vectors[]=
{
    {
        .cp=&ccec_cp_192,
        .password="foofoofoo",
        .iterations=1024,
        .str_salt="4141414141414141",
        .str_legacy_x963_full_key="04b2c06c91874594ac7a9a11e015021dbfce8be82937c44ee8f49736d538ed23af7d57b64ef11aed308b405deb6a6712f54cd97af15879dc056f76061796f8f71efafdf368622fddab",
        .str_fips_x963_full_key="044ea8feee26902c7df26d4fec83592c6a1fba2c2ee5463ee0467ff1c12001aa7f00ffff2e9eacad923336ded5d9b1fdd3d020c30e2d7767d712049879327387988f2c5ee37b1cd2ba",
        .str_compact_x963_full_key="044ea8feee26902c7df26d4fec83592c6a1fba2c2ee5463ee0467ff1c12001aa7f00ffff2e9eacad923336ded5d9b1fdd3d020c30e2d7767d712049879327387988f2c5ee37b1cd2ba",
    },
    {
        .cp=&ccec_cp_224,
        .password="foofoofoo",
        .iterations=1024,
        .str_salt="4141414141414141",
        .str_legacy_x963_full_key="048ff2fc917799d97633df4a431cb1a2b02418a2a40c3b8153533a48d6a9f93112ff6bce3c3c9852e32a62ea7b989801f1ced7d6212b9e67ae7b1cd2b94cd97af15879dc056f76061796f8f71efafdf368622fddab",
#if CC_UNIT_SIZE==8
        .str_fips_x963_full_key="04c3312a8817ea34d7eb72a5af0bbd9804558904e7ea070835545f60d875e09171c9d992c3440d14d2f3587bd3359483968ec6683d0b38a0bc00e5745c885181d60a580111d020c30e2d7767d71204987932738799",
#elif CC_UNIT_SIZE==4
        .str_fips_x963_full_key="043b468f17be760e163c76eaf61468a8fede4e57032b5747301241be09aa70886d8d9e79fe2ee49c49c98fc62dae64ceec37cf30647acfd9b9885181d60a580111d020c30e2d7767d712049879327387988f2c5ee4",
#endif
    },
    {
        .cp=&ccec_cp_256,
        .password="foofoofoo",
        .iterations=1024,
        .str_salt="4141414141414141",
        .str_legacy_x963_full_key="044c20da234c2cd2d674c42cd322de2f6c4b51ad3f9b3915342dba188a85fe48b9e4103add4611308a3b951e894dbaddb8593a520c89f39cc0a5b546518ebaf38f8f2c5ee37b1cd2b94cd97af15879dc056f76061796f8f71efafdf368622fddab",
        .str_fips_x963_full_key="049767be9128a7f6d0ac245931cf17b84846c4120bf95e5cc276a8f43d670f9d1a8d74ad12d38c776eb0baaab07301a5636b6de55aaae5c996b0a5cea771f632d9f383216100e5745c885181d60a580111d020c30e2d7767d71204987932738799",
        .str_compact_x963_full_key="049767be9128a7f6d0ac245931cf17b84846c4120bf95e5cc276a8f43d670f9d1a728b52ec2c7388924f45554f8cfe5a9c94921aa6551a36694f5a31588e09cd260c7cde9dff1a8ba477ae7e29f5a7feedecc6379f79a036ade1b53249c9ef9db8",
    },
    {
        .cp=&ccec_cp_384,
        .password="foofoofoo",
        .iterations=1024,
        .str_salt="4141414141414141",
        .str_legacy_x963_full_key="04954955319fa1e463a7bef143e8231f347ef6fa36c25e935d00008cb7837f427207a5a93eb9dcd04a9c8b7d6501050f0982d185e05e5a632869608ad7621b3a40558cd8608c1b5dd2f1705d286ca2e5f87d837cb9727df8949ed4b4fd4b6c98d1d020c30e2d7767d712049879327387988f2c5ee37b1cd2b94cd97af15879dc056f76061796f8f71efafdf368622fddab",
        .str_fips_x963_full_key="043546cb3667a75a375f7e1cddc5f133389d0fd4dcc759b8e74d80df4c4b94ece497bcd544d782f1ad84336c9decd525e4bc9f24c13826a467bae79e404befa3bc76701b62f65138736fb025b7f335add145d0cffbe534bca6c3afc1ed99b12062835a04461534742d76701b8fd0959f90913923e79bbec5a393ddb9d7d69aabebf383216100e5745c885181d60a580112",
        .str_compact_x963_full_key="043546cb3667a75a375f7e1cddc5f133389d0fd4dcc759b8e74d80df4c4b94ece497bcd544d782f1ad84336c9decd525e44360db3ec7d95b98451861bfb4105c43898fe49d09aec78c904fda480cca522dba2f30031acb43593c503e13664edf9d7ca5fbb9eacb8bd2898fe4702f6a606f6ec6dc1864413a5c338593aa1d9c81f36496ec5147cb331e649a9794c26d2861",
    },
    {
        .cp=&ccec_cp_521,
        .password="foofoofoo",
        .iterations=1024,
        .str_salt="4141414141414141",
        .str_legacy_x963_full_key="0400c968e680dc020dea239817ba7ac407b14fc92059f3757f63d037869cd262fadbcae8ca005cc9a86f3dbcd15328084667cff94e1a4fd3b8d1d529a29955c92a620f012c5aa28b4aab652b2654d5e19da7f90ce4f6be300e09072d0cc676814043aeb564c38f7f74db3fb27cfe7bd19322a2f7727f26989a49c97cd135cfe986472e024a01ebf383216100e5745c885181d60a580111d020c30e2d7767d712049879327387988f2c5ee37b1cd2b94cd97af15879dc056f76061796f8f71efafdf368622fddab",
#if CC_UNIT_SIZE==8
        .str_fips_x963_full_key="040122a5b2a09234374c143614d4ee897c6aba09a674cf748de994ca2c2e2debc4b198b2259b780ccf71204492b38595b9efc6a0e8f3a5f83ebb6a28b20f79a4d223a8014a9575f2cde7bae68f502ccfe39a04db658eff2714b3e6c19b3d634dfbd6c36c6a6f201e5f483f3e942310bedebf1e50ad7600c32d9f795496d12bee9f6036236001129e9e8ecba2f709fb2a1a8969ec192a0e93a43b6963d38ee902929da64df51c7317ad70ff94e3e6f1835a04461534742d76701b8fd0959f90913923e79bbec5a4",
#elif CC_UNIT_SIZE==4
        .str_fips_x963_full_key="0401edd47f457e722edd62a432f2eb90ccc2dfa8c018c3ca2c3cd2afeadceec71801fd98ee99e555ffb67229d4d0f0e0d7c8cbb7a754e05191e61d4aa09e356c08e9f70186b37bcb63bb89a3d543d6049077c22ffc4a39f6935c422e20ba15946ba77b9918fdad631677c6df396202ac785bfa049415da185908231af7ec6810500fb715c300cba2f709fb2a1a8969ec192a0e93a43b6963d38ee902929da64df51c7317ad70ff94e3e6f1835a04461534742d76701b8fd0959f90913923e79bbec5a393ddb9d8",
#endif
#if CC_UNIT_SIZE==8
        .str_compact_x963_full_key="040122a5b2a09234374c143614d4ee897c6aba09a674cf748de994ca2c2e2debc4b198b2259b780ccf71204492b38595b9efc6a0e8f3a5f83ebb6a28b20f79a4d223a800b56a8a0d3218451970afd3301c65fb249a7100d8eb4c193e64c29cb204293c939590dfe1a0b7c0c16bdcef412140e1af5289ff3cd26086ab692ed411609fc9dc9f00ed616171345d08f604d5e5769613e6d5f16c5bc4969c2c7116fd6d6259b20ae38739d916842a4baf79fc71fd02e1d531a2c545ae28b906a81e2a369336f5799e65",
#elif CC_UNIT_SIZE==4
        .str_fips_x963_full_key="0401edd47f457e722edd62a432f2eb90ccc2dfa8c018c3ca2c3cd2afeadceec71801fd98ee99e555ffb67229d4d0f0e0d7c8cbb7a754e05191e61d4aa09e356c08e9f700794c84349c44765c2abc29fb6f883dd003b5c6096ca3bdd1df45ea6b94588466e702529ce9883920c69dfd5387a405fb6bea25e7a6f7dce5081397efaff048ea3c01345d08f604d5e5769613e6d5f16c5bc4969c2c7116fd6d6259b20ae38ce8528efabca2a0923bd592256a978d1b80998a406b202a27f86323c71fb0f17afd5aaa31",
#endif
    },
};

static int ccec_keys_are_equal(ccec_full_ctx_t full_key,byteBuffer x963_ec_full_key, size_t test_nb) {
    int status=1;
    // Export key
    size_t bufsiz = ccec_x963_export_size(1, ccec_ctx_pub(full_key));
    uint8_t buf[bufsiz];
    ccec_x963_export(1, buf, full_key);

    // Compare with expect value
    status&=is(x963_ec_full_key->len,bufsiz,"Key size mismatch for test");
    status&=ok_memcmp(buf, x963_ec_full_key->bytes, bufsiz, "%d bit EC Key mismatch for test %d",ccec_ctx_bitlen(full_key),test_nb);
    return status;
}

static int
ECStaticGenTest(void)
{
    for (size_t i=0;i<sizeof(ccec_pbkdf2_keygen_vectors)/sizeof(ccec_pbkdf2_keygen_vectors[0]);i++) {
        const struct ccec_pbkdf2_keygen_vector *test_vector=&ccec_pbkdf2_keygen_vectors[i];
        ccec_const_cp_t cp=test_vector->cp();
        struct ccrng_pbkdf2_prng_state pbkdf2_prng;
        ccec_full_ctx_decl_cp(cp, full_key);

        size_t iterations = 1024;

        struct ccrng_state *rng2 = (struct ccrng_state *)&pbkdf2_prng;
        byteBuffer x963_ec_full_key_legacy = hexStringToBytes(test_vector->str_legacy_x963_full_key);
        byteBuffer x963_ec_full_key_fips = hexStringToBytes(test_vector->str_fips_x963_full_key);
        byteBuffer x963_ec_full_key_compact = hexStringToBytes(test_vector->str_compact_x963_full_key);
        byteBuffer x963_ec_full_key_default = hexStringToBytes(test_vector->str_fips_x963_full_key); // Default is FIPS
        byteBuffer salt = hexStringToBytes(test_vector->str_salt);

        // Legacy
        ok_or_fail(ccrng_pbkdf2_prng_init(&pbkdf2_prng, 2*ccn_sizeof(ccec_cp_order_bitlen(cp)),
                                          strlen(test_vector->password), test_vector->password,
                                          salt->len, salt->bytes, iterations)==0,"pbkdf2 init");
        if (x963_ec_full_key_legacy->len &&
           (is(ccec_generate_key_legacy(cp, rng2, full_key),0, "Generate Legacy"))) {
            ok(ccec_keys_are_equal(full_key,x963_ec_full_key_legacy,i), "Check legacy key");
        }

        // FIPS
        ok_or_fail(ccrng_pbkdf2_prng_init(&pbkdf2_prng, 8*ccn_sizeof(ccec_cp_order_bitlen(cp)),
                                          strlen(test_vector->password), test_vector->password,
                                          salt->len, salt->bytes, iterations)==0,"pbkdf2 init");
        if (x963_ec_full_key_fips->len &&
            (is(ccec_generate_key_fips(cp, rng2, full_key),0, "Generate FIPS"))) {
                ok(ccec_keys_are_equal(full_key,x963_ec_full_key_fips,i), "Check FIPS key");
        }

        // Compact
        ok_or_fail(ccrng_pbkdf2_prng_init(&pbkdf2_prng, 8*ccn_sizeof(ccec_cp_order_bitlen(cp)),
                                          strlen(test_vector->password), test_vector->password,
                                          salt->len, salt->bytes, iterations)==0,"pbkdf2 init");
        if (x963_ec_full_key_compact->len &&
            (is(ccec_compact_generate_key(cp, rng2, full_key),0, "Generate compact"))) {
                ok(ccec_keys_are_equal(full_key,x963_ec_full_key_compact,i), "Check compact key");
        }

        // Default
        ok_or_fail(ccrng_pbkdf2_prng_init(&pbkdf2_prng, 8*ccn_sizeof(ccec_cp_order_bitlen(cp)),
                                          strlen(test_vector->password), test_vector->password,
                                          salt->len, salt->bytes, iterations)==0,"pbkdf2 init");
        if (x963_ec_full_key_default->len &&
            (is(ccec_generate_key(cp, rng2, full_key),0, "Generate default"))) {
                ok(ccec_keys_are_equal(full_key,x963_ec_full_key_default,i), "Check default key");
        }

        free(x963_ec_full_key_legacy);
        free(x963_ec_full_key_fips);
        free(x963_ec_full_key_compact);
        free(x963_ec_full_key_default);
        free(salt);
    }
    return 1;
}

static void fill(int *guard) {
    guard[0] = -1;
    guard[1] = -1;
    guard[2] = -1;
    guard[3] = -1;
}

static int chkit(int *guard) {
    return guard[0] == -1 &&
    guard[1] == -1 &&
    guard[2] == -1 &&
    guard[3] == -1;
}

static int
ECCompactGenTest(struct ccrng_state *rng, size_t expected_keysize, ccec_const_cp_t cp)
{
    int top[4];
    ccec_full_ctx_decl_cp(cp, full_key1); ccec_ctx_init(cp, full_key1);
    ccec_full_ctx_decl_cp(cp, full_key2); ccec_ctx_init(cp, full_key2);
    int bottom[4];
    
    fill(top); fill(bottom);
    ok_or_fail(ccec_compact_generate_key(cp, rng, full_key1) == 0, "Generated Key 1");
    ok_or_fail(ccec_compact_generate_key(cp, rng, full_key2) == 0, "Generated Key 2");
    
    if(!chkit(top) || !chkit(bottom)) diag("ALARM");
    
    int status = 0;
    if(verbose) diag("Compact Test with keysize %u", expected_keysize);
    ok_or_goto(ccec_ctx_bitlen(full_key1) == expected_keysize, "Generated correct keysize 1", errout);
    ok_or_goto(ccec_ctx_bitlen(full_key2) == expected_keysize, "Generated correct keysize 2", errout);
    ok_or_goto(export_import_compact(full_key1,rng), "Import Export compact format", errout);
    ok_or_goto(key_exchange_compact(full_key1,full_key2), "EC Construction Tests", errout);
    status = 1;
errout:
    return status;
}


static int
ECStdGenTest(struct ccrng_state *rng, size_t expected_keysize, ccec_const_cp_t cp, int fips)
{
    int top[4];
    ccec_full_ctx_decl_cp(cp, full_key); ccec_ctx_init(cp, full_key);
    int bottom[4];
    
    fill(top); fill(bottom);
    if(fips) ok_or_fail(ccec_generate_key_fips(cp, rng, full_key) == 0, "Generated Key");
    else ok_or_fail(ccecdh_generate_key(cp, rng, full_key) == 0, "Generated Key");

    if(!chkit(top) || !chkit(bottom)) diag("ALARM");
    
    int status = 0;
    if(verbose) diag("Test with keysize %u", expected_keysize);
    ok_or_goto(ccec_ctx_bitlen(full_key) == expected_keysize, "Generated correct keysize", errout);
    ok_or_goto(round_trip_tests(full_key), "EC Round-Trip Key Tests", errout);
    ok_or_goto(construction(full_key), "EC Construction Tests", errout);
    status = 1;
errout:
    return status;
}

#define FIPS 1
#define ECDH 0

int ccec_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    struct ccrng_state *rng = global_test_rng;
    int stdgen = 1;
    int stddhgen = 1;
    int staticgen = 1;
    int pgpwrap = 1;
    int compact = 1;
    
	plan_tests(kTestTestCount);

    if(verbose) diag("KeyGen KATs");
    ok(eckeygen_tests(), "KeyGen KATs");

    if(verbose) diag("ECDSA KATs");
    ok(ecdsa_known_answer_tests(), "ECDSA KATs");

    if(verbose) diag("ECDSA Negative tests");
    ok(ecdsa_negative_tests(), "ECDSA Negative tests");

    if(verbose) diag("ECDH KATs");
    ok(ecdh_known_answer_tests(), "ECDH KATs");

    if(verbose) diag("ECDH Negative tests");
    ok(ecdh_negative_tests(), "ECDH Negative tests");

    fputs("\n", stdout);

    if(verbose) diag("Zero Gen FIPS Tests");
        ok(ECZeroGenFIPSTest(224, ccec_cp_224()), "Generate 224 bit EC Key Pair");
        ok(ECZeroGenFIPSTest(256, ccec_cp_256()), "Generate 256 bit EC Key Pair");
        ok(ECZeroGenFIPSTest(521, ccec_cp_521()), "Generate 521 bit EC Key Pair");
        if(verbose) diag_linereturn();

    if(stdgen) {
        if(verbose) diag("Standard Gen Tests");
        ok(ECStdGenTest(rng, 192, ccec_cp_192(), FIPS), "Generate 192 bit EC(FIPS) Key Pair");
        ok(ECStdGenTest(rng, 224, ccec_cp_224(), FIPS), "Generate 224 bit EC(FIPS) Key Pair");
        ok(ECStdGenTest(rng, 256, ccec_cp_256(), FIPS), "Generate 256 bit EC(FIPS) Key Pair");
        ok(ECStdGenTest(rng, 384, ccec_cp_384(), FIPS), "Generate 384 bit EC(FIPS) Key Pair");
        ok(ECStdGenTest(rng, 521, ccec_cp_521(), FIPS), "Generate 521 bit EC(FIPS) Key Pair");
        if(verbose) diag_linereturn();
    } /* stdgen */
    
    if(stddhgen) {

        if(verbose) diag("Standard ECDH Tests");
        ok(ECStdGenTest(rng, 192, ccec_cp_192(), ECDH), "Generate 192 bit ECDH Key Pair");
        ok(ECStdGenTest(rng, 224, ccec_cp_224(), ECDH), "Generate 224 bit ECDH Key Pair");
        ok(ECStdGenTest(rng, 256, ccec_cp_256(), ECDH), "Generate 256 bit ECDH Key Pair");
        ok(ECStdGenTest(rng, 384, ccec_cp_384(), ECDH), "Generate 384 bit ECDH Key Pair");
        ok(ECStdGenTest(rng, 521, ccec_cp_521(), ECDH), "Generate 521 bit ECDH Key Pair");
        if(verbose) diag_linereturn();
    } /* stddhgen */
    
    if(staticgen) {
        if(verbose) diag("Static Gen Tests");
        ok(ECStaticGenTest(), "Generate Static EC Key Pairs");
        if(verbose) diag_linereturn();
    } /* stdgen */
    
    if(compact) {
        if(verbose) diag("Compact representation");
        ok(ECCompactGenTest(rng, 192, ccec_cp_192()), "Generate 192 bit EC Key Pair");
        //ok(ECCompactGenTest(rng, 224, ccec_cp_224()), "Generate 224 bit EC Key Pair"); Not supported yet because of sqrt
        ok(ECCompactGenTest(rng, 256, ccec_cp_256()), "Generate 256 bit EC Key Pair");
        ok(ECCompactGenTest(rng, 384, ccec_cp_384()), "Generate 384 bit EC Key Pair");
        ok(ECCompactGenTest(rng, 521, ccec_cp_521()), "Generate 521 bit EC Key Pair");
        if(verbose) diag_linereturn();
    } /* stdgen */
    
    if(verbose) diag("Zero Gen Tests");
        ok(ECZeroGenTest(256, ccec_cp_256()), "Generate 256 bit EC Key Pair");
    if(verbose) diag_linereturn();

    if (pgpwrap) {
        if(verbose) diag("EC Wrapping tests");
        ok(ecwrapping_tests(),"EC Wrapping tests");
    }
    return 0;
}

#endif


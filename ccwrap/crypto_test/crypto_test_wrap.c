/*
 * Copyright (c) 2012,2015,2016,2017,2018 Apple Inc. All rights reserved.
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

static int verbose = 0;

#if (CCWRAP == 0)
entryPoint(ccwrap_tests,"ccwrap test")
#else
#include <corecrypto/ccmode.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccwrap.h>

#define KEY128 "000102030405060708090a0b0c0d0e0f"
#define KEY192 "000102030405060708090a0b0c0d0e0f0001020304050607"
#define KEY256 "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"
#define KEY512 "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"

struct ccwrap_vector {
    size_t count;
    const char *kek; // Key to encrypt the input
    const char *key; // Input
    const char *wrap; // Wrapped input
    int error;
};

const struct ccwrap_vector ccwrap_aes_vectors[]=
{
// Toy sample
    {
        .count = 0,
        .kek = "f59782f1dceb0544a8da06b34969b9212b55ce6dcbdd0975a33f4b3f88b538da",
        .key = "73d33060b5f9f2eb5785c0703ddfa704",
        .wrap = "2e63946ea3c090902fa1558375fdb2907742ac74e39403fc",
        .error = 0,
    },
// Test vectors
#include "../test_vectors/KW_AD_128.inc"
#include "../test_vectors/KW_AD_192.inc"
#include "../test_vectors/KW_AD_256.inc"
#include "../test_vectors/KW_AE_128.inc"
#include "../test_vectors/KW_AE_192.inc"
#include "../test_vectors/KW_AE_256.inc"
};

static int test_wrap(const struct ccmode_ecb *enc_ecb,
                     const struct ccmode_ecb *dec_ecb,
                     const char *keydata,
                     const char *kekdata) {
    ccecb_ctx_decl(enc_ecb->size, enc_ctx);
    ccecb_ctx_decl(dec_ecb->size, dec_ctx);
    byteBuffer kek = hexStringToBytes(kekdata);

    ccecb_init(enc_ecb, enc_ctx, kek->len, kek->bytes);
    ccecb_init(dec_ecb, dec_ctx, kek->len, kek->bytes);
    
    byteBuffer key = hexStringToBytes(keydata);
    size_t wrapped_size =  ccwrap_wrapped_size(key->len);
    byteBuffer wrapped_key = mallocByteBuffer(wrapped_size);

    
    ok(ccwrap_auth_encrypt(enc_ecb, enc_ctx,
                           key->len, key->bytes,
                           &wrapped_size, wrapped_key->bytes) == 0, "Wrapped Key");
    
    size_t unwrapped_size =  ccwrap_unwrapped_size(wrapped_size);
    byteBuffer unwrapped_key = mallocByteBuffer(unwrapped_size);

    ok(ccwrap_auth_decrypt(dec_ecb, dec_ctx,
                           wrapped_key->len, wrapped_key->bytes,
                           &unwrapped_size, unwrapped_key->bytes) == 0, "Unwrapped Key");
    ok(bytesAreEqual(key, unwrapped_key), "Round Trip Success");
    free(kek);
    free(key);
    free(wrapped_key);
    free(unwrapped_key);
    return 1;
}

static int test_kat_wrap(const struct ccmode_ecb *enc_ecb,
                     const struct ccmode_ecb *dec_ecb,
                     const struct ccwrap_vector *tv) {
    ccecb_ctx_decl(enc_ecb->size, enc_ctx);
    ccecb_ctx_decl(dec_ecb->size, dec_ctx);
    byteBuffer kek = hexStringToBytes(tv->kek);
    byteBuffer key = hexStringToBytes(tv->key);
    int rc = 1;
    int error;

    size_t wrapped_size =  ccwrap_wrapped_size(key->len);
    size_t unwrapped_size =  ccwrap_unwrapped_size(wrapped_size);
    byteBuffer computed_wrapped_key = mallocByteBuffer(wrapped_size);
    byteBuffer expected_wrapped_key = hexStringToBytes(tv->wrap);
    byteBuffer unwrapped_key = mallocByteBuffer(unwrapped_size);

    rc &= is(ccecb_init(enc_ecb, enc_ctx, kek->len, kek->bytes),0, "Enc init");
    rc &= is(ccecb_init(dec_ecb, dec_ctx, kek->len, kek->bytes),0, "Dec init");

    if (tv->error==0) {
        rc &= is(ccwrap_auth_encrypt(enc_ecb, enc_ctx,
                           key->len, key->bytes,
                           &wrapped_size, computed_wrapped_key->bytes),0, "Wrapped Key");
        rc &= ok(bytesAreEqual(computed_wrapped_key, expected_wrapped_key), "Wrap Success");
    } else {
        pass("Wrapping");
        pass("Wrapped data");
    }

    error=ccwrap_auth_decrypt(dec_ecb, dec_ctx,
                           wrapped_size, computed_wrapped_key->bytes,
                           &unwrapped_size, unwrapped_key->bytes);

    rc &= is(error,tv->error,"Unwrapping");
    if (tv->error==0) {
        rc &= ok(bytesAreEqual(key, unwrapped_key), "Round Trip Success");
    } else {
        pass("Unwrapping data");
    }

    free(kek);
    free(key);
    free(computed_wrapped_key);
    free(expected_wrapped_key);
    free(unwrapped_key);
    return rc;
}

static int test_ccwrap_wrapped_size(void)
{
    size_t i;
    size_t vectors[][2] = {
        {CCWRAP_SEMIBLOCK * 2, CCWRAP_SEMIBLOCK * 3},
        {0, CCWRAP_SEMIBLOCK},
    };
    size_t nvectors = (sizeof vectors) / (sizeof vectors[0]);
    int rc = 0;
    
    for (i = 0; i < nvectors; i += 1) {
        rc |= is(ccwrap_wrapped_size(vectors[i][0]), vectors[i][1], "Unwrapped size");
    }
    
    return rc;
}

static int test_ccwrap_unwrapped_size(void)
{
    size_t i;
    size_t vectors[][2] = {
        {CCWRAP_SEMIBLOCK * 3, CCWRAP_SEMIBLOCK * 2},
        {CCWRAP_SEMIBLOCK, 0},
        {CCWRAP_SEMIBLOCK - 1, 0},
        {0, 0},
    };
    size_t nvectors = (sizeof vectors) / (sizeof vectors[0]);
    int rc = 0;
    
    for (i = 0; i < nvectors; i += 1) {
        rc |= is(ccwrap_unwrapped_size(vectors[i][0]), vectors[i][1], "Unwrapped size");
    }

    return rc;
}

static int test_ccwrap_auth_encrypt_bad_nbytes(void)
{
    int rc = 0;
    const struct ccmode_ecb *enc_ecb = ccaes_ecb_encrypt_mode();
    ccecb_ctx_decl(enc_ecb->size, enc_ctx);
    byteBuffer kek = hexStringToBytes(KEY128);
    
    ccecb_init(enc_ecb, enc_ctx, kek->len, kek->bytes);
    
    size_t i;
    size_t vectors[] = {
        CCWRAP_SEMIBLOCK,
        CCWRAP_SEMIBLOCK*2 + 1,
        
        // this amount is only valid in the unwrap direction
        CCWRAP_SEMIBLOCK*CCWRAP_MAXSEMIBLOCKS,
    };
    size_t nvectors = sizeof vectors / sizeof vectors[0];
    
    for (i = 0; i < nvectors; i += 1) {
        size_t nbytes = vectors[i];
        size_t obytes = ccwrap_wrapped_size(nbytes);
        uint8_t key[nbytes];
        uint8_t wrapped[obytes];

        rc |= is(ccwrap_auth_encrypt(enc_ecb, enc_ctx,
                                     nbytes, key,
                                     &obytes, wrapped),
                 -1, "encrypt bad nbytes");
    }
    
    free(kek);
    return rc;
}

static int test_ccwrap_auth_decrypt_bad_nbytes(void)
{
    int rc = 0;
    const struct ccmode_ecb *dec_ecb = ccaes_ecb_decrypt_mode();
    ccecb_ctx_decl(dec_ecb->size, dec_ctx);
    byteBuffer kek = hexStringToBytes(KEY128);
    
    ccecb_init(dec_ecb, dec_ctx, kek->len, kek->bytes);
    
    size_t i;
    size_t vectors[] = {
        CCWRAP_SEMIBLOCK*2,
        CCWRAP_SEMIBLOCK*3 + 1,
        CCWRAP_SEMIBLOCK*(CCWRAP_MAXSEMIBLOCKS + 1),
    };
    size_t nvectors = sizeof vectors / sizeof vectors[0];
    
    for (i = 0; i < nvectors; i += 1) {
        size_t nbytes = vectors[i];
        size_t obytes = ccwrap_unwrapped_size(nbytes);
        uint8_t wrapped[nbytes];
        uint8_t key[obytes];

        rc |= is(ccwrap_auth_decrypt(dec_ecb, dec_ctx,
                                     nbytes, wrapped,
                                     &obytes, key),
                 -1, "decrypt bad nbytes");
    }
    
    free(kek);
    return rc;
}

int ccwrap_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
	plan_tests(21059);
    if(verbose) diag("Starting ccwrap tests\n");
    const struct ccmode_ecb *enc_ecb = ccaes_ecb_encrypt_mode();
    const struct ccmode_ecb *dec_ecb = ccaes_ecb_decrypt_mode();

    for (size_t i=0;i<sizeof(ccwrap_aes_vectors)/sizeof(struct ccwrap_vector);i++) {
        ok(test_kat_wrap(enc_ecb, dec_ecb,&ccwrap_aes_vectors[i]),
           "AES key size %u, plaintext size %u, count %d",
           ccwrap_aes_vectors[i].kek==NULL?0:strlen(ccwrap_aes_vectors[i].kek)/2,
           ccwrap_aes_vectors[i].key==NULL?0:strlen(ccwrap_aes_vectors[i].key)/2,
           ccwrap_aes_vectors[i].count);
    }

    ok(test_wrap(enc_ecb, dec_ecb, KEY128, KEY128), "ccwrap of 128 bit key with 128 bit kek");
    ok(test_wrap(enc_ecb, dec_ecb, KEY256, KEY128), "ccwrap of 256 bit key with 128 bit kek");
    ok(test_wrap(enc_ecb, dec_ecb, KEY512, KEY128), "ccwrap of 512 bit key with 128 bit kek");
    ok(test_wrap(enc_ecb, dec_ecb, KEY128, KEY192), "ccwrap of 128 bit key with 192 bit kek");
    ok(test_wrap(enc_ecb, dec_ecb, KEY256, KEY192), "ccwrap of 256 bit key with 192 bit kek");
    ok(test_wrap(enc_ecb, dec_ecb, KEY512, KEY192), "ccwrap of 512 bit key with 192 bit kek");
    ok(test_wrap(enc_ecb, dec_ecb, KEY128, KEY256), "ccwrap of 128 bit key with 256 bit kek");
    ok(test_wrap(enc_ecb, dec_ecb, KEY256, KEY256), "ccwrap of 256 bit key with 256 bit kek");
    ok(test_wrap(enc_ecb, dec_ecb, KEY512, KEY256), "ccwrap of 512 bit key with 256 bit kek");
    
    ok(test_ccwrap_wrapped_size(), "wrapped size");
    ok(test_ccwrap_unwrapped_size(), "unwrapped size");
    ok(test_ccwrap_auth_encrypt_bad_nbytes(), "encrypt bad nbytes");
    ok(test_ccwrap_auth_decrypt_bad_nbytes(), "decrypt bad nbytes");
    
    return 0;
}
#endif


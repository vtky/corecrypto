/*
 * Copyright (c) 2014,2015,2016,2017,2018 Apple Inc. All rights reserved.
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

#include <corecrypto/ccaes.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccmode_factory.h>
#include <corecrypto/ccmode_internal.h>
#include <corecrypto/ccn.h>

#include "crypto_test_modes.h"
#include "testbyteBuffer.h"
#include "testmore.h"

static int verbose = 0;

typedef struct ccgcm_test_t {
    char *keyStr;     //key
    char *aDataStr;     //additional data
    char *init_ivStr;      //initialization vector
    char *ptStr;      //plain text
    char *ctStr;      //cipher text
    char *tagStr;     //tag
} ccgcm_test_vector;

ccgcm_test_vector gcm_vectors[]={
#include "../test_vectors/aes_gcm_test_vectors_ossl.inc"
#include "../test_vectors/aes_gcm_test_vectors.inc"
};

size_t nvectors = sizeof(gcm_vectors) / sizeof(ccgcm_test_vector);

static int ccgcm_discrete(const struct ccmode_gcm *mode,
                          size_t key_len, const void *key,
                          size_t iv_len, const void *iv,
                          size_t adata_len, const void *adata,
                          size_t nbytes, const void *in, void *out,
                          size_t tag_len, void *tag)
{
    size_t max_block_len = cc_rand(19); if(max_block_len==0) max_block_len=1;
    if(verbose) printf("\n------max_block_len=%zu\n", max_block_len);
    int rc = 0;

    ccgcm_ctx_decl(mode->size, ctx);
    mode->init(mode, ctx, key_len, key);

    if(iv_len > 0 && iv != NULL) {
        rc |= mode->set_iv(ctx, iv_len, iv);
    }

    if(adata_len > 0 && adata != NULL) {
        if (adata_len>max_block_len) {
            size_t d1 = adata_len-max_block_len;
            rc |= mode->gmac(ctx, max_block_len, adata);
            rc |= mode->gmac(ctx, d1, adata+max_block_len);
        } else {
            rc |= mode->gmac(ctx, adata_len, adata);
        }
    } else {
        if(verbose) printf("Skipping added AAD\n");
    }

    if(nbytes > 0) {
        rc |= mode->gcm(ctx, nbytes, in, out);
    } else {
        if(verbose) printf("Skipping data\n");
    }

    rc |= mode->finalize(ctx, tag_len, tag);
    ccgcm_ctx_clear(mode->size, ctx);

    return rc;
}

static int compare(const void *base, const void *result, size_t nbytes)
{
    if(base) {
        return memcmp(base, result, nbytes);
    } else {
        byteBuffer res = bytesToBytes(base, nbytes);
        diag("produced\n");
        printByteBufferAsCharAssignment(res , "Str");
        free(res);
        return 0;
    }
}


typedef int (*ccgcm_test_func_t)(const struct ccmode_gcm *mode,
size_t key_len, const void *key,
size_t iv_len, const void *iv,
size_t adata_len, const void *adata,
size_t nbytes, const void *in, void *out,
size_t tag_len, void *tag);



static int gcm_test_a_function(const struct ccmode_gcm *em, const struct ccmode_gcm *dm,
                               size_t key_len, const void *key,
                               size_t iv_len, const void *iv,
                               size_t adata_len, const void *adata,
                               size_t nbytes, const void *plaintext, void *ciphertext,
                               size_t tag_len, void *tag,
                               ccgcm_test_func_t func)
{

    uint8_t cipher_result[nbytes], plain_result[nbytes];
    uint8_t cipher_tag[tag_len], plain_tag[tag_len];
    int rc;

    rc = func(em, key_len, key, iv_len, iv, adata_len, adata, nbytes, plaintext,     cipher_result, tag_len, cipher_tag);
    ok_or_fail(rc==0, "gcm encryption failed");
    memcpy(plain_tag, tag, tag_len); //set the expected tag for decryption
    rc = func(dm, key_len, key, iv_len, iv, adata_len, adata, nbytes, cipher_result, plain_result,  tag_len, plain_tag );
    ok_or_fail(rc==0, "gcm decryption failed");

    ok_or_fail(compare(plaintext, plain_result, nbytes)==0, "Round Trip Encrypt/Decrypt works");
    ok_or_fail(compare(tag, cipher_tag, tag_len)==0, "tags match on encrypt");
    ok_or_fail(compare(tag, plain_tag, tag_len)==0, "tags match on decrypt");
    ok_or_fail(compare(ciphertext, cipher_result, nbytes)==0, "Ciphertext matches known answer");

    return 1;

}

static int gcm_testcase(const struct ccmode_gcm *encrypt_ciphermode, const struct ccmode_gcm *decrypt_ciphermode, size_t casenum)
{
    size_t i=casenum;
    byteBuffer key = hexStringToBytes(gcm_vectors[i].keyStr);
    byteBuffer iv = hexStringToBytes(gcm_vectors[i].init_ivStr);
    byteBuffer adata = hexStringToBytes(gcm_vectors[i].aDataStr);
    byteBuffer plaintext = hexStringToBytes(gcm_vectors[i].ptStr);
    byteBuffer ciphertext = hexStringToBytes(gcm_vectors[i].ctStr);
    byteBuffer tag = hexStringToBytes(gcm_vectors[i].tagStr);

    if(verbose) printf("GCM Case %zu\n", casenum);

    gcm_test_a_function(encrypt_ciphermode, decrypt_ciphermode,
                        key->len, key->bytes,
                        iv->len, iv->bytes,
                        adata->len, adata->bytes,
                        plaintext->len,
                        plaintext->bytes, ciphertext->bytes,
                        tag->len, tag->bytes,
                        ccgcm_discrete);

    gcm_test_a_function(encrypt_ciphermode, decrypt_ciphermode,
                        key->len, key->bytes,
                        iv->len, iv->bytes,
                        adata->len, adata->bytes,
                        plaintext->len,
                        plaintext->bytes, ciphertext->bytes,
                        tag->len, tag->bytes,
                        ccgcm_one_shot);

    gcm_test_a_function(encrypt_ciphermode, decrypt_ciphermode,
                        key->len, key->bytes,
                        iv->len, iv->bytes,
                        adata->len, adata->bytes,
                        plaintext->len,
                        plaintext->bytes, ciphertext->bytes,
                        tag->len, tag->bytes,
                        ccgcm_one_shot_legacy);

    free(key);
    free(iv);
    free(adata);
    free(plaintext);
    free(ciphertext);
    free(tag);
    return 1;

}

static int gcm_test_zerolen_iv(const struct ccmode_gcm *encrypt_ciphermode, const struct ccmode_gcm *decrypt_ciphermode)
{
    int rc;

    byteBuffer key = hexStringToBytes("59454c4c4f57205355424d4152494e45");
    byteBuffer ad = hexStringToBytes("0000005a");
    byteBuffer ptext = hexStringToBytes("506f69736f6e6f7573207061726167726170687320736d61736820796f75722070686f6e6f677261706820696e2068616c660a49742062652074686520496e73706563746168204465636b206f6e207468652077617270617468");
    byteBuffer ctext = hexStringToBytes("3a8fbd9d5e5d53663664c8a67ca82c22d09b932a18fb18a37814330955bf55b73aef15a678182f42b9b0f7d8137b7c30dc09123ab9b150b8e04d65532e223e6a4eacc98275f75e113e9daf8598b7445fe04ec754bfe914bd65e8");
    byteBuffer tag = hexStringToBytes("226a3338b54f22819e933c242746f303");

    uint8_t textout[ptext->len];
    uint8_t tagout[tag->len];

    rc = ccgcm_one_shot(encrypt_ciphermode, key->len, key->bytes, 0, NULL, ad->len, ad->bytes, ptext->len, ptext->bytes, textout, sizeof (tagout), tagout);
    ok_or_fail(rc != 0, "gcm one-shot encryption accepted zero-length iv");

    rc = ccgcm_discrete(encrypt_ciphermode, key->len, key->bytes, 0, NULL, ad->len, ad->bytes, ptext->len, ptext->bytes, textout, sizeof (tagout), tagout);
    ok_or_fail(rc != 0, "gcm discrete encryption accepted zero-length iv");

    rc = ccgcm_one_shot_legacy(encrypt_ciphermode, key->len, key->bytes, 0, NULL, ad->len, ad->bytes, ptext->len, ptext->bytes, textout, sizeof (tagout), tagout);
    ok_or_fail(rc == 0, "gcm one-shot legacy encryption failed");
    ok_or_fail(compare(ctext->bytes, textout, ctext->len) == 0, "gcm one-shot legacy encryption text mismatch");
    ok_or_fail(compare(tag->bytes, tagout, tag->len) == 0, "gcm one-shot legacy encryption tag mismatch");

    rc = ccgcm_one_shot(decrypt_ciphermode, key->len, key->bytes, 0, NULL, ad->len, ad->bytes, ctext->len, ctext->bytes, textout, sizeof (tagout), tagout);
    ok_or_fail(rc != 0, "gcm one-shot decryption accepted zero-length iv");

    rc = ccgcm_discrete(decrypt_ciphermode, key->len, key->bytes, 0, NULL, ad->len, ad->bytes, ctext->len, ctext->bytes, textout, sizeof (tagout), tagout);
    ok_or_fail(rc != 0, "gcm discrete decryption accepted zero-length iv");

    rc = ccgcm_one_shot_legacy(decrypt_ciphermode, key->len, key->bytes, 0, NULL, ad->len, ad->bytes, ctext->len, ctext->bytes, textout, sizeof (tagout), tagout);
    ok_or_fail(rc == 0, "gcm legacy decryption failed");
    ok_or_fail(compare(ptext->bytes, textout, ptext->len) == 0, "gcm one-shot legacy decryption text mismatch");
    ok_or_fail(compare(tag->bytes, tagout, tag->len) == 0, "gcm one-shot legacy decryption tag mismatch");

    free(key);
    free(tag);
    free(ad);
    free(ptext);
    free(ctext);
    return 1;
}

static int gcm_test_init_with_iv(const struct ccmode_gcm *encrypt_ciphermode, const struct ccmode_gcm *decrypt_ciphermode)
{
    // int rc;

    byteBuffer key = hexStringToBytes("e792232af1917965d75fc9b65a87f656");
    byteBuffer iv1 = hexStringToBytes("c7ccdafe0000000000000000");
    byteBuffer iv2 = hexStringToBytes("c7ccdafe0000000000000001");
    byteBuffer ad = hexStringToBytes("04d7e6bd00cca0947da2");
    byteBuffer ptext = hexStringToBytes("576f772c20746865205368616f6c696e207374796c6520697320616c6c20696e206d650a4368696c642c207468652077686f6c652064616d6e2069736c652069732063616c6c696e206d650a");
    byteBuffer ctext1 = hexStringToBytes("f90a4f9c1250849af5289066aad8c10f67ffc2ca5799e58d8b49cc6f22c495f56f46adb18c3b21b4710306dffc88ce9a7252ba92b74b35db08221d8dca7aed27105b0d1a812bd10e49af2345");
    byteBuffer tag1 = hexStringToBytes("73d833e2d55d741743b09e0e07c6d610");
    byteBuffer ctext2 = hexStringToBytes("d075317f57fc20ff37832f507e90c84fd311a0a160b59084217b642829028dcef56ffa73db659bf250ab97eda2df50635d1fc29f6e2dbbc651acd4e747ed7577805a61708bec9ad8e272cce4");
    byteBuffer tag2 = hexStringToBytes("298184a805bede8490c0da2cf19e7b0e");

    uint8_t ivout[iv1->len];
    uint8_t textout[ptext->len];
    uint8_t tagout[tag1->len];

    ccgcm_ctx_decl(ccgcm_context_size(encrypt_ciphermode), encrypt_ctx);
    ccgcm_ctx_decl(ccgcm_context_size(decrypt_ciphermode), decrypt_ctx);

    ok_or_fail(ccgcm_init_with_iv(encrypt_ciphermode, encrypt_ctx, key->len, key->bytes, iv1->bytes) == 0, "ccgcm_init_with_iv encrypt1");
    ok_or_fail(ccgcm_aad(encrypt_ciphermode, encrypt_ctx, ad->len, ad->bytes) == 0, "ccgcm_aad encrypt1");
    ok_or_fail(ccgcm_update(encrypt_ciphermode, encrypt_ctx, ptext->len, ptext->bytes, textout) == 0, "ccgcm_update encrypt1");
    ok_or_fail(ccgcm_finalize(encrypt_ciphermode, encrypt_ctx, tag1->len, tagout) == 0, "ccgcm_finalize encrypt1");
    ok_memcmp(ctext1->bytes, textout, ctext1->len, "ctext1 encrypt1");
    ok_memcmp(tag1->bytes, tagout, tag1->len, "tag1 encrypt1");

    ok_or_fail(ccgcm_init_with_iv(decrypt_ciphermode, decrypt_ctx, key->len, key->bytes, iv1->bytes) == 0, "ccgcm_init_with_iv decrypt1");
    ok_or_fail(ccgcm_aad(decrypt_ciphermode, decrypt_ctx, ad->len, ad->bytes) == 0, "ccgcm_aad decrypt1");
    ok_or_fail(ccgcm_update(decrypt_ciphermode, decrypt_ctx, ctext1->len, ctext1->bytes, textout) == 0, "ccgcm_update decrypt1");
    ok_or_fail(ccgcm_finalize(decrypt_ciphermode, decrypt_ctx, tag1->len, tagout) == 0, "ccgcm_finalize decrypt1");
    ok_memcmp(ptext->bytes, textout, ptext->len, "ptext decrypt1");
    ok_memcmp(tag1->bytes, tagout, tag1->len, "tag1 decrypt1");

    ok_or_fail(ccgcm_reset(encrypt_ciphermode, encrypt_ctx) == 0, "ccgcm_reset encrypt2");
    ok_or_fail(ccgcm_inc_iv(encrypt_ciphermode, encrypt_ctx, ivout) == 0, "ccgcm_inc_iv encrypt2");
    ok_or_fail(ccgcm_aad(encrypt_ciphermode, encrypt_ctx, ad->len, ad->bytes) == 0, "ccgcm_aad encrypt2");
    ok_or_fail(ccgcm_update(encrypt_ciphermode, encrypt_ctx, ptext->len, ptext->bytes, textout) == 0, "ccgcm_update encrypt2");
    ok_or_fail(ccgcm_finalize(encrypt_ciphermode, encrypt_ctx, tag2->len, tagout) == 0, "ccgcm_finalize encrypt2");
    ok_memcmp(iv2->bytes, ivout, iv2->len, "iv2 encrypt2");
    ok_memcmp(ctext2->bytes, textout, ctext2->len, "ctext2 encrypt2");
    ok_memcmp(tag2->bytes, tagout, tag2->len, "tag2 encrypt2");

    ok_or_fail(ccgcm_reset(decrypt_ciphermode, decrypt_ctx) == 0, "ccgcm_reset decrypt2");
    ok_or_fail(ccgcm_inc_iv(decrypt_ciphermode, decrypt_ctx, ivout) == 0, "ccgcm_inc_iv decrypt2");
    ok_or_fail(ccgcm_aad(decrypt_ciphermode, decrypt_ctx, ad->len, ad->bytes) == 0, "ccgcm_aad decrypt2");
    ok_or_fail(ccgcm_update(decrypt_ciphermode, decrypt_ctx, ctext2->len, ctext2->bytes, textout) == 0, "ccgcm_update decrypt2");
    ok_or_fail(ccgcm_finalize(decrypt_ciphermode, decrypt_ctx, tag2->len, tagout) == 0, "ccgcm_finalize decrypt2");
    ok_memcmp(iv2->bytes, ivout, iv2->len, "iv2 decrypt2");
    ok_memcmp(ptext->bytes, textout, ptext->len, "ptext decrypt2");
    ok_memcmp(tag2->bytes, tagout, tag2->len, "tag2 decrypt2");

    ok_or_fail(ccgcm_init_with_iv(encrypt_ciphermode, encrypt_ctx, key->len, key->bytes, iv1->bytes) == 0, "ccgcm_init_with_iv encrypt no-set-iv");
    ok_or_fail(ccgcm_reset(encrypt_ciphermode, encrypt_ctx) == 0, "ccgcm_reset encrypt no-set-iv");
    ok_or_fail(ccgcm_set_iv(encrypt_ciphermode, encrypt_ctx, iv2->len, iv2->bytes) != 0, "ccgcm_set_iv encrypt no-set-iv");

    ok_or_fail(ccgcm_init_with_iv(decrypt_ciphermode, decrypt_ctx, key->len, key->bytes, iv1->bytes) == 0, "ccgcm_init_with_iv decrypt no-set-iv");
    ok_or_fail(ccgcm_reset(decrypt_ciphermode, decrypt_ctx) == 0, "ccgcm_reset decrypt no-set-iv");
    ok_or_fail(ccgcm_set_iv(decrypt_ciphermode, decrypt_ctx, iv2->len, iv2->bytes) != 0, "ccgcm_set_iv decrypt no-set-iv");

    ok_or_fail(ccgcm_init(encrypt_ciphermode, encrypt_ctx, key->len, key->bytes) == 0, "ccgcm_init_with_iv encrypt no-inc-iv");
    ok_or_fail(ccgcm_set_iv(encrypt_ciphermode, encrypt_ctx, iv1->len, iv1->bytes) == 0, "ccgcm_set_iv encrypt no-inc-iv");
    ok_or_fail(ccgcm_reset(encrypt_ciphermode, encrypt_ctx) == 0, "ccgcm_reset encrypt no-inc-iv");
    ok_or_fail(ccgcm_inc_iv(encrypt_ciphermode, encrypt_ctx, ivout) != 0, "ccgcm_set_iv encrypt no-inc-iv");

    ok_or_fail(ccgcm_init(decrypt_ciphermode, decrypt_ctx, key->len, key->bytes) == 0, "ccgcm_init_with_iv decrypt no-inc-iv");
    ok_or_fail(ccgcm_set_iv(decrypt_ciphermode, decrypt_ctx, iv1->len, iv1->bytes) == 0, "ccgcm_set_iv decrypt no-inc-iv");
    ok_or_fail(ccgcm_reset(decrypt_ciphermode, decrypt_ctx) == 0, "ccgcm_reset decrypt no-inc-iv");
    ok_or_fail(ccgcm_inc_iv(decrypt_ciphermode, decrypt_ctx, ivout) != 0, "ccgcm_set_iv decrypt no-inc-iv");


    free(key);
    free(iv1);
    free(iv2);
    free(ad);
    free(ptext);
    free(ctext1);
    free(tag1);
    free(ctext2);
    free(tag2);



    return 1;
}

/* In this test we reach into the internal state to trigger the validation error on long messages. */
static int gcm_test_counter_wrap(const struct ccmode_gcm *encrypt_ciphermode, const struct ccmode_gcm *decrypt_ciphermode)
{
    uint8_t buf[CCGCM_BLOCK_NBYTES] = { 0 };

    ccgcm_ctx_decl(ccgcm_context_size(encrypt_ciphermode), encrypt_ctx);
    ccgcm_ctx_decl(ccgcm_context_size(decrypt_ciphermode), decrypt_ctx);

    ok_or_fail(ccgcm_init(encrypt_ciphermode, encrypt_ctx, CCAES_KEY_SIZE_128, buf) == 0, "ccgcm_init encrypt counter wrap");
    ok_or_fail(ccgcm_set_iv(encrypt_ciphermode, encrypt_ctx, CCGCM_IV_NBYTES, buf) == 0, "ccgcm_set encrypt counter wrap");
    ok_or_fail(ccgcm_update(encrypt_ciphermode, encrypt_ctx, sizeof (buf), buf, buf) == 0, "ccgcm_update (begin) encrypt counter wrap");
    ((struct _ccmode_gcm_key *)encrypt_ctx)->text_nbytes = CCGCM_TEXT_MAX_NBYTES - CCGCM_BLOCK_NBYTES;
    ok_or_fail(ccgcm_update(encrypt_ciphermode, encrypt_ctx, sizeof (buf), buf, buf) == 0, "ccgcm_update (end) encrypt counter wrap");
    ok_or_fail(ccgcm_update(encrypt_ciphermode, encrypt_ctx, 1, buf, buf) == CCMODE_INVALID_INPUT, "ccgcm_update (overflow) encrypt counter wrap");

    ok_or_fail(ccgcm_init(decrypt_ciphermode, decrypt_ctx, CCAES_KEY_SIZE_128, buf) == 0, "ccgcm_init decrypt counter wrap");
    ok_or_fail(ccgcm_set_iv(decrypt_ciphermode, decrypt_ctx, CCGCM_IV_NBYTES, buf) == 0, "ccgcm_set decrypt counter wrap");
    ok_or_fail(ccgcm_update(decrypt_ciphermode, decrypt_ctx, sizeof (buf), buf, buf) == 0, "ccgcm_update (begin) decrypt counter wrap");
    ((struct _ccmode_gcm_key *)decrypt_ctx)->text_nbytes = CCGCM_TEXT_MAX_NBYTES - CCGCM_BLOCK_NBYTES;
    ok_or_fail(ccgcm_update(decrypt_ciphermode, decrypt_ctx, sizeof (buf), buf, buf) == 0, "ccgcm_update (end) decrypt counter wrap");
    ok_or_fail(ccgcm_update(decrypt_ciphermode, decrypt_ctx, 1, buf, buf) == CCMODE_INVALID_INPUT, "ccgcm_update (overflow) decrypt counter wrap");

    return 1;
}

int test_gcm(const struct ccmode_gcm *encrypt_ciphermode, const struct ccmode_gcm *decrypt_ciphermode)
{

    for(size_t i = 0; i < nvectors; i++) {
        gcm_testcase(  encrypt_ciphermode, decrypt_ciphermode, i);
    }

    gcm_test_zerolen_iv(encrypt_ciphermode, decrypt_ciphermode);

    gcm_test_init_with_iv(encrypt_ciphermode, decrypt_ciphermode);

    gcm_test_counter_wrap(encrypt_ciphermode, decrypt_ciphermode);

    return 1;
}

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

#include <corecrypto/ccmode.h>

#include "testmore.h"
#include "testbyteBuffer.h"
#include "crypto_test_modes.h"


struct ccmode_ctr_vector {
    size_t keylen;
    const void *key;
    const uint8_t *iv;
    size_t nbytes;
    const uint8_t *pt;
    const uint8_t *ct;
};

/* CTR */
int ccmode_ctr_test_one_vector(const struct ccmode_ctr *ctr, const struct ccmode_ctr_vector *v, int dec);

int ccmode_ctr_test_one_vector_chained(const struct ccmode_ctr *ctr, const struct ccmode_ctr_vector *v, int dec);

int ccmode_ctr_test_one_vector_chained2(const struct ccmode_ctr *ctr, const struct ccmode_ctr_vector *v, int dec);



/* does one CTR encryption or decryption and compare result */
static int ccmode_ctr_test_one(const struct ccmode_ctr *ctr, size_t keylen, const void *keydata,
                        const void *iv, size_t nbytes, const void *in, const void *out)
{
    unsigned char temp[nbytes];
    unsigned char temp2[nbytes];
    ccctr_ctx_decl(ctr->size, key);
    ccctr_init(ctr, key, keylen, keydata, iv);
    ccctr_update(ctr, key, nbytes, in, temp);
    
    ccctr_one_shot(ctr, keylen, keydata, iv, nbytes, in, temp2);
    return memcmp_print(out, temp, nbytes) || memcmp_print(out, temp2, nbytes);
}

/* Test one test vector - use dec=1 to reverse pt and ct */
int ccmode_ctr_test_one_vector(const struct ccmode_ctr *ctr, const struct ccmode_ctr_vector *v, int dec)
{
    if (dec)
        return ccmode_ctr_test_one(ctr, v->keylen, v->key, v->iv, v->nbytes, v->ct, v->pt);
    else
        return ccmode_ctr_test_one(ctr, v->keylen, v->key, v->iv, v->nbytes, v->pt, v->ct);
}

/* Test one test vector, 1 byte at a time */
static int ccmode_ctr_test_one_chained(const struct ccmode_ctr *ctr, size_t keylen, const void *keydata,
                                const void *iv, size_t nbytes, const void *in, const void *out)
{
    size_t i;
    const unsigned char *input=in;
    unsigned char temp[nbytes];
    ccctr_ctx_decl(ctr->size, key);
    ccctr_init(ctr, key, keylen, keydata, iv);
    for (i=0; i<nbytes; i++) {
        ccctr_update(ctr,key, 1, &input[i], &temp[i]);
    }
    
    return memcmp_print(out, temp, nbytes);
}

int ccmode_ctr_test_one_vector_chained(const struct ccmode_ctr *ctr, const struct ccmode_ctr_vector *v, int dec)
{
    if (dec)
        return ccmode_ctr_test_one_chained(ctr, v->keylen, v->key, v->iv, v->nbytes, v->ct, v->pt);
    else
        return ccmode_ctr_test_one_chained(ctr, v->keylen, v->key, v->iv, v->nbytes, v->pt, v->ct);
}

/* Test one test vector, 1 byte at a time */
static int ccmode_ctr_test_one_chained2(const struct ccmode_ctr *ctr, size_t keylen, const void *keydata,
                                 const void *iv, size_t nbytes, const void *in, const void *out)
{
    size_t i=0;
    const unsigned char *input=in;
    unsigned char temp[nbytes];
    ccctr_ctx_decl(ctr->size, key);
    ccctr_init(ctr, key, keylen, keydata, iv);
    if (nbytes>2*ctr->ecb_block_size+2) {
        ccctr_update(ctr,key, 1, &input[i], &temp[i]);
        i++;
        ccctr_update(ctr,key, 2*ctr->ecb_block_size, &input[i], &temp[i]);
        i+=2*ctr->ecb_block_size;
        ccctr_update(ctr,key, 1, &input[i], &temp[i]);
        i++;
    }
    for (; i<nbytes; i++) {
        ccctr_update(ctr,key, 1, &input[i], &temp[i]);
    }
    
    return memcmp_print(out, temp, nbytes);
}

int ccmode_ctr_test_one_vector_chained2(const struct ccmode_ctr *ctr, const struct ccmode_ctr_vector *v, int dec)
{
    if (dec)
        return ccmode_ctr_test_one_chained2(ctr, v->keylen, v->key, v->iv, v->nbytes, v->ct, v->pt);
    else
        return ccmode_ctr_test_one_chained2(ctr, v->keylen, v->key, v->iv, v->nbytes, v->pt, v->ct);
}


static int ctr(const char *name, const struct ccmode_ctr* enc, const ccsymmetric_test_vector *sym_vectors)
{
    int rc=1;
    for(unsigned int i=0; (&sym_vectors[i])->keyStr!=NULL; i++)
    {
        const ccsymmetric_test_vector*v=&sym_vectors[i];
        // Convert from generic test vector format containing string
        // to CTR format with hexadecimal values
        struct ccmode_ctr_vector ctr_v;
        byteBuffer key = hexStringToBytes(v->keyStr);
        byteBuffer init_iv = hexStringToBytes(v->init_ivStr);
        byteBuffer pt = hexStringToBytes(v->ptStr);
        byteBuffer ct = hexStringToBytes(v->ctStr);
        ctr_v.keylen=key->len;
        ctr_v.key=key->bytes;
        ctr_v.iv=init_iv->bytes;
        ctr_v.nbytes=pt->len;
        ctr_v.pt=pt->bytes;
        ctr_v.ct=ct->bytes;
        
        rc &= is(ccctr_block_size(enc),(size_t)1,"Granularity size == 1 Vector %d %s", i, name);
        rc &= is(enc->ecb_block_size,init_iv->len,"ECB block size == IV len Vector %d %s", i, name);
        
        // Test the vector
        rc &= ok(ccmode_ctr_test_one_vector(enc, &ctr_v, 0)==0, "Encrypt Vector %d %s", i, name);
        rc &= ok(ccmode_ctr_test_one_vector(enc, &ctr_v, 1)==0, "Decrypt Vector %d %s", i, name);
        
        rc &= ok(ccmode_ctr_test_one_vector_chained(enc, &ctr_v, 0)==0, "Encrypt Chained Vector %d %s", i, name);
        rc &= ok(ccmode_ctr_test_one_vector_chained(enc, &ctr_v, 1)==0, "Decrypt Chained Vector %d %s", i, name);
        
        rc &= ok(ccmode_ctr_test_one_vector_chained2(enc, &ctr_v, 0)==0, "Encrypt Chained Vector %d %s", i, name);
        rc &= ok(ccmode_ctr_test_one_vector_chained2(enc, &ctr_v, 1)==0, "Decrypt Chained Vector %d %s", i, name);
        
        free(key);
        free(init_iv);
        free(pt);
        free(ct);
    }
    return rc;
}

int test_ctr(const char *name, const struct ccmode_ctr *encrypt_ciphermode, const struct ccmode_ctr *decrypt_ciphermode,
             const ccsymmetric_test_vector *sym_vectors)
{
    int rc=1;
    rc &= ctr(name,encrypt_ciphermode,sym_vectors);
    rc &= ctr(name,decrypt_ciphermode,sym_vectors);
    return rc;
}



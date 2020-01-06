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

#include "testmore.h"
#include "testbyteBuffer.h"
#include "ccdrbg_test.h"
#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccdes.h>
#include <corecrypto/ccmode.h>

#if (CCDRBG == 0)
entryPoint(ccdrbg_tests,"ccdrbg")
#else

static struct ccdrbg_vector nistctr_aes128_df_vectors[] = {
#include "../test_vectors/CTR_DRBG-AES-128-df.inc"
};

static struct ccdrbg_vector nistctr_aes128_nodf_vectors[] = {
#include "../test_vectors/CTR_DRBG-AES-128-nodf.inc"
};

static struct ccdrbg_vector nistctr_aes192_df_vectors[] = {
#include "../test_vectors/CTR_DRBG-AES-192-df.inc"
};

static struct ccdrbg_vector nistctr_aes192_nodf_vectors[] = {
#include "../test_vectors/CTR_DRBG-AES-192-nodf.inc"
};

static struct ccdrbg_vector nistctr_aes256_df_vectors[] = {
#include "../test_vectors/CTR_DRBG-AES-256-df.inc"
};

static struct ccdrbg_vector nistctr_aes256_nodf_vectors[] = {
#include "../test_vectors/CTR_DRBG-AES-256-nodf.inc"
};

static struct ccdrbg_PR_vector nistctr_aes128_df_PR_vectors[] = {
#include "../test_vectors/CTR_DRBG-AES-128-df-PR.inc"
};

static struct ccdrbg_PR_vector nistctr_aes128_nodf_PR_vectors[] = {
#include "../test_vectors/CTR_DRBG-AES-128-nodf-PR.inc"
};

static struct ccdrbg_PR_vector nistctr_aes192_df_PR_vectors[] = {
#include "../test_vectors/CTR_DRBG-AES-192-df-PR.inc"
};

static struct ccdrbg_PR_vector nistctr_aes192_nodf_PR_vectors[] = {
#include "../test_vectors/CTR_DRBG-AES-192-nodf-PR.inc"
};

static struct ccdrbg_PR_vector nistctr_aes256_df_PR_vectors[] = {
#include "../test_vectors/CTR_DRBG-AES-256-df-PR.inc"
};

static struct ccdrbg_PR_vector nistctr_aes256_nodf_PR_vectors[] = {
#include "../test_vectors/CTR_DRBG-AES-256-nodf-PR.inc"
};

#define NOF(x) (sizeof(x)/sizeof((x)[0]))

#define commonTestNistCtr_test(ecb,keylen,df,v) commonTestNistCtr((ecb),(keylen),(df),#v,(v),(NOF(v)))

static int commonTestNistCtr(const struct ccmode_ctr *ctr,size_t keylen,
                              int df,
                              char * name,
                              struct ccdrbg_vector *v,
                              size_t n) {
    int rc=0;
    struct ccdrbg_info info;
    struct ccdrbg_nistctr_custom custom = {
        .ctr_info = ctr,
        .keylen = keylen,
        .strictFIPS = 0,
        .use_df = df,
    };

    ccdrbg_factory_nistctr(&info, &custom);

    for(size_t i=0; i<n; i++)
    {
        unsigned char temp[v[i].randomLen];
        ccdrbg_nist_test_vector(&info, &v[i], temp);
        rc|=ok_memcmp(temp, v[i].random, v[i].randomLen, "%s, vector %lu", name, i);
    }
    return rc;
}

#define commonTestNistCtrPR_test(ecb,keylen,df,v) commonTestNistCtrPR((ecb),(keylen),(df),#v,(v),(NOF(v)))

static int commonTestNistCtrPR(
                                const struct ccmode_ctr *ctr,
                                size_t keylen,
                                int df,
                                char *name,
                                struct ccdrbg_PR_vector *v,
                                size_t n) {
    int rc=0;
    struct ccdrbg_info info;
    struct ccdrbg_nistctr_custom custom;
    size_t i;

    custom.ctr_info=ctr;
    custom.keylen=keylen;
    custom.strictFIPS=0;
    custom.use_df=df;

    ccdrbg_factory_nistctr(&info, &custom);

    for(i=0; i<n; i++)
    {
        unsigned char temp[v[i].randomLen];
        ccdrbg_nist_PR_test_vector(&info, &v[i], temp);
        rc|=ok_memcmp(temp, v[i].random, v[i].randomLen, "%s, vector %lu", name, i);
    }
    return rc;
}

/*
 AES (encrypt)

 COUNT = 0
 EntropyInput = b9ad873294a58a0d6c2e9d072f8a270b
 Nonce = 0d5849ccaa7b8a95
 PersonalizationString =
 AdditionalInput =
 EntropyInputReseed = e47485dda9d246a07c0c39f0cf8cb76b
 AdditionalInputReseed =
 AdditionalInput =
 ReturnedBits = 24bd4f7cc6eb71987ab7b06bd066cc07
 */

static int testNistCtrAES128(void) {
    int rc=0;
    unsigned char bytes[16];
    struct ccdrbg_info info;
    struct ccdrbg_nistctr_custom custom;

    custom.ctr_info=ccaes_ctr_crypt_mode();
    custom.keylen=16;
    custom.strictFIPS=0;
    custom.use_df=1;

    ccdrbg_factory_nistctr(&info, &custom);

    uint8_t state[info.size];
    struct ccdrbg_state *rng=(struct ccdrbg_state *)state;

    byteBuffer entropy=hexStringToBytes("b9ad873294a58a0d6c2e9d072f8a270b");
    byteBuffer nonce=hexStringToBytes("0d5849ccaa7b8a95");
    byteBuffer reseed=hexStringToBytes("e47485dda9d246a07c0c39f0cf8cb76b");
    byteBuffer result=hexStringToBytes("24bd4f7cc6eb71987ab7b06bd066cc07");
    byteBuffer result2=hexStringToBytes("53a374589113bea418166ce349fa739a");
    byteBuffer result3=hexStringToBytes("321f125cc30fe61e623927f85a19e8e0");

    /* FIPS test vector */
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_init(&info, rng, (uint32_t)entropy->len, entropy->bytes,
                                              (uint32_t)nonce->len, nonce->bytes, 0, NULL), "init");

    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 16, bytes, 0, NULL), "Generate 1");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_reseed(&info, rng, reseed->len, reseed->bytes, 0, NULL), "Reseed");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 16, bytes, 0, NULL), "Generate 2");

    rc|=ok_memcmp(bytes, result->bytes,result->len, "returned bytes");

    ccdrbg_done(&info, rng);
    
    /* Additional test vector to cover the behavior of generate with 0 length (21208820) */
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_init(&info, rng, (uint32_t)entropy->len, entropy->bytes,
                                        (uint32_t)nonce->len, nonce->bytes, 0, NULL), "init");
    
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 0, bytes, 0, NULL), "Generate zero length");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 16, bytes, 0, NULL), "Generate 2");
    rc|=ok_memcmp(bytes, result2->bytes,result2->len, "returned bytes");
    
    ccdrbg_done(&info, rng);
    
    /* Additional test vector to cover the behavior of generate with length not block-aligned */
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_init(&info, rng, (uint32_t)entropy->len, entropy->bytes,
                                        (uint32_t)nonce->len, nonce->bytes, 0, NULL), "init");
    
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 13, bytes, 0, NULL), "Generate incomplete block");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 16, bytes, 0, NULL), "Generate full block");
    rc|=ok_memcmp(bytes, result3->bytes,result3->len, "returned bytes");
    
    ccdrbg_done(&info, rng);
    free(entropy);
    free(nonce);
    free(reseed);
    free(result);
    free(result2);
    free(result3);
    return rc;
}

/* AES-128 no df
 COUNT = 0
 EntropyInput = 420edbaff787fdbd729e12c2f3cfc0ec6704de59bf28ed438bf0d86ddde7ebcc
 Nonce = be293b972894533b
 PersonalizationString =
 AdditionalInput =
 EntropyInputReseed = a821c34b7505291f80341e37f930451659091550bef04cb68a01b1be394b1037
 AdditionalInputReseed =
 AdditionalInput =
 ReturnedBits = 263c1cf3fd8c0bcb1ed754ce10cfc2fc
 */

static int testNistCtrAES128nodf(void) {
    int rc=0;
    unsigned char bytes[16];
    struct ccdrbg_info info;
    struct ccdrbg_nistctr_custom custom;

    custom.ctr_info=ccaes_ctr_crypt_mode();
    custom.keylen=16;
    custom.strictFIPS=0;
    custom.use_df=0;

    ccdrbg_factory_nistctr(&info, &custom);

    uint8_t state[info.size];
    struct ccdrbg_state *rng=(struct ccdrbg_state *)state;

    byteBuffer entropy=hexStringToBytes("420edbaff787fdbd729e12c2f3cfc0ec6704de59bf28ed438bf0d86ddde7ebcc");
    byteBuffer nonce=hexStringToBytes("be293b972894533b");
    byteBuffer reseed=hexStringToBytes("a821c34b7505291f80341e37f930451659091550bef04cb68a01b1be394b1037");
    byteBuffer result=hexStringToBytes("263c1cf3fd8c0bcb1ed754ce10cfc2fc");

    /* typecast: size of entropy and nonce must be less than 4GB, and fit in uint32_t */
    rc|=is(CCDRBG_STATUS_OK,info.init(&info, rng, (uint32_t)entropy->len, entropy->bytes,
                                              (uint32_t)nonce->len, nonce->bytes, 0, NULL), "init");

    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 16, bytes, 0, NULL), "Generate 1");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_reseed(&info, rng, reseed->len, reseed->bytes, 0, NULL), "Reseed");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 16, bytes, 0, NULL), "Generate 2");

    rc|=ok_memcmp(bytes, result->bytes,result->len, "returned bytes");
    free(entropy);
    free(nonce);
    free(reseed);
    free(result);
    return rc;
}

/* AES-256

 COUNT = 0
 EntropyInput = ec0197a55b0c9962d549b161e96e732a0ee3e177004fe95f5d6120bf82e2c0ea
 Nonce = 9b131c601efd6a7cc2a21cd0534de8d8
 PersonalizationString =
 AdditionalInput =
 EntropyInputReseed = 61810b74d2ed76365ae70ee6772bba4938ee38d819ec1a741fb3ff4c352f140c
 AdditionalInputReseed =
 AdditionalInput =
 ReturnedBits = 7ea89ce613e11b5de7f979e14eb0da4d

 */

static int testNistCtrAES256(void) {
    int rc=0;
    unsigned char bytes[16];
    struct ccdrbg_info info;
    struct ccdrbg_nistctr_custom custom;

    custom.ctr_info=ccaes_ctr_crypt_mode();
    custom.keylen=32;
    custom.strictFIPS=0;
    custom.use_df=1;

    ccdrbg_factory_nistctr(&info, &custom);

    uint8_t state[info.size];
    struct ccdrbg_state *rng=(struct ccdrbg_state *)state;

    byteBuffer entropy=hexStringToBytes("ec0197a55b0c9962d549b161e96e732a0ee3e177004fe95f5d6120bf82e2c0ea");
    byteBuffer nonce=hexStringToBytes("9b131c601efd6a7cc2a21cd0534de8d8");
    byteBuffer reseed=hexStringToBytes("61810b74d2ed76365ae70ee6772bba4938ee38d819ec1a741fb3ff4c352f140c");
    byteBuffer result=hexStringToBytes("7ea89ce613e11b5de7f979e14eb0da4d");

    /* typecast: size of entropy and nonce must be less than 4GB, and fit in uint32_t */
    rc|=is(CCDRBG_STATUS_OK,info.init(&info, rng, (uint32_t)entropy->len, entropy->bytes,
                                              (uint32_t)nonce->len, nonce->bytes, 0, NULL), "init");

    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 16, bytes, 0, NULL), "Generate 1");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_reseed(&info, rng, reseed->len, reseed->bytes, 0, NULL), "Reseed");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 16, bytes, 0, NULL), "Generate 2");

    rc|=ok_memcmp(bytes, result->bytes,result->len, "returned bytes");
    free(entropy);
    free(nonce);
    free(reseed);
    free(result);
    return rc;
}

/* AES-192

 COUNT = 0
 EntropyInput = 1e259e4e7f5b4c5b5b4d5119f2cde4853dc1dd131172f394
 Nonce = 40347af9fb51845a5d3712a2169065cb
 PersonalizationString =
 AdditionalInput =
 EntropyInputReseed = 82bd0a6027531a768163ff636d88a8e7513018117627da6d
 AdditionalInputReseed =
 AdditionalInput =
 ReturnedBits = 0b4de73186bde75f0d4d551ba55af931

 */

static int testNistCtrAES192(void) {
    int rc=0;
    unsigned char bytes[16];
    struct ccdrbg_info info;
    struct ccdrbg_nistctr_custom custom;

    custom.ctr_info=ccaes_ctr_crypt_mode();
    custom.keylen=24;
    custom.strictFIPS=0;
    custom.use_df=1;
    ccdrbg_factory_nistctr(&info, &custom);
    uint8_t state[info.size];
    struct ccdrbg_state *rng=(struct ccdrbg_state *)state;

    byteBuffer entropy=hexStringToBytes("1e259e4e7f5b4c5b5b4d5119f2cde4853dc1dd131172f394");
    byteBuffer nonce=hexStringToBytes("40347af9fb51845a5d3712a2169065cb");
    byteBuffer reseed=hexStringToBytes("82bd0a6027531a768163ff636d88a8e7513018117627da6d");
    byteBuffer result=hexStringToBytes("0b4de73186bde75f0d4d551ba55af931");

    /* typecast: size of entropy and nonce must be less than 4GB, and fit in uint32_t */
    rc|=is(CCDRBG_STATUS_OK,info.init(&info, rng, (uint32_t)entropy->len, entropy->bytes,
                                              (uint32_t)nonce->len, nonce->bytes, 0, NULL), "init");

    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 16, bytes, 0, NULL), "Generate 1");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_reseed(&info, rng, reseed->len, reseed->bytes, 0, NULL), "Reseed");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 16, bytes, 0, NULL), "Generate 2");

    rc|=ok_memcmp(bytes, result->bytes,result->len, "returned bytes");

    free(entropy);
    free(nonce);
    free(reseed);
    free(result);
    return rc;
}

#ifdef SOMEONE_FIXED_DRBG_TO_SUPPORT_KEYLEN_NOT_MULTIPLE_OF_FOUR

/* The drbg assume that the keylen is a multiple of 4 bytes - not the case for tdes */

/*
 3KeyTDEA (encrypt)

 COUNT = 0
 EntropyInput = 994c6b36fbd570abdff0925149ad
 Nonce = 1af5034e727780
 PersonalizationString =
 AdditionalInput =
 EntropyInputReseed = 6f29a7962aa01f31cb56aa6492c4
 AdditionalInputReseed =
 AdditionalInput =
 ReturnedBits = 523deda06869cad8
 */

static int testNistCtrTDES168(void) {
    unsigned char bytes[8];
    int rc=0;
    struct ccdrbg_info info;
    struct ccdrbg_nistctr_custom custom;

    custom.ecb=ccdes3_ecb_encrypt_mode();
    custom.keylen=168;
    custom.strictFIPS=0;
    custom.use_df=1;
    ccdrbg_factory_nistctr(&info, &custom);
    uint8_t state[info.size];
    struct ccdrbg_state *rng=(struct ccdrbg_state *)state;

    byteBuffer entropy=hexStringToBytes("994c6b36fbd570abdff0925149ad");
    byteBuffer nonce=hexStringToBytes("1af5034e727780");
    byteBuffer reseed=hexStringToBytes("6f29a7962aa01f31cb56aa6492c4");
    byteBuffer result=hexStringToBytes("523deda06869cad8");

    /* typecast: size of entropy and nonce must be less than 4GB, and fit in uint32_t */
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_init(&info,rng,
                                        (uint32_t)entropy->len, entropy->bytes,
                                        (uint32_t)nonce->len, nonce->bytes,
                                        0, NULL), "init");

    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 8, bytes,0, NULL), "Generate 1");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_reseed(&info, rng,reseed->len, reseed->bytes,0, NULL), "Reseed");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng,8, bytes,0, NULL), "Generate 2");

    rc|=ok_memcmp(bytes, result->bytes,result->len, "returned bytes");

    ccdrbg_done(&info, rng);
    free(entropy);
    free(nonce);
    free(reseed);
    free(result);
    return rc;
}


/* TDEA no df

 COUNT = 0
 EntropyInput = 8d047024cc4371a3e291508d0aabdeec26bf71f20aaece5a097f57fcbf
 Nonce = 10ef051fffb725
 PersonalizationString =
 AdditionalInput =
 EntropyInputReseed = 13fce32a710a1e3341b0e6941cb789ad47572f981f18e51fc7e7ebfc0f
 AdditionalInputReseed =
 AdditionalInput =
 ReturnedBits = e652a6d23313ef59

 */

static int testNistCtrTDES168nodf(void) {
    unsigned char bytes[8];
    int rc=0;
    struct ccdrbg_info info;
    struct ccdrbg_nistctr_custom custom;

    custom.ecb=ccdes3_ecb_encrypt_mode();
    custom.keylen=168;
    custom.strictFIPS=0;
    custom.use_df=0;
    ccdrbg_factory_nistctr(&info, &custom);
    uint8_t state[info.size];
    struct ccdrbg_state *rng=(struct ccdrbg_state *)state;

    byteBuffer entropy=hexStringToBytes("8d047024cc4371a3e291508d0aabdeec26bf71f20aaece5a097f57fcbf");
    byteBuffer nonce=hexStringToBytes("10ef051fffb725");
    byteBuffer reseed=hexStringToBytes("13fce32a710a1e3341b0e6941cb789ad47572f981f18e51fc7e7ebfc0f");
    byteBuffer result=hexStringToBytes("e652a6d23313ef59");

    /* typecast: size of entropy and nonce must be less than 4GB, and fit in uint32_t */
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_init(&info,rng,
                                        (uint32_t)entropy->len, entropy->bytes,
                                        (uint32_t)nonce->len, nonce->bytes,
                                        0, NULL), "init");

    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 8, bytes,0, NULL), "Generate 1");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_reseed(&info, rng,reseed->len, reseed->bytes,0, NULL), "Reseed");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng,8, bytes,0, NULL), "Generate 2");
    
    rc|=ok_memcmp(bytes, result->bytes,result->len, "returned bytes");

    ccdrbg_done(&info, rng);
    free(entropy);
    free(nonce);
    free(reseed);
    free(result);
    return rc;
}
#endif // SOMEONE_FIXED_DRBG_TO_SUPPORT_KEYLEN_NOT_MULTIPLE_OF_FOUR

int ccdrbg_tests_ctr(void)
{
    int status=0;

    status|=testNistCtrAES128();
    status|=testNistCtrAES128nodf();
    status|=testNistCtrAES192();
    status|=testNistCtrAES256();
#ifdef SOMEONE_FIXED_DRBG_TO_SUPPORT_KEYLEN_NOT_MULTIPLE_OF_FOUR
    status|=testNistCtrTDES168();
    status|=testNistCtrTDES168nodf();
#endif //SOMEONE_FIXED_DRBG_TO_SUPPORT_KEYLEN_NOT_MULTIPLE_OF_FOUR

    status|=commonTestNistCtr_test(ccaes_ctr_crypt_mode(),16,1,
                           nistctr_aes128_df_vectors);

    status|=commonTestNistCtr_test(ccaes_ctr_crypt_mode(),24,1,
                           nistctr_aes192_df_vectors);

    status|=commonTestNistCtr_test(ccaes_ctr_crypt_mode(),32,1,
                           nistctr_aes256_df_vectors);

    status|=commonTestNistCtr_test(ccaes_ctr_crypt_mode(),16,0,
                           nistctr_aes128_nodf_vectors);

    status|=commonTestNistCtr_test(ccaes_ctr_crypt_mode(),24,0,
                           nistctr_aes192_nodf_vectors);

    status|=commonTestNistCtr_test(ccaes_ctr_crypt_mode(),32,0,
                           nistctr_aes256_nodf_vectors);

    status|=commonTestNistCtrPR_test(ccaes_ctr_crypt_mode(),16,1,
                             nistctr_aes128_df_PR_vectors);

    status|=commonTestNistCtrPR_test(ccaes_ctr_crypt_mode(),24,1,
                             nistctr_aes192_df_PR_vectors);

    status|=commonTestNistCtrPR_test(ccaes_ctr_crypt_mode(),32,1,
                             nistctr_aes256_df_PR_vectors);

    status|=commonTestNistCtrPR_test(ccaes_ctr_crypt_mode(),16,0,
                             nistctr_aes128_nodf_PR_vectors);

    status|=commonTestNistCtrPR_test(ccaes_ctr_crypt_mode(),24,0,
                             nistctr_aes192_nodf_PR_vectors);

    status|=commonTestNistCtrPR_test(ccaes_ctr_crypt_mode(),32,0,
                             nistctr_aes256_nodf_PR_vectors);

    return status;
}

#endif // (CCDRBG == 0)

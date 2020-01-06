/*
 * Copyright (c) 2016,2018 Apple Inc. All rights reserved.
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
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>

#if (CCDRBG == 0)
entryPoint(ccdrbg_tests,"ccdrbg")
#else

static struct ccdrbg_vector nisthmac_sha1_vectors[] = {
#include "../test_vectors/HMAC_DRBG-SHA-1.inc"
};

static struct ccdrbg_vector nisthmac_sha224_vectors[] = {
#include "../test_vectors/HMAC_DRBG-SHA-224.inc"
};

static struct ccdrbg_vector nisthmac_sha256_vectors[] = {
#include "../test_vectors/HMAC_DRBG-SHA-256.inc"
};

#if 0
static struct ccdrbg_vector nisthmac_sha512_224_vectors[] = {
#include "../test_vectors/HMAC_DRBG-SHA-512-224.inc"
};

static struct ccdrbg_vector nisthmac_sha512_256_vectors[] = {
#include "../test_vectors/HMAC_DRBG-SHA-512-256.inc"
};
#endif

static struct ccdrbg_vector nisthmac_sha384_vectors[] = {
#include "../test_vectors/HMAC_DRBG-SHA-384.inc"
};

static struct ccdrbg_vector nisthmac_sha512_vectors[] = {
#include "../test_vectors/HMAC_DRBG-SHA-512.inc"
};


#define NOF(x) (sizeof(x)/sizeof((x)[0]))


/*
 [SHA-256]
 [PredictionResistance = False]
 [EntropyInputLen = 256]
 [NonceLen = 128]
 [PersonalizationStringLen = 256]
 [AdditionalInputLen = 0]
 [ReturnedBitsLen = 1024]

 COUNT = 0
 EntropyInput = fa0ee1fe39c7c390aa94159d0de97564342b591777f3e5f6a4ba2aea342ec840
 Nonce = dd0820655cb2ffdb0da9e9310a67c9e5
 PersonalizationString = f2e58fe60a3afc59dad37595415ffd318ccf69d67780f6fa0797dc9aa43e144c
 ** INSTANTIATE:
	V   = 8ef5e5870a97c084d1755e84fd741309679c35fa9c7d35daf22209ac26428773
	Key = 7f37fd4ce652ffbe367106d3b36e0111653e8cbe85004d92f18576c93586ca94
 EntropyInputReseed = e0629b6d7975ddfa96a399648740e60f1f9557dc58b3d7415f9ba9d4dbb501f6
 AdditionalInputReseed =
 ** RESEED:
	V   = ee34cedfaa282d1d55e0bb001aa5ae42c1f90b56c6b426ad47deccce83786f38
	Key = fd616afaa26dd2fc3c2e93cf84af86e6d948fa01c617758816d5ea689925b812
 AdditionalInput =
 ** GENERATE (FIRST CALL):
	V   = 12a5a939f3f229cb85a1d6fb72ca5e109959726dda4ff9d95c11d7129ad3c1f9
	Key = d4bbadb25daa6f76c18ad05c07e448f719f0af2f535e2f938e2dcc5dfa5525b7
 AdditionalInput =
 ReturnedBits = f92d4cf99a535b20222a52a68db04c5af6f5ffc7b66a473a37a256bd8d298f9b4aa4af7e8d181e02367903f93bdb744c6c2f3f3472626b40ce9bd6a70e7b8f93992a16a76fab6b5f162568e08ee6c3e804aefd952ddd3acb791c50f2ad69e9a04028a06a9c01d3a62aca2aaf6efe69ed97a016213a2dd642b4886764072d9cbe
 ** GENERATE (SECOND CALL):
	V   = 53bc9a0420b02b4f6a60aacd8e0320bc440a2385e27887e6ceba60571b27aa47
	Key = eab97b2cf76bd1817dc5d6826361b51c4dc8776ef643254dae01f83b23c2d5c2

*/
static int testNistHmacSHA256(void) {
    int rc=0;

    struct ccdrbg_info info;
    struct ccdrbg_nisthmac_custom custom_hmac = {
        .di = ccsha256_di(),
        .strictFIPS = 0,
    };

    ccdrbg_factory_nisthmac(&info, &custom_hmac);

    uint8_t state[info.size];
    struct ccdrbg_state *rng=(struct ccdrbg_state *)state;

    byteBuffer entropy=hexStringToBytes("fa0ee1fe39c7c390aa94159d0de97564342b591777f3e5f6a4ba2aea342ec840");
    byteBuffer nonce=hexStringToBytes("dd0820655cb2ffdb0da9e9310a67c9e5");
    byteBuffer ps=hexStringToBytes("f2e58fe60a3afc59dad37595415ffd318ccf69d67780f6fa0797dc9aa43e144c");
    byteBuffer reseed=hexStringToBytes("e0629b6d7975ddfa96a399648740e60f1f9557dc58b3d7415f9ba9d4dbb501f6");
    byteBuffer result=hexStringToBytes("f92d4cf99a535b20222a52a68db04c5af6f5ffc7b66a473a37a256bd8d298f9b4aa4af7e8d181e02367903f93bdb744c6c2f3f3472626b40ce9bd6a70e7b8f93992a16a76fab6b5f162568e08ee6c3e804aefd952ddd3acb791c50f2ad69e9a04028a06a9c01d3a62aca2aaf6efe69ed97a016213a2dd642b4886764072d9cbe");
    byteBuffer result2=hexStringToBytes("97e05f7ed83f6ade911a09e0ce8fdd8bf6f5ffc7b66a473a37a256bd8d298f9b4aa4af7e8d181e02367903f93bdb744c6c2f3f3472626b40ce9bd6a70e7b8f93992a16a76fab6b5f162568e08ee6c3e804aefd952ddd3acb791c50f2ad69e9a04028a06a9c01d3a62aca2aaf6efe69ed97a016213a2dd642b4886764072d9cbe");
    unsigned char bytes[CC_MAX(result->len,result2->len)];

    /* FIPS test vector */
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_init(&info, rng, (uint32_t)entropy->len, entropy->bytes,
                                        (uint32_t)nonce->len, nonce->bytes, ps->len, ps->bytes), "init");

    rc|=is(CCDRBG_STATUS_OK,ccdrbg_reseed(&info, rng, reseed->len, reseed->bytes, 0, NULL), "Reseed");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, result->len, bytes, 0, NULL), "Generate 1");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, result->len, bytes, 0, NULL), "Generate 2");
    rc|=ok_memcmp(bytes, result->bytes,result->len, "returned bytes");

    ccdrbg_done(&info, rng);

    /* Additional test vector to cover the behavior of generate with 0 length (21208820) */
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_init(&info, rng, (uint32_t)entropy->len, entropy->bytes,
                                        (uint32_t)nonce->len, nonce->bytes, 0, NULL), "init");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_reseed(&info, rng, reseed->len, reseed->bytes, 0, NULL), "Reseed");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 0, bytes, 0, NULL), "Generate zero length");
    rc|=is(CCDRBG_STATUS_OK,ccdrbg_generate(&info, rng, 16, bytes, 0, NULL), "Generate 2");
    rc|=ok_memcmp(bytes, result2->bytes,result2->len, "returned bytes");

    ccdrbg_done(&info, rng);
    free(entropy);
    free(nonce);
    free(ps);
    free(reseed);
    free(result);
    free(result2);
    return rc;
}


#define commonTestNistHMAC_test(di,v) commonTestNistHMAC((di),#v,(v),(NOF(v)))

static int commonTestNistHMAC(const struct ccdigest_info *di,
                              char * name,
                              struct ccdrbg_vector *v,
                              size_t n) {
    int rc=0;
    struct ccdrbg_info info;
    struct ccdrbg_nisthmac_custom custom = {
        .di = di,
        .strictFIPS = 0,
    };

    ccdrbg_factory_nisthmac(&info, &custom);

    for(size_t i=0; i<n; i++)
    {
        unsigned char temp[v[i].randomLen];
        ccdrbg_nist_14_3_test_vector(&info, &v[i], temp);
        rc|=ok_memcmp(temp, v[i].random, v[i].randomLen, "%s, vector %lu",name, i);
    }
    return rc;
}


int ccdrbg_tests_hmac(void)
{
    int status=0;

    status|=testNistHmacSHA256();

    status|=commonTestNistHMAC_test(ccsha1_di(),nisthmac_sha1_vectors);

    status|=commonTestNistHMAC_test(ccsha224_di(),nisthmac_sha224_vectors);

    status|=commonTestNistHMAC_test(ccsha256_di(),nisthmac_sha256_vectors);

    status|=commonTestNistHMAC_test(ccsha384_di(),nisthmac_sha384_vectors);

    status|=commonTestNistHMAC_test(ccsha512_di(),nisthmac_sha512_vectors);

    return status;
}

#endif // (CCDRBG == 0)

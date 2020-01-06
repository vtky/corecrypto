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
#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_drbg_trng.h"

#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccaes.h>

int fipspost_post_drbg_trng(int fips_mode)
{
    const uint8_t *entropy = (const uint8_t *)
            "\x05\x6d\xcd\xe5\x4a\x18\x17\xa7\x76\x07\xf0\x1f\x2c\x37\xb0\x1f"
            "\x51\xf2\xa9\xb6\x85\xa0\x05\x50\xbc\x31\x29\x3a\x71\x3e\x08\xb3"
            "\xd2\x1b\x8e\x63\x94\x41\xc0\x4a\xf6\xb2\x14\xf8\x4c\x38\x7b\x6b";
    const uint8_t *pers_str = (const uint8_t *)
            "\xcd\x53\x1a\x46\x92\x09\x66\x00\x6f\x2c\x33\xe8\x44\xb9\xc6\x39"
            "\xaf\x43\x43\xf3\x58\x25\x1d\x58\xb4\x79\x64\x53\xcd\x78\x0c\xdf"
            "\xa8\xda\x1d\xfa\xcc\x26\xeb\x3f\x64\xb0\x40\xcc\xc6\x38\x00\x2a";
    const uint8_t *entropy_reseed_1 = (const uint8_t *)
            "\xbe\xda\x17\x7e\x59\xbc\xc2\x59\x63\x72\x16\x51\x9e\x9b\xc4\x6c"
            "\xcf\xd5\xab\xb2\xe3\x2b\x2e\x4f\x3e\xa8\xe3\xdf\xb5\xde\x9d\xb8"
            "\x8c\x29\x74\xc4\x1d\x01\x1f\x58\xa8\xfe\xc3\x55\x9d\x7d\xed\xb0";
    const uint8_t *entropy_reseed_2 = (const uint8_t *)
            "\x72\xa2\xb8\x1e\x7d\xb6\x95\xb1\xc1\xcc\xa1\x13\xd7\x92\x92\xf8"
            "\x98\x01\x7e\x39\xe9\xdb\x34\xbc\xa3\x95\x47\xf8\xf1\x7d\x8e\x97"
            "\x29\x20\xe3\xc7\x9d\xc7\x80\x7d\xf6\xec\x5a\x7b\xe9\xf8\xc2\x8a";
    const uint8_t *expected_output = (const uint8_t *)POST_FIPS_RESULT_STR(
            "\xf6\x40\x24\x2d\xdd\x34\xe9\xe1\x31\xe7\x13\x03\x7b\x18\x34\xb7");

    int32_t ret;
    uint8_t output[CCAES_BLOCK_SIZE];

    struct ccdrbg_info info;
    ccdrbg_factory_trng(&info);
    uint8_t state[ccdrbg_context_size(&info)];
    struct ccdrbg_state *drbg = (struct ccdrbg_state *)state;

    ret = ccdrbg_init(&info, drbg, CCDRBG_TRNG_VECTOR_LEN, entropy, 0, NULL,
            CCDRBG_TRNG_VECTOR_LEN, pers_str);
    if (ret != 0) {
        failf("failed ccdrbg_init: %d", ret);
        return CCERR_GENERIC_FAILURE;
    }

    ret = ccdrbg_reseed(&info, drbg, CCDRBG_TRNG_VECTOR_LEN, entropy_reseed_1, 0, NULL);
    if (ret != 0) {
        failf("failed ccdrbg_reseed(1): %d", ret);
        return CCERR_GENERIC_FAILURE;
    }

    ret = ccdrbg_reseed(&info, drbg, CCDRBG_TRNG_VECTOR_LEN, entropy_reseed_2, 0, NULL);
    if (ret != 0) {
        failf("failed ccdrbg_reseed(2): %d", ret);
        return CCERR_GENERIC_FAILURE;
    }

    ret = ccdrbg_generate(&info, drbg, CCAES_BLOCK_SIZE, output, 0, NULL);
    if (ret != 0) {
        failf("failed ccdrbg_generate: %d", ret);
        return CCERR_GENERIC_FAILURE;
    }

    return memcmp(expected_output, output, CCAES_BLOCK_SIZE) == 0 ? 0 : CCERR_KAT_FAILURE;
}

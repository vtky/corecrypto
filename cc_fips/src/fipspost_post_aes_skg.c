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
#include "fipspost_post_aes_skg.h"

#include <stdbool.h>

#include <corecrypto/ccaes.h> // for CCAES_BLOCK_SIZE

static int fipspost_post_aes_skg_oneshot(bool enc, bool cbc,
        size_t key_len, const uint8_t *key,
        size_t iv_len, const uint8_t *iv,
        size_t input_len, const uint8_t *input,
        const uint8_t *output);

static int fipspost_post_aes_skg_oneshot(bool enc, bool cbc,
        size_t key_len, const uint8_t *key,
        size_t iv_len, const uint8_t *iv,
        size_t input_len, const uint8_t *input,
        const uint8_t *output)
{
    const void *ccmode;
    uint8_t result[CCAES_BLOCK_SIZE];

    if (input_len != CCAES_BLOCK_SIZE) {
        failf("invalid input length: %zu", input_len);
        return CCERR_GENERIC_FAILURE;
    }
    
    if (iv_len != 0 && iv_len != CCAES_BLOCK_SIZE) {
        failf("invalid iv length: %zu", iv_len);
    }

    if (cbc) {
        if (enc) {
            ccmode = &ccaes_skg_cbc_encrypt_mode;
        } else {
            ccmode = &ccaes_skg_cbc_decrypt_mode;
        }
        cccbc_one_shot(ccmode, key_len, key, iv,
                input_len / cccbc_block_size(ccmode), input, result);
    } else {
        if (enc) {
            ccmode = &ccaes_skg_ecb_encrypt_mode;
        } else {
            ccmode = &ccaes_skg_ecb_decrypt_mode;
        }
        ccecb_one_shot(ccmode, key_len, key,
                input_len / ccecb_block_size(ccmode), input, result);
    }

    if (memcmp(output, result, CCAES_BLOCK_SIZE) != 0) {
        failf("result mismatch");
        return CCERR_KAT_FAILURE;
    }

    return 0;
}

int fipspost_post_aes_skg_enc_cbc_128(int fips_mode)
{
    // AES 128 Encryption Test Data
    uint8_t *key = (uint8_t *)
            "\x34\x49\x1b\x26\x6d\x8f\xb5\x4c\x5c\xe1\xa9\xfb\xf1\x7b\x09\x8c";
    uint8_t *iv = (uint8_t *)
            "\x9b\xc2\x0b\x29\x51\xff\x72\xd3\xf2\x80\xff\x3b\xd2\xdc\x3d\xcc";
    uint8_t *input = (uint8_t *)
            "\x06\xfe\x99\x71\x63\xcb\xcb\x55\x85\x3e\x28\x57\x74\xcc\xa8\x9d";
    uint8_t *output = (uint8_t *)POST_FIPS_RESULT_STR(
            "\x32\x5d\xe3\x14\xe9\x29\xed\x08\x97\x87\xd0\xa2\x05\xd1\xeb\x33");

    return fipspost_post_aes_skg_oneshot(true, true, CCAES_KEY_SIZE_128, key,
            CCAES_BLOCK_SIZE, iv, CCAES_BLOCK_SIZE, input, output);
}

int fipspost_post_aes_skg_dec_cbc_128(int fips_mode)
{
    // AES 128 Decryption Test Data
    uint8_t *key = (uint8_t *)
            "\xc6\x8e\x4e\xb2\xca\x2a\xc5\xaf\xee\xac\xad\xea\xa3\x97\x11\x94";
    uint8_t *iv = (uint8_t *)
            "\x11\xdd\x9d\xa1\xbd\x22\x3a\xcf\x68\xc5\xa1\xe1\x96\x4c\x18\x9b";
    uint8_t *input = (uint8_t *)
            "\xaa\x36\x57\x9b\x0c\x72\xc5\x28\x16\x7b\x70\x12\xd7\xfa\xf0\xde";
    uint8_t *output = (uint8_t *)POST_FIPS_RESULT_STR(
            "\x9e\x66\x1d\xb3\x80\x39\x20\x9a\x72\xc7\xd2\x96\x40\x66\x88\xf2");

    return fipspost_post_aes_skg_oneshot(false, true, CCAES_KEY_SIZE_128, key,
            CCAES_BLOCK_SIZE, iv, CCAES_BLOCK_SIZE, input, output);
}

int fipspost_post_aes_skg_enc_ecb_128(int fips_mode)
{
    // AES 128 Encryption Test Data
    uint8_t *key = (uint8_t *)
            "\xe6\x80\x74\x7f\x14\xe8\xa6\xee\x00\xbb\xa6\xbd\x65\x57\xae\x51";
    uint8_t *input = (uint8_t *)
            "\x7f\xea\x96\xf9\x0f\xba\xe1\x2a\x85\x7f\x5c\x97\xe0\xcb\xa5\x79";
    uint8_t *output = (uint8_t *)POST_FIPS_RESULT_STR(
            "\x3d\x30\xe6\x36\x45\x85\x46\x16\x71\xaa\x67\x10\x26\xb2\xec\xd9");

    return fipspost_post_aes_skg_oneshot(true, false, CCAES_KEY_SIZE_128, key,
            0, NULL, CCAES_BLOCK_SIZE, input, output);
}

int fipspost_post_aes_skg_dec_ecb_128(int fips_mode)
{
    // AES 128 Decryption Test Data
    uint8_t *key = (uint8_t *)
            "\xe6\x80\x74\x7f\x14\xe8\xa6\xee\x00\xbb\xa6\xbd\x65\x57\xae\x51";
    uint8_t *input = (uint8_t *)
            "\x3d\x30\xe6\x36\x45\x85\x46\x16\x71\xaa\x67\x10\x26\xb2\xec\xd9";
    uint8_t *output = (uint8_t *)POST_FIPS_RESULT_STR(
            "\x7f\xea\x96\xf9\x0f\xba\xe1\x2a\x85\x7f\x5c\x97\xe0\xcb\xa5\x79");

    return fipspost_post_aes_skg_oneshot(false, false, CCAES_KEY_SIZE_128, key,
            0, NULL, CCAES_BLOCK_SIZE, input, output);
}

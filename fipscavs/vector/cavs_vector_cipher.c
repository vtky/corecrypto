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

#include "cavs_vector_cipher.h"

#include <corecrypto/ccaes.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccmode_factory.h>

static int cavs_vector_cipher_oneshot(cavs_cipher_enc ct, cavs_aes_is is,
        cavs_cipher_mode cm, int enc, size_t tag_len, uint8_t *tag,
        size_t iv_len, const uint8_t *iv, size_t key_len, const uint8_t *key,
        size_t data_len, const uint8_t *data, size_t add_data_len,
        const uint8_t *add_data, uint8_t *result);

/*
 * Tests both AES and 3DES oneshot encryption operations.
 */
int cavs_vector_cipher(cavs_cipher_enc ct, cavs_aes_is is,
        cavs_cipher_mode cm, int enc, size_t tag_len, uint8_t *tag, size_t
        iv_len, const uint8_t *iv, size_t key_len, const uint8_t *key,
        size_t data_len, const uint8_t *data, size_t add_data_len, const uint8_t *add_data,
        uint8_t *result)
{
    int ret = CAVS_STATUS_FAIL;
    
    // Check the Key
    if (key == NULL) {
        errorf("No key data");
        goto fail;
    }

    if (cm == CAVS_CIPHER_MODE_CBC) {
        if ((iv_len == 0 || iv_len > 16) ) {
            errorf("No iv data length");
            goto fail;
        }

        if (iv == NULL) {
            errorf("No iv data");
            goto fail;
        }
    } else if (cm == CAVS_CIPHER_MODE_ECB) {
        // Check the length of the key
        if (key_len == 0 || key_len > 32) { // 32==256 bits, largest supported key size
            errorf("bad key length");
            goto fail;
        }
        if (iv != NULL || iv_len != 0) {
            errorf("IV data incorrectly supplied to ECB");
            goto fail;
        }
    } else {
        /* No additional checks specified. */
    }

    // do the actual work of the cipher
    ret = cavs_vector_cipher_oneshot(ct, is, cm,
            enc, tag_len, (uint8_t *)tag,
            iv_len, (const uint8_t *)iv,
            key_len, (const uint8_t *)key,
            data_len, (const uint8_t *)data,
            add_data_len, (const uint8_t *)add_data,
            (uint8_t *)result);
    if (ret == CAVS_STATUS_FAIL) {
        /* Many tests cause oneshot to fail. Most callers ignore return value. */
        debug("failed cavs_vector_cipher_oneshot");
    }

fail:
    return ret;
}

static int cavs_vector_cipher_oneshot(cavs_cipher_enc ct, cavs_aes_is is,
        cavs_cipher_mode cm, int enc, size_t tag_len, uint8_t *tag,
        size_t iv_len, const uint8_t *iv, size_t key_len, const uint8_t *key,
        size_t data_len, const uint8_t *data, size_t add_data_len,
        const uint8_t *add_data, uint8_t *result)
{
    int rc = 0;

    debug("%s, %s, %s, %s", cavs_cipher_enc_to_string(ct), cavs_aes_is_to_string(is), cavs_cipher_mode_to_string(cm), enc ? "E" : "D");
    buffer_debug(tag, tag_len, "tag");
    buffer_debug(iv, iv_len, "iv");
    buffer_debug(key, key_len, "key");
    buffer_debug(data, data_len, "data");
    buffer_debug(add_data, add_data_len, "add_data");

    const void *ccmode = cavs_find_ccmode(is, ct, cm, enc);
    if (!ccmode) {
        errorf("Failed to find ccmode: cavs_aes_is:%d cavs_cipher_enc:%d cavs_cipher_mode:%d encryption:%d",
                is, ct, cm, enc);
        return CAVS_STATUS_FAIL;
    }

    if (cm == CAVS_CIPHER_MODE_CCM) {
        rc = ccccm_one_shot(ccmode, key_len, key, (unsigned int)iv_len, iv,
                data_len, data, result, (unsigned int)add_data_len,
                add_data, (unsigned int)tag_len, (void *)tag);
    } else if (cm == CAVS_CIPHER_MODE_GCM) {
        rc = ccgcm_one_shot(ccmode, key_len, key, iv_len, iv, add_data_len,
                add_data, data_len, data, result, tag_len, (void *)tag);
    } else if (cm == CAVS_CIPHER_MODE_ECB) {
        ccecb_one_shot(ccmode, key_len, key,
                data_len / ccecb_block_size(ccmode), data, result);
    } else if (cm == CAVS_CIPHER_MODE_CBC) {
        cccbc_one_shot(ccmode, key_len, key, iv,
                data_len / cccbc_block_size(ccmode), data, result);
    } else if (cm == CAVS_CIPHER_MODE_OFB) {
        ccofb_one_shot(ccmode, key_len, key, iv, data_len, data, result);
    } else if (cm == CAVS_CIPHER_MODE_CFB) {
        cccfb_one_shot(ccmode, key_len, key, iv, data_len, data, result);
    } else if (cm == CAVS_CIPHER_MODE_CFB8) {
        cccfb8_one_shot(ccmode, key_len, key, iv, data_len, data, result);
    } else {
        errorf("unsupported cipher mode: %s", cavs_cipher_mode_to_string(cm));
        return CAVS_STATUS_FAIL;
    }

    return rc == 0 ? CAVS_STATUS_OK : CAVS_STATUS_FAIL;
}

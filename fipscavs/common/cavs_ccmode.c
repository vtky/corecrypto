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

#include <corecrypto/ccaes.h>
#include <corecrypto/ccdes.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccmode_factory.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/cchmac.h>

#include "cavs_common.h"

/*
 * cavs_find_ccmode
 *
 * For a specified instruction set, encryption cipher, and cipher mode,
 * return a void pointer to a valid ccmode object, or NULL.
 */
const void *cavs_find_ccmode(cavs_aes_is is, cavs_cipher_enc cipher,
        cavs_cipher_mode mode, int encryption)
{
    /* Validate the integrity of the supplied parameters. */
    if (is == CAVS_AES_IS_UNKNOWN || is >= CAVS_AES_IS_LAST ||
            cipher == CAVS_CIPHER_ENC_UNKNOWN || cipher >= CAVS_CIPHER_ENC_LAST ||
            mode == CAVS_CIPHER_MODE_UNKNOWN || mode >= CAVS_CIPHER_MODE_LAST) {
        errorf("invalid parameters supplied");
        return NULL;
    }

    /* Objects returned when needed by a caller. */
    static struct ccmode_ecb static_ECB CC_UNUSED;
    static struct ccmode_cbc static_CBC CC_UNUSED;
    static struct ccmode_cfb static_CFB CC_UNUSED;
    static struct ccmode_cfb8 static_CFB8 CC_UNUSED;
    static struct ccmode_ctr static_CTR CC_UNUSED;
    static struct ccmode_ofb static_OFB CC_UNUSED;
    static struct ccmode_xts static_XTS CC_UNUSED;
    static struct ccmode_gcm static_GCM CC_UNUSED;
    static struct ccmode_ccm static_CCM CC_UNUSED;

#define BEGIN_SET(ARCH, CIPHER, IS)                                         \
    if (is == IS && cipher == CIPHER) {
#define ENTRY(MODE, ENC, DEC)                                               \
        if (mode == CAVS_CIPHER_MODE_ ## MODE) {                            \
            return (const void *)(encryption ? ENC : DEC);                  \
        }
#define FACTORY_ENC_ENTRY(MODE, TYPE, ROOT)                                 \
        if (mode == CAVS_CIPHER_MODE_ ## MODE && encryption) {              \
            ccmode_factory_ ## TYPE ## _encrypt(&static_##MODE, &ROOT);     \
            return (const void *)&static_##MODE;                            \
        }
#define FACTORY_DEC_ENTRY(MODE, TYPE, ROOT)                                 \
        if (mode == CAVS_CIPHER_MODE_ ## MODE && !encryption) {             \
            ccmode_factory_ ## TYPE ## _decrypt(&static_##MODE, &ROOT);     \
            return (const void *)&static_##MODE;                            \
        }
#define FACTORY_ENTRY(MODE, TYPE, ROOT)                                     \
        FACTORY_ENC_ENTRY(MODE, TYPE, ROOT)                                 \
        FACTORY_DEC_ENTRY(MODE, TYPE, ROOT)

#define FACTORY_CRYPT(MODE, TYPE, ROOT)                                     \
        if (mode == CAVS_CIPHER_MODE_ ## MODE) {                            \
            ccmode_factory_ ## TYPE ## _crypt(&static_##MODE, &ROOT);       \
            return (const void *)&static_##MODE;                            \
        }

#define FACTORY_XTS(ROOT_ENC, ROOT_DEC)                                     \
        if (mode == CAVS_CIPHER_MODE_XTS) {                                 \
            if (encryption) {                                               \
                ccmode_factory_xts_encrypt(&static_XTS, &ROOT_ENC, &ROOT_ENC);\
                return (const void *)&static_XTS;                           \
            } else {                                                        \
                ccmode_factory_xts_decrypt(&static_XTS, &ROOT_DEC, &ROOT_ENC);\
                return (const void *)&static_XTS;                           \
            }                                                               \
        }

#define END_SET()                                                           \
    }

#if CC_KERNEL       // Kernel has substantially different ccmode support.
    BEGIN_SET(CAVS_ARCH_CURRENT, CAVS_CIPHER_ENC_TDES, CAVS_AES_IS_GEN)
        ENTRY(ECB,              &ccdes3_ltc_ecb_encrypt_mode, &ccdes3_ltc_ecb_decrypt_mode)
        ENTRY(CBC,              ccdes3_cbc_encrypt_mode(),  ccdes3_cbc_decrypt_mode())
    END_SET()

    BEGIN_SET(CAVS_ARCH_CURRENT, CAVS_CIPHER_ENC_AES, CAVS_AES_IS_GEN)
        ENTRY(ECB,              ccaes_ecb_encrypt_mode(),  ccaes_ecb_decrypt_mode())
        ENTRY(CBC,              ccaes_cbc_encrypt_mode(),  ccaes_cbc_decrypt_mode())
        ENTRY(CTR,              ccaes_ctr_crypt_mode(),    ccaes_ctr_crypt_mode())
        ENTRY(XTS,              ccaes_xts_encrypt_mode(),  ccaes_xts_decrypt_mode())
        ENTRY(CCM,              ccaes_ccm_encrypt_mode(),  ccaes_ccm_decrypt_mode())
    END_SET()

#if (defined(__x86_64__) || defined(__i386__)) && CC_USE_ASM        // x86 Kernel Support
    BEGIN_SET(CAVS_ARCH_INTEL, CAVS_CIPHER_ENC_AES, CAVS_AES_IS_ASM)
        ENTRY(ECB,              &ccaes_intel_ecb_encrypt_opt_mode, &ccaes_intel_ecb_decrypt_opt_mode)
        ENTRY(CBC,              &ccaes_intel_cbc_encrypt_opt_mode, &ccaes_intel_cbc_decrypt_opt_mode)
        ENTRY(XTS,              &ccaes_intel_xts_encrypt_opt_mode, &ccaes_intel_xts_decrypt_opt_mode)
    END_SET()

    BEGIN_SET(CAVS_ARCH_INTEL, CAVS_CIPHER_ENC_AES, CAVS_AES_IS_NIGEN)
        ENTRY(CBC,              ccaes_cbc_encrypt_mode(),  ccaes_cbc_decrypt_mode())
        ENTRY(XTS,              ccaes_xts_encrypt_mode(),  ccaes_xts_decrypt_mode())
    END_SET()

    BEGIN_SET(CAVS_ARCH_INTEL, CAVS_CIPHER_ENC_AES, CAVS_AES_IS_NI)
        ENTRY(ECB,              &ccaes_intel_ecb_encrypt_aesni_mode, &ccaes_intel_ecb_decrypt_aesni_mode)
        ENTRY(CBC,              &ccaes_intel_cbc_encrypt_aesni_mode, &ccaes_intel_cbc_decrypt_aesni_mode)
        ENTRY(XTS,              &ccaes_intel_xts_encrypt_aesni_mode, &ccaes_intel_xts_decrypt_aesni_mode)
    END_SET()
#endif

#if (defined(__arm__) || defined (__arm64__)) && CC_USE_ASM         // ARM Kernel Support
    BEGIN_SET(CAVS_ARCH_ARM, CAVS_CIPHER_ENC_AES, CAVS_AES_IS_ASM)
        ENTRY(ECB,              &ccaes_arm_ecb_encrypt_mode, &ccaes_arm_ecb_decrypt_mode)
        ENTRY(CBC,              &ccaes_arm_cbc_encrypt_mode, &ccaes_arm_cbc_decrypt_mode)
        ENTRY(XTS,              &ccaes_arm_xts_encrypt_mode, &ccaes_arm_xts_decrypt_mode)
    END_SET()
#endif

#else               // And now for the userland ccmode table.
#if !CC_USE_L4
    BEGIN_SET(CAVS_ARCH_CURRENT, CAVS_CIPHER_ENC_TDES, CAVS_AES_IS_GEN)
        ENTRY(ECB,              &ccdes3_ltc_ecb_encrypt_mode, &ccdes3_ltc_ecb_decrypt_mode)
        ENTRY(CBC,              ccdes3_cbc_encrypt_mode(),  ccdes3_cbc_decrypt_mode())
        ENTRY(CFB,              ccdes3_cfb_encrypt_mode(),  ccdes3_cfb_decrypt_mode())
        ENTRY(CFB8,             ccdes3_cfb8_encrypt_mode(), ccdes3_cfb8_decrypt_mode())
        ENTRY(OFB,              ccdes3_ofb_crypt_mode(),    ccdes3_ofb_crypt_mode())
    END_SET()
#else               // L4 specific ccmodes
    BEGIN_SET(CAVS_ARCH_CURRENT, CAVS_CIPHER_ENC_AES, CAVS_AES_IS_SKG)
        ENTRY(ECB,              &ccaes_skg_ecb_encrypt_mode, &ccaes_skg_ecb_decrypt_mode)
        ENTRY(CBC,              &ccaes_skg_cbc_encrypt_mode, &ccaes_skg_cbc_encrypt_mode)
    END_SET()
    BEGIN_SET(CAVS_ARCH_CURRENT, CAVS_CIPHER_ENC_AES, CAVS_AES_IS_TRNG)
        ENTRY(ECB,              &ccaes_trng_ecb_encrypt_mode, &ccaes_trng_ecb_encrypt_mode)
    END_SET()
#endif

    BEGIN_SET(CAVS_ARCH_CURRENT, CAVS_CIPHER_ENC_AES, CAVS_AES_IS_GEN)
        ENTRY(ECB,              &ccaes_ltc_ecb_encrypt_mode, &ccaes_ltc_ecb_decrypt_mode)
        ENTRY(CBC,              ccaes_cbc_encrypt_mode(),  ccaes_cbc_decrypt_mode())
        ENTRY(CTR,              ccaes_ctr_crypt_mode(),    ccaes_ctr_crypt_mode())
        FACTORY_ENTRY(CFB, cfb, ccaes_ltc_ecb_encrypt_mode)
        FACTORY_ENTRY(CFB8, cfb8, ccaes_ltc_ecb_encrypt_mode)
        FACTORY_CRYPT(OFB, ofb, ccaes_ltc_ecb_encrypt_mode)
        FACTORY_ENTRY(GCM, gcm, ccaes_ltc_ecb_encrypt_mode)
        FACTORY_ENTRY(CCM, ccm, ccaes_ltc_ecb_encrypt_mode)
        FACTORY_XTS(ccaes_ltc_ecb_encrypt_mode, ccaes_ltc_ecb_decrypt_mode)
    END_SET()

#if !CC_UNITTEST
#if (defined(__x86_64__) || defined(__i386__)) && CC_USE_ASM        // Userland Intel ASM
    BEGIN_SET(CAVS_ARCH_INTEL, CAVS_CIPHER_ENC_AES, CAVS_AES_IS_ASM)
        ENTRY(ECB,              &ccaes_intel_ecb_encrypt_opt_mode, &ccaes_intel_ecb_decrypt_opt_mode)
        ENTRY(CBC,              &ccaes_intel_cbc_encrypt_opt_mode, &ccaes_intel_cbc_decrypt_opt_mode)
        FACTORY_ENTRY(CFB, cfb, ccaes_intel_ecb_encrypt_opt_mode)
        FACTORY_ENTRY(CFB8, cfb8, ccaes_intel_ecb_encrypt_opt_mode)
        FACTORY_CRYPT(OFB, ofb, ccaes_intel_ecb_encrypt_opt_mode)
        FACTORY_ENTRY(GCM, gcm, ccaes_intel_ecb_encrypt_opt_mode)
        FACTORY_ENTRY(CCM, ccm, ccaes_intel_ecb_encrypt_opt_mode)
        FACTORY_XTS(ccaes_intel_ecb_encrypt_opt_mode, ccaes_intel_ecb_decrypt_opt_mode)
    END_SET()

    BEGIN_SET(CAVS_ARCH_INTEL, CAVS_CIPHER_ENC_AES, CAVS_AES_IS_NIGEN)
        FACTORY_ENC_ENTRY(CBC, cbc, ccaes_intel_ecb_encrypt_aesni_mode)
        FACTORY_DEC_ENTRY(CBC, cbc, ccaes_intel_ecb_decrypt_aesni_mode)
        FACTORY_XTS(ccaes_intel_ecb_encrypt_aesni_mode, ccaes_intel_ecb_decrypt_aesni_mode)
    END_SET()

    BEGIN_SET(CAVS_ARCH_INTEL, CAVS_CIPHER_ENC_AES, CAVS_AES_IS_NI)
        ENTRY(ECB,              &ccaes_intel_ecb_encrypt_aesni_mode, &ccaes_intel_ecb_decrypt_aesni_mode)
        ENTRY(CBC,              &ccaes_intel_cbc_encrypt_aesni_mode, &ccaes_intel_cbc_decrypt_aesni_mode)
        FACTORY_ENTRY(CFB, cfb, ccaes_intel_ecb_encrypt_aesni_mode)
        FACTORY_ENTRY(CFB8, cfb8, ccaes_intel_ecb_encrypt_aesni_mode)
        FACTORY_CRYPT(OFB, ofb, ccaes_intel_ecb_encrypt_aesni_mode)
        FACTORY_ENTRY(GCM, gcm, ccaes_intel_ecb_encrypt_aesni_mode)
        FACTORY_ENTRY(CCM, ccm, ccaes_intel_ecb_encrypt_aesni_mode)
        ENTRY(XTS,              &ccaes_intel_xts_encrypt_aesni_mode, &ccaes_intel_xts_decrypt_aesni_mode)
    END_SET()

    BEGIN_SET(CAVS_ARCH_INTEL, CAVS_CIPHER_ENC_AES, CAVS_AES_IS_GLAD)
        ENTRY(CBC,              &ccaes_gladman_cbc_encrypt_mode, &ccaes_gladman_cbc_decrypt_mode);
    END_SET()
#endif

#if (defined(__arm__) || defined (__arm64__)) && CC_USE_ASM
    BEGIN_SET(CAVS_ARCH_ARM, CAVS_CIPHER_ENC_AES, CAVS_AES_IS_ASM)
        ENTRY(ECB,              &ccaes_arm_ecb_encrypt_mode, &ccaes_arm_ecb_decrypt_mode)
        ENTRY(CBC,              &ccaes_arm_cbc_encrypt_mode, &ccaes_arm_cbc_decrypt_mode)
        FACTORY_ENTRY(CFB, cfb, ccaes_arm_ecb_encrypt_mode)
        FACTORY_ENTRY(CFB8, cfb8, ccaes_arm_ecb_encrypt_mode)
        FACTORY_CRYPT(OFB, ofb, ccaes_arm_ecb_encrypt_mode)
        FACTORY_ENTRY(GCM, gcm, ccaes_arm_ecb_encrypt_mode)
        FACTORY_ENTRY(CCM, ccm, ccaes_arm_ecb_encrypt_mode)
        ENTRY(XTS,              ccaes_xts_encrypt_mode(),  ccaes_xts_decrypt_mode())
    END_SET()

    BEGIN_SET(CAVS_ARCH_ARM, CAVS_CIPHER_ENC_AES, CAVS_AES_IS_GLAD)
        ENTRY(CBC,              &ccaes_gladman_cbc_encrypt_mode, &ccaes_gladman_cbc_decrypt_mode);
    END_SET()

#if defined(__arm__) && !CC_USE_L4
    BEGIN_SET(CAVS_ARCH_ARM, CAVS_CIPHER_ENC_AES, CAVS_AES_IS_HW)
        ENTRY(CBC,              &ccaes_ios_hardware_cbc_encrypt_mode, &ccaes_ios_hardware_cbc_decrypt_mode);
    END_SET()
#endif

#endif
#endif // CC_UNITTEST
#endif

    errorf("Unable to find matching ccmode: %s/%s/%s/%d",
            cavs_aes_is_to_string(is), cavs_cipher_enc_to_string(cipher),
            cavs_cipher_mode_to_string(mode), encryption);
    return NULL;
}

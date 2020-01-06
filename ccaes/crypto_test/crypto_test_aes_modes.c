/*
 * Copyright (c) 2012,2013,2014,2015,2016,2017,2018 Apple Inc. All rights reserved.
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
#include <corecrypto/ccaes.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccmode_factory.h>
#include <corecrypto/cc_runtime_config.h>
#include "crypto_test_aes_modes.h"
#include "ccaes_ios_hardware.h"

#if (CCAES_MODES == 0)
entryPoint(ccaes_modes_tests,"ccaes mode")
#else
#include "crypto_test_modes.h"

static int kTestTestCount = 116234 /* base */
#if     CCAES_INTEL_ASM
        + 50993;
#elif   CCAES_MUX
        +46+49;
#else
        + 0;
#endif

#define END_VECTOR   {.keyStr=NULL}

ccsymmetric_test_vector aes_ctr_vectors[] = {
    #include "../test_vectors/aes_ctr_test_vectors.inc"
    END_VECTOR
};

int ccaes_modes_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{

    struct ccmode_ctr ccaes_generic_ctr_crypt_mode;
    ccmode_factory_ctr_crypt(&ccaes_generic_ctr_crypt_mode, &ccaes_ltc_ecb_encrypt_mode);

    static struct ccmode_xts ccaes_generic_ltc_xts_encrypt_mode;
    static struct ccmode_xts ccaes_generic_ltc_xts_decrypt_mode;
    ccmode_factory_xts_encrypt(&ccaes_generic_ltc_xts_encrypt_mode, &ccaes_ltc_ecb_encrypt_mode,  &ccaes_ltc_ecb_encrypt_mode);
    ccmode_factory_xts_decrypt(&ccaes_generic_ltc_xts_decrypt_mode, &ccaes_ltc_ecb_decrypt_mode,  &ccaes_ltc_ecb_encrypt_mode);

    static struct ccmode_gcm ccaes_generic_ltc_gcm_encrypt_mode;
    static struct ccmode_gcm ccaes_generic_ltc_gcm_decrypt_mode;
    ccmode_factory_gcm_encrypt(&ccaes_generic_ltc_gcm_encrypt_mode, &ccaes_ltc_ecb_encrypt_mode);
    ccmode_factory_gcm_decrypt(&ccaes_generic_ltc_gcm_decrypt_mode, &ccaes_ltc_ecb_encrypt_mode);

    static struct ccmode_ccm ccaes_generic_ltc_ccm_encrypt_mode;
    static struct ccmode_ccm ccaes_generic_ltc_ccm_decrypt_mode;
    ccmode_factory_ccm_encrypt(&ccaes_generic_ltc_ccm_encrypt_mode, &ccaes_ltc_ecb_encrypt_mode);
    ccmode_factory_ccm_decrypt(&ccaes_generic_ltc_ccm_decrypt_mode, &ccaes_ltc_ecb_encrypt_mode);

#if CCAES_INTEL_ASM
    if(CC_HAS_AESNI()) kTestTestCount+=69;
#endif
#if CCAES_MUX
    if (ccaes_ios_hardware_enabled(CCAES_HW_CTR)) kTestTestCount+=46;
    if (ccaes_ios_hardware_enabled(CCAES_HW_CBC)) kTestTestCount+=49;
#endif
    plan_tests(kTestTestCount);

    aes_validation_test();

    test_ctr("Default AES-CTR",ccaes_ctr_crypt_mode(), ccaes_ctr_crypt_mode(), aes_ctr_vectors);
    test_ctr("Generic AES-CTR",&ccaes_generic_ctr_crypt_mode, &ccaes_generic_ctr_crypt_mode, aes_ctr_vectors);
#if CCAES_MUX
    // Mux is always supported, falls back to pure SW when needed
    if (ccaes_ios_hardware_enabled(CCAES_HW_CTR))  /* Test only, not to be used by corecrypto clients */
        test_ctr("HW AES-CTR",&ccaes_ios_hardware_ctr_crypt_mode, &ccaes_ios_hardware_ctr_crypt_mode, aes_ctr_vectors);
    test_ctr("MUX AES-CTR",ccaes_ios_mux_ctr_crypt_mode(), ccaes_ios_mux_ctr_crypt_mode(), aes_ctr_vectors);
#endif

#if CCAES_MUX
    if (ccaes_ios_hardware_enabled(CCAES_HW_CBC))  /* Test only, not to be used by corecrypto clients */
        ok(test_mode((ciphermode_t) &ccaes_ios_hardware_cbc_encrypt_mode, (ciphermode_t) &ccaes_ios_hardware_cbc_decrypt_mode, cc_cipherAES, cc_ModeCBC) == 1, "iOS HW AES for CBC");
    ok(test_mode((ciphermode_t) ccaes_ios_mux_cbc_encrypt_mode(), (ciphermode_t) ccaes_ios_mux_cbc_decrypt_mode(), cc_cipherAES, cc_ModeCBC) == 1, "Mux AES for CBC - iOS HW/SW");
#endif


	ok(test_mode((ciphermode_t)ccaes_siv_encrypt_mode(), (ciphermode_t)ccaes_siv_decrypt_mode(), cc_cipherAES, cc_ModeSIV) == 1, "Generic AES-SIV");
    ok(test_mode((ciphermode_t) &ccaes_ltc_ecb_encrypt_mode, (ciphermode_t) &ccaes_ltc_ecb_decrypt_mode, cc_cipherAES, cc_ModeECB) == 1, "Standard LTC AES for ECB");
    ok(test_mode((ciphermode_t) &ccaes_gladman_cbc_encrypt_mode, (ciphermode_t) &ccaes_gladman_cbc_decrypt_mode, cc_cipherAES, cc_ModeCBC) == 1, "Standard LTC AES for CBC");
#if 0 // CCAES_ARM_ASM
    ok(test_mode((ciphermode_t) &ccaes_arm_ecb_encrypt_mode, (ciphermode_t) &ccaes_arm_ecb_decrypt_mode, cc_cipherAES, cc_ModeECB) == 1, "arm VNG AES for ECB");
    ok(test_mode((ciphermode_t) &ccaes_arm_cbc_encrypt_mode, (ciphermode_t) &ccaes_arm_cbc_decrypt_mode, cc_cipherAES, cc_ModeCBC) == 1, "arm VNG AES for CBC");
#endif
#if CCAES_INTEL_ASM
    ok(test_mode((ciphermode_t) &ccaes_intel_ecb_encrypt_opt_mode, (ciphermode_t) &ccaes_intel_ecb_decrypt_opt_mode, cc_cipherAES, cc_ModeECB) == 1, "Intel Non-AES-NI AES-ECB");
    ok(test_mode((ciphermode_t) &ccaes_intel_cbc_encrypt_opt_mode, (ciphermode_t) &ccaes_intel_cbc_decrypt_opt_mode, cc_cipherAES, cc_ModeCBC) == 1, "Intel Non-AES-NI AES-CBC");
    ok(test_mode((ciphermode_t) &ccaes_intel_xts_encrypt_opt_mode, (ciphermode_t) &ccaes_intel_xts_decrypt_opt_mode, cc_cipherAES, cc_ModeXTS) == 1, "Intel Non-AES-NI AES-XTS");
    ok(test_xts(&ccaes_intel_xts_encrypt_opt_mode, &ccaes_intel_xts_decrypt_opt_mode), "Intel Non-AES-NI AES-XTS Extended testing");
    if(CC_HAS_AESNI()) {
        ok(test_mode((ciphermode_t) &ccaes_intel_ecb_encrypt_aesni_mode, (ciphermode_t) &ccaes_intel_ecb_decrypt_aesni_mode, cc_cipherAES, cc_ModeECB) == 1, "Intel AES-NI AES-ECB");
        ok(test_mode((ciphermode_t) &ccaes_intel_cbc_encrypt_aesni_mode, (ciphermode_t) &ccaes_intel_cbc_decrypt_aesni_mode, cc_cipherAES, cc_ModeCBC) == 1, "Intel AES-NI AES-CBC");
        ok(test_mode((ciphermode_t) &ccaes_intel_xts_encrypt_aesni_mode, (ciphermode_t) &ccaes_intel_xts_decrypt_aesni_mode, cc_cipherAES, cc_ModeXTS) == 1, "Intel AES-NI AES-XTS");
        ok(test_xts(&ccaes_intel_xts_encrypt_aesni_mode, &ccaes_intel_xts_decrypt_aesni_mode), "Intel AES-NI AES-XTS Extended testing");
    }
#endif
    ok(test_mode((ciphermode_t) ccaes_ecb_encrypt_mode(), (ciphermode_t) ccaes_ecb_decrypt_mode(), cc_cipherAES, cc_ModeECB) == 1, "Default AES-ECB");
    ok(test_mode((ciphermode_t) ccaes_cbc_encrypt_mode(), (ciphermode_t) ccaes_cbc_decrypt_mode(), cc_cipherAES, cc_ModeCBC) == 1, "Default AES-CBC");
    ok(test_mode((ciphermode_t) ccaes_cfb_encrypt_mode(), (ciphermode_t) ccaes_cfb_decrypt_mode(), cc_cipherAES, cc_ModeCFB) == 1, "Default AES-CFB");
    ok(test_mode((ciphermode_t) ccaes_cfb8_encrypt_mode(), (ciphermode_t) ccaes_cfb8_decrypt_mode(), cc_cipherAES, cc_ModeCFB8) == 1, "Default AES-CFB8");
    ok(test_mode((ciphermode_t) ccaes_ofb_crypt_mode(), (ciphermode_t) ccaes_ofb_crypt_mode(), cc_cipherAES, cc_ModeOFB) == 1, "Default AES-OFB");
    ok(test_mode((ciphermode_t) (const struct ccmode_xts *) &ccaes_generic_ltc_xts_encrypt_mode,
                 (ciphermode_t) (const struct ccmode_xts *) &ccaes_generic_ltc_xts_decrypt_mode, cc_cipherAES, cc_ModeXTS) == 1, "Generic AES-XTS");
    ok(test_mode((ciphermode_t) ccaes_xts_encrypt_mode(), (ciphermode_t) ccaes_xts_decrypt_mode(), cc_cipherAES, cc_ModeXTS) == 1, "Default AES-XTS");
    ok(test_mode((ciphermode_t) ccaes_gcm_encrypt_mode(), (ciphermode_t) ccaes_gcm_decrypt_mode(), cc_cipherAES, cc_ModeGCM) == 1, "Default AES-GCM");
    ok(test_mode((ciphermode_t) (const struct ccmode_gcm *) &ccaes_generic_ltc_gcm_encrypt_mode,
                  (ciphermode_t) (const struct ccmode_gcm *) &ccaes_generic_ltc_gcm_decrypt_mode, cc_cipherAES, cc_ModeGCM) == 1, "Generic AES-GCM");
    ok(test_mode((ciphermode_t) ccaes_ccm_encrypt_mode(), (ciphermode_t) ccaes_ccm_decrypt_mode(), cc_cipherAES, cc_ModeCCM) == 1, "Default AES-CCM");
    ok(test_mode((ciphermode_t) (const struct ccmode_ccm *) &ccaes_generic_ltc_ccm_encrypt_mode,
                 (ciphermode_t) (const struct ccmode_ccm *) &ccaes_generic_ltc_ccm_decrypt_mode, cc_cipherAES, cc_ModeCCM) == 1, "Generic AES-CCM");
    ok(test_gcm(ccaes_gcm_encrypt_mode(), ccaes_gcm_decrypt_mode()), "Default AES-GCM Extended testing");
    ok(test_gcm(&ccaes_generic_ltc_gcm_encrypt_mode,&ccaes_generic_ltc_gcm_decrypt_mode), "Generic AES-GCM Extended testing");
    ok(test_xts(ccaes_xts_encrypt_mode(), ccaes_xts_decrypt_mode()), "Default AES-XTS Extended testing");
    ok(test_xts(&ccaes_generic_ltc_xts_encrypt_mode, &ccaes_generic_ltc_xts_decrypt_mode), "Generic AES-XTS Extended testing");
    return 0;
}
#endif

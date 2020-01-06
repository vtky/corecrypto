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

#include <mach/mach_types.h>
#include <mach-o/loader.h>
#include <libkern/crypto/register_crypto.h>

kern_return_t corecrypto_kext_start(kmod_info_t * ki, void *d);
kern_return_t corecrypto_kext_stop(kmod_info_t *ki, void *d);
extern void    panic(const char *, ...);

#include <corecrypto/ccdigest.h>
#include <corecrypto/ccmd5.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccdes.h>
#include <corecrypto/ccpad.h>
#include <corecrypto/ccblowfish.h>
#include <corecrypto/cccast.h>
#include <corecrypto/ccchacha20poly1305.h>

#include <corecrypto/ccrng.h>
#include <corecrypto/ccrng_cryptographic.h>
#include "fipspost.h"

#include <libkern/libkern.h>
#include <pexpert/pexpert.h>

static struct crypto_functions kpis;

static const struct ccchacha20poly1305_fns ccchacha20poly1305_fns = {
    .info = ccchacha20poly1305_info,
    .init = ccchacha20poly1305_init,
    .reset = ccchacha20poly1305_reset,
    .setnonce = ccchacha20poly1305_setnonce,
    .incnonce = ccchacha20poly1305_incnonce,
    .aad = ccchacha20poly1305_aad,
    .encrypt = ccchacha20poly1305_encrypt,
    .finalize = ccchacha20poly1305_finalize,
    .decrypt = ccchacha20poly1305_decrypt,
    .verify = ccchacha20poly1305_verify
};

kern_return_t corecrypto_kext_start(kmod_info_t * ki, void *d)
{
    int status;
#pragma unused (d)

#if CC_FIPSPOST_TRACE
    kprintf("corecrypto_kext_start called: tracing enabled\n");
#else
    kprintf("corecrypto_kext_start called\n");
#endif

    // Initialize RNG before ccrng is used
    status = ccrng_cryptographic_init_once();
    if (status!=0) {
        // Fatal error, we can't boot if the RNG failed to initialize
        panic("corecrypto kext RNG initialization failure (%d)", status);
    };
    
    int result;
    int fips_mode = 0;
    
    if (!PE_parse_boot_argn("fips_mode", &fips_mode, sizeof(fips_mode)))
    {
        fips_mode = FIPS_MODE_FLAG_FULL;
    }

    if (!FIPS_MODE_IS_DISABLE(fips_mode)) {
        if ((result = fipspost_post(fips_mode, (struct mach_header *)ki->address)) != 0)
        {
            panic("FIPS Kernel POST Failed (%d)!", result);
        }
    }

    /* Register KPIs */

    /* digests common functions */
    kpis.ccdigest_init_fn = &ccdigest_init;
    kpis.ccdigest_update_fn = &ccdigest_update;
    kpis.ccdigest_fn = &ccdigest;
    /* digest implementations */
    kpis.ccmd5_di = ccmd5_di();
    kpis.ccsha1_di = ccsha1_di();
    kpis.ccsha256_di = ccsha256_di();
    kpis.ccsha384_di = ccsha384_di();
    kpis.ccsha512_di = ccsha512_di();

    /* hmac common function */
    kpis.cchmac_init_fn = &cchmac_init;
    kpis.cchmac_update_fn = &cchmac_update;
    kpis.cchmac_final_fn = &cchmac_final;
    kpis.cchmac_fn = &cchmac;

    /* ciphers modes implementations */
    /* AES, ecb, cbc and xts */
    kpis.ccaes_ecb_encrypt = ccaes_ecb_encrypt_mode();
    kpis.ccaes_ecb_decrypt = ccaes_ecb_decrypt_mode();
    kpis.ccaes_cbc_encrypt = ccaes_cbc_encrypt_mode();
    kpis.ccaes_cbc_decrypt = ccaes_cbc_decrypt_mode();
    kpis.ccaes_ctr_crypt = ccaes_ctr_crypt_mode();
    kpis.ccaes_gcm_encrypt = ccaes_gcm_encrypt_mode();
    kpis.ccaes_gcm_decrypt = ccaes_gcm_decrypt_mode();
    
    kpis.ccgcm_init_with_iv_fn = &ccgcm_init_with_iv;
    kpis.ccgcm_inc_iv_fn = &ccgcm_inc_iv;
    
    kpis.ccchacha20poly1305_fns = &ccchacha20poly1305_fns;
    
    kpis.ccaes_xts_encrypt = ccaes_xts_encrypt_mode();
    kpis.ccaes_xts_decrypt = ccaes_xts_decrypt_mode();
    /* DES, ecb and cbc */
    kpis.ccdes_ecb_encrypt = ccdes_ecb_encrypt_mode();
    kpis.ccdes_ecb_decrypt = ccdes_ecb_decrypt_mode();
    kpis.ccdes_cbc_encrypt = ccdes_cbc_encrypt_mode();
    kpis.ccdes_cbc_decrypt = ccdes_cbc_decrypt_mode();
    /* TDES, ecb and cbc */
    kpis.cctdes_ecb_encrypt = ccdes3_ecb_encrypt_mode();
    kpis.cctdes_ecb_decrypt = ccdes3_ecb_decrypt_mode();
    kpis.cctdes_cbc_encrypt = ccdes3_cbc_encrypt_mode();
    kpis.cctdes_cbc_decrypt = ccdes3_cbc_decrypt_mode();
    /* RC4 */
    kpis.ccrc4_info = ccrc4();
    /* Blowfish - ECB only */
    kpis.ccblowfish_ecb_encrypt = ccblowfish_ecb_encrypt_mode();
    kpis.ccblowfish_ecb_decrypt = ccblowfish_ecb_decrypt_mode();
    /* CAST - ECB only */
    kpis.cccast_ecb_encrypt = cccast_ecb_encrypt_mode();
    kpis.cccast_ecb_decrypt = cccast_ecb_decrypt_mode();
    /* DES key helper functions */
    kpis.ccdes_key_is_weak_fn = &ccdes_key_is_weak;
    kpis.ccdes_key_set_odd_parity_fn = &ccdes_key_set_odd_parity;
    /* XTS padding+encrypt */
    kpis.ccpad_xts_encrypt_fn = NULL; //&ccpad_xts_encrypt;
    kpis.ccpad_xts_decrypt_fn = NULL; // &ccpad_xts_decrypt;
#if  ((defined(IPHONE_SIMULATOR_HOST_MIN_VERSION_REQUIRED) && IPHONE_SIMULATOR_HOST_MIN_VERSION_REQUIRED >= 100000) \
|| (defined(__MAC_OS_X_VERSION_MIN_REQUIRED)  && __MAC_OS_X_VERSION_MIN_REQUIRED >= 101200)   \
|| (defined(__IPHONE_OS_VERSION_MIN_REQUIRED) && __IPHONE_OS_VERSION_MIN_REQUIRED>= 100000)   \
|| (defined(__TV_OS_VERSION_MIN_REQUIRED)     && __TV_OS_VERSION_MIN_REQUIRED    >= 100000)   \
|| (defined(__WATCH_OS_VERSION_MIN_REQUIRED)  && __WATCH_OS_VERSION_MIN_REQUIRED >= 30000))
    /* CTS3 padding+encrypt */
    kpis.ccpad_cts3_encrypt_fn = &ccpad_cts3_encrypt;
    kpis.ccpad_cts3_decrypt_fn = &ccpad_cts3_decrypt;
#endif
    
    /* rng */
    kpis.ccrng_fn = &ccrng;

    /* rsa */
    kpis.ccrsa_make_pub_fn = &ccrsa_make_pub;
    kpis.ccrsa_verify_pkcs1v15_fn = &ccrsa_verify_pkcs1v15;

    register_crypto_functions(&kpis);

    if (FIPS_MODE_IS_VERBOSE(fips_mode))
    {
        kprintf("corecrypto_kext_start completed sucessfully\n");
    }

    return KERN_SUCCESS;
}

kern_return_t corecrypto_kext_stop(kmod_info_t *ki CC_UNUSED, void *d CC_UNUSED)
{
    // Corecrypto kext is never unloaded
    return KERN_SUCCESS;
}

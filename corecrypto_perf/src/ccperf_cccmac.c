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

#include <corecrypto/ccperf.h>
#include <corecrypto/cccmac.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccmode_factory.h>
#include <corecrypto/cc_priv.h>

#if CCAES_MUX
#define CCAES_MUX_TEST
#endif

#ifdef CCAES_MUX_TEST
#include <corecrypto/ccaes.h>
static struct ccmode_cbc ccaes_mux_cbc_encrypt_mode;
#endif

/* mode created with the CBC factory */
static struct ccmode_cbc ccaes_generic_ltc_cbc_encrypt_mode;

#if CCAES_INTEL_ASM
/* intel */
static struct ccmode_cbc ccaes_intel_cbc_encrypt_mode;
#endif

#define CCMODE_CBC_TEST(_mode, _keylen) { .name="cccmac_"#_mode"_"#_keylen, .cbc=&cc##_mode, .keylen=_keylen }

static struct cccmac_perf_test {
    const char *name;
    const struct ccmode_cbc *cbc;
    size_t keylen;
} cccmac_perf_tests[] = {
    CCMODE_CBC_TEST(aes_generic_ltc_cbc_encrypt_mode,16),
    CCMODE_CBC_TEST(aes_gladman_cbc_encrypt_mode,16),
#if CCAES_INTEL_ASM
    CCMODE_CBC_TEST(aes_intel_cbc_encrypt_mode,16),
#endif
#if CCAES_ARM_ASM
    CCMODE_CBC_TEST(aes_arm_cbc_encrypt_mode,16),
#endif
#ifdef CCAES_MUX_TEST
    CCMODE_CBC_TEST(aes_ios_hardware_cbc_encrypt_mode,16),
    CCMODE_CBC_TEST(aes_mux_cbc_encrypt_mode,16),
#endif
    CCMODE_CBC_TEST(aes_generic_ltc_cbc_encrypt_mode,24),
    CCMODE_CBC_TEST(aes_gladman_cbc_encrypt_mode,24),
#if CCAES_INTEL_ASM
    CCMODE_CBC_TEST(aes_intel_cbc_encrypt_mode,24),
#endif
#if CCAES_ARM_ASM
    CCMODE_CBC_TEST(aes_arm_cbc_encrypt_mode,24),
#endif
#ifdef CCAES_MUX_TEST
    CCMODE_CBC_TEST(aes_ios_hardware_cbc_encrypt_mode,24),
    CCMODE_CBC_TEST(aes_mux_cbc_encrypt_mode,24),
#endif
    CCMODE_CBC_TEST(aes_generic_ltc_cbc_encrypt_mode,32),
    CCMODE_CBC_TEST(aes_gladman_cbc_encrypt_mode,32),
#if CCAES_INTEL_ASM
    CCMODE_CBC_TEST(aes_intel_cbc_encrypt_mode,32),
#endif
#if CCAES_ARM_ASM
    CCMODE_CBC_TEST(aes_arm_cbc_encrypt_mode,32),
#endif
#ifdef CCAES_MUX_TEST
    CCMODE_CBC_TEST(aes_ios_hardware_cbc_encrypt_mode,32),
    CCMODE_CBC_TEST(aes_mux_cbc_encrypt_mode,32),
#endif
};

static double perf_cccmac(size_t loops, size_t size, const void *arg)
{
    const struct cccmac_perf_test *test=arg;
    unsigned char mac[test->cbc->block_size];
    unsigned char key[test->keylen];
    unsigned char data[size];

    cc_zero(test->keylen,key);

    perf_start();
    do {
        cccmac_one_shot_generate(test->cbc, test->keylen, key,
               size, data, sizeof(mac), mac);
    } while (--loops != 0);
    return perf_seconds();
}

static struct ccperf_family family;

struct ccperf_family *ccperf_family_cccmac(int argc, char *argv[])
{
    ccmode_factory_cbc_encrypt(&ccaes_generic_ltc_cbc_encrypt_mode, &ccaes_ltc_ecb_encrypt_mode);
#ifdef CCAES_MUX_TEST
    CC_MEMCPY(&ccaes_mux_cbc_encrypt_mode, ccaes_ios_mux_cbc_encrypt_mode(), sizeof(struct ccmode_cbc));
#endif
#if CCAES_INTEL_ASM
    if (CC_HAS_AESNI())
    {
        CC_MEMCPY(&ccaes_intel_cbc_encrypt_mode,
                                   &ccaes_intel_cbc_encrypt_aesni_mode, sizeof(struct ccmode_cbc));
    }
    else
    {
        CC_MEMCPY(&ccaes_intel_cbc_encrypt_mode,
                                   &ccaes_intel_cbc_encrypt_opt_mode, sizeof(struct ccmode_cbc));
    }
#endif
    F_GET_ALL(family, cccmac);
    const size_t sizes[]={32,256,4096,4*4096};
    F_SIZES_FROM_ARRAY(family, sizes);
    family.size_kind=ccperf_size_bytes;
    return &family;
}


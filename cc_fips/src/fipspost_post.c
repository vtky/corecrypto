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
#include <corecrypto/cc_absolute_time.h>

#include "fipspost.h"
#include "fipspost_priv.h"

#include "fipspost_trace.h"

#include "fipspost_get_hmac.h"

#include "fipspost_post_integrity.h"
#include "fipspost_post_hmac.h"
#include "fipspost_post_aes_ecb.h"
#include "fipspost_post_aes_cbc.h"
#include "fipspost_post_rsa_sig.h"
#include "fipspost_post_ecdsa.h"
#include "fipspost_post_drbg_ctr.h"
#include "fipspost_post_ecdh.h"

#if !CC_USE_L4
#include "fipspost_post_ffdh.h"
#include "fipspost_post_aes_gcm.h"
#include "fipspost_post_aes_xts.h"
#include "fipspost_post_tdes_cbc.h"
#include "fipspost_post_drbg_hmac.h"
#if !CC_KERNEL
#include "fipspost_post_rsa_enc_dec.h"
#endif
#endif

/* Dylib is not transitioned over to 'normal' mechanisms yet. */
#if !CC_USE_L4 && !CC_KERNEL
int fipspost_post_dylib_integrity(int fips_mode);
#endif

/*
 * The pre-calculated SHA256 HMAC gets placed here for integrity testing.  The
 * current value is a random number, but it is replaced by hmacfiletool during
 * the build process.
 */
FIPSPOST_DECLARE_PRECALC_HMAC;

int fipspost_post(int fips_mode, struct mach_header *pmach_header)
{
    uint64_t post_time = cc_absolute_time();
    uint64_t start_time;
    uint64_t end_time;
	int result = CCERR_GENERIC_FAILURE; /* guilty until proven */
    int test_counter = 0;
    int return_on_failure;

    fips_mode |= FIPS_MODE_FLAG_VERBOSE;

#if CC_KERNEL
    /*
     * The FIPS testing kext will repeatedly call this function, but lacks the
     * mach_header.  Save it so that subsequent calls don't need to do a
     * lookup.
     *
     * The dylib should always supply the header.
     */
    static struct mach_header *corecrypto_kext_pmach_header = NULL;

    if (pmach_header != NULL) {
        corecrypto_kext_pmach_header = pmach_header;
    } else if (corecrypto_kext_pmach_header != NULL) {
        pmach_header = corecrypto_kext_pmach_header;
    } else {
        failf("unable to acquire mach header");
        return CCERR_GENERIC_FAILURE;
    }
#endif

#define run_post(post_test, ...) do {                                       \
        test_counter--;                                                     \
        FIPSPOST_TRACE_MESSAGE(FIPSPOST_TRACE_TEST_STR);                    \
        FIPSPOST_TRACE_MESSAGE(#post_test);                                 \
        start_time = cc_absolute_time();                                    \
        if ((result = post_test(fips_mode, ##__VA_ARGS__)) != 0) {          \
            failf(#post_test ": %d", result);                               \
            if (return_on_failure) {                                        \
                return (test_counter * 1000 + result);                      \
            }                                                               \
        } else {                                                            \
            end_time = cc_absolute_time();                                  \
            debugf("PASSED: (%u ms) - " #post_test,                         \
                    (uint32_t)(1000 * (end_time - start_time) * cc_absolute_time_sf()));\
        }                                                                   \
    } while (0);

    FIPSPOST_TRACE_EVENT;

    /*
     * Validate the integrity check separately to allow the NOINTEG flag
     * to override the normal return-on-failure.
     */
    return_on_failure = FIPS_MODE_IS_NOINTEG(fips_mode) ? 0 :
            !FIPS_MODE_IS_FORCEFAIL(fips_mode);

    run_post(fipspost_post_integrity, pmach_header);

    /* Reset return_on_failure to the expected behavior. */
    return_on_failure = !FIPS_MODE_IS_FORCEFAIL(fips_mode);

    /* Run each supported POST test. */
    run_post(fipspost_post_hmac);
    run_post(fipspost_post_aes_ecb);
    run_post(fipspost_post_aes_cbc);
    run_post(fipspost_post_rsa_sig);
    run_post(fipspost_post_ecdsa);
    run_post(fipspost_post_ecdh);
    run_post(fipspost_post_drbg_ctr);
#if !CC_USE_L4
    run_post(fipspost_post_aes_gcm);
    run_post(fipspost_post_aes_xts);
    run_post(fipspost_post_tdes_cbc);
    run_post(fipspost_post_drbg_hmac);
#if !CC_KERNEL
    run_post(fipspost_post_ffdh);
    run_post(fipspost_post_rsa_enc_dec);
#endif
#endif

    end_time = cc_absolute_time();

	if (result == 0) {
		debugf("all tests PASSED (%u ms)",
                (uint32_t)(1000 * (end_time - post_time) * cc_absolute_time_sf()));
	}

    /* Consume failures and return success when NOPANIC is set. */
    return FIPS_MODE_IS_NOPANIC(fips_mode) ? 0 : result;
}

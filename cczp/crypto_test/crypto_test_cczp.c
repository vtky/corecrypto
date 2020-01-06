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

#include <corecrypto/ccrng.h>
#include <corecrypto/cczp.h>
#include <corecrypto/cczp_priv.h>
#include "cc_debug.h"
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccn_priv.h>
#include "crypto_test_cczp_inv.h"
#include "testmore.h"
#include <limits.h>

static int test_cczp_init(void) {

    /* Negative test */
    const cc_unit d[2]  = {0, 0};
    const cc_unit recipd[3]  = {1, 1, 1};

    cczp_decl_n(2, zerod);
    CCZP_N(zerod)=2;
    ccn_set(2,CCZP_PRIME(zerod),d);
    ccn_set(3,CCZP_RECIP(zerod),recipd);

    /* ccn_make_recip is expected to write zeroes when d is zero */
    cczp_init(zerod);
    ok(ccn_is_zero(3,cczp_recip(zerod)), "ccn_make_recip when d is zero");

    return 0;
}

static const cc_unit p[] = {
    ccn256_32(0xe5a022bd, 0x33109be3, 0x536f9eda, 0x564edabe,
              0x9b4ddf1c, 0x157c483c, 0x4caa41fc, 0xccbee49b)
};
static const size_t n = ccn_nof(256);

/* negative tests for cczp_power* edge cases */
/* common cases are well covered by higher-level tests (e.g. ccdh, ccrsa, etc.) */
static int test_cczp_power_fns(void)
{
    cc_unit r[n];
    cc_unit s[n];
    cc_unit t[n];
    cc_unit e[n];
    cczp_decl_n(n, zp);
    CCZP_N(zp) = n;
    ccn_set(n, CCZP_PRIME(zp), p);
    cczp_init(zp);
    
    ccn_seti(n, s, 2);
    
    ccn_seti(n, e, 0);
    cczp_power(zp, r, s, e);
    ok(ccn_is_one(n, r), "cczp_power when e = 0");
    cczp_power_ssma(zp, r, s, e);
    ok(ccn_is_one(n, r), "cczp_power_ssma when e = 0");
    cczp_power_fast(zp, r, s, e);
    ok(ccn_is_one(n, r), "cczp_power_fast when e = 0");
    
    ccn_seti(n, e, 1);
    cczp_power(zp, r, s, e);
    ok(ccn_cmp(n, r, s) == 0, "cczp_power when e = 1");
    cczp_power_ssma(zp, r, s, e);
    ok(ccn_cmp(n, r, s) == 0, "cczp_power_ssma when e = 1");
    cczp_power_fast(zp, r, s, e);
    ok(ccn_cmp(n, r, s) == 0, "cczp_power_fast when e = 1");
    
    ccn_add(n, t, s, p);
    isnt(cczp_power(zp, r, t, e), 0, "cczp_power when base > p");
    isnt(cczp_power_ssma(zp, r, t, e), 0, "cczp_power_ssma when base > p");
    isnt(cczp_power_fast(zp, r, t, e), 0, "cczp_power_fast when base > p");
    
    return 0;
}

int cczp_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    plan_tests(CCN_UNIT_SIZE==8?211:155);

    test_cczp_inv_corner_cases();

    test_cczp_inv_kats();

    for(int nbits = 64; nbits<4096; nbits +=651)
        test_cczp_inv(nbits);

    test_cczp_init();
    
    test_cczp_power_fns();

    return 0;
}


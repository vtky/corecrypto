/*
 * Copyright (c) 2015,2016,2017,2018 Apple Inc. All rights reserved.
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
#include <corecrypto/cczp.h>
#include <corecrypto/ccprime.h>
#include "crypto_test_cczp_inv.h"
#include <corecrypto/ccperf.h>

typedef int (*cczp_cczp_inv_t)(cczp_const_t zp, cc_unit *r, const cc_unit *x);

static double internal_modinv(cczp_cczp_inv_t modinv, size_t loops, cc_size nbits)
{
    int st;
    cc_size n = ccn_nof(nbits);
    cc_unit a[n], ai[n];


    int rc=0;

    cczp_decl_n(n, zp);
    CCZP_N(zp) = n;

    st=ccn_random(n, a, rng); if(st!=0) abort();
    st=ccn_random(n, CCZP_PRIME(zp), rng); if(st!=0) abort();
    CCZP_PRIME(zp)[0] |= 1; //make sure zp is odd so that cczp_mod_inv_odd doesn't return immediatly
    cczp_init(zp); //for cczp_mod_inv_field only
    cczp_modn(zp, a, n, a);

    perf_start();
    do {
        rc|=modinv(zp, ai, a);
    } while (--loops != 0);
    return perf_seconds();

    //cczp_inv_field return error because p is not a prime, but this is not important for timing
    //cczp_inv may return error because there is no inverse, but this is not iportant for timing
}


static double perf_cczp_inv_odd(size_t loops, cc_size nbits)
{
    return internal_modinv(cczp_inv_odd, loops, nbits);
}

static double perf_cczp_inv_slow(size_t loops, cc_size nbits)
{
    return internal_modinv(cczp_inv_slow, loops, nbits);
}

static double perf_cczp_inv_XGCD(size_t loops, cc_size nbits)
{
    return internal_modinv(cczp_inv, loops, nbits);
}

static double perf_cczp_inv_field(size_t loops, cc_size nbits)
{
    return internal_modinv(cczp_inv_field, loops, nbits);
}


#define _TEST(_x) { .name = #_x, .func = perf_ ## _x}
static struct cczp_inv_perf_test {
    const char *name;
    double(*func)(size_t loops, cc_size nbits);
} cczp_inv_perf_tests[] = {
    _TEST(cczp_inv_slow),
    _TEST(cczp_inv_field),
    _TEST(cczp_inv_odd),
    _TEST(cczp_inv_XGCD),

};

static double perf_cczp_inv(size_t loops CC_UNUSED, size_t size, const void *arg)
{
    const struct cczp_inv_perf_test *test=arg;
    return test->func(loops, size);
}

static struct ccperf_family family;

struct ccperf_family *ccperf_family_cczp_inv(int argc, char *argv[])
{
    F_GET_ALL(family, cczp_inv);

    const size_t sizes[]={256,512,1024,2048,4096};
    F_SIZES_FROM_ARRAY(family, sizes);

    family.size_kind=ccperf_size_bits;
    return &family;
}




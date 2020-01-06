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

#include "cc_debug.h"
#include <corecrypto/cczp.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccn.h>
#include "crypto_test_ccn.h"
#include "testmore.h"
#include "testbyteBuffer.h"
#include "testccnBuffer.h"
#include  "ccn_op.h"

static void mult(cc_unit *r, cc_size ns, const cc_unit *s, cc_size nt, const cc_unit *t)
{
    cc_assert(r != s);
    cc_assert(r != t);

    r[ns] = ccn_mul1 (ns, r, s, t[0]);
    while (nt > 1)
    {
        r += 1, t += 1, nt -= 1;
        r[ns] = ccn_addmul1 (ns, r, s, t[0]);
    }
}

static int verify_ccn_div_euclid(cc_size nq, const cc_unit *q, cc_size nr, const cc_unit *r, cc_size na, const cc_unit *a, cc_size nd, const cc_unit *d)
{
    cc_unit v[nq+nd];
    //ccn_zero(nq+nd, v);
    mult(v, nq, q, nd, d);
    ccn_addn(nq+nd, v, v, nr, r);

    int rc = ccn_cmp(na, a, v);
    return rc;
}

static int test_ccn_div(int modulus_bits, int modulus_real_bits, int divisor_bits)
{
    struct ccrng_state *rng = global_test_rng;
    if(modulus_real_bits >modulus_bits)
        modulus_real_bits = modulus_bits;

    //create divisor
    cc_size nd= ccn_nof(modulus_bits);
    cc_unit d[nd]; cc_unit r[nd];
    ccn_zero(nd, d);
    ccn_random_bits(modulus_real_bits, d, rng);

    //create random dividend
    cc_size na = ccn_nof(divisor_bits);
    cc_unit a[na]; ccn_zero(na, a);
    cc_unit q[na]; ccn_zero(na, q);
    ccn_random_bits(divisor_bits, a, rng);

    //other rc's are input parameter error and are considered fine here
    int rc = ccn_div_euclid(na, q, nd, r, na, a, nd, d);
    ok(rc!=-1, "ccn_div_euclid() returned error");
    if(rc==0){
        rc = verify_ccn_div_euclid(na, q, nd, r, na, a, nd, d);
    } else
        rc = 0;

    return rc;
}

static void ccn_addn_kat(){
    ccnBuffer s = hexStringToCcn("FFFFFFFFffffffffFFFFFFFFffffffffFFFFFFFFffffffff");
    ccnBuffer t = hexStringToCcn("00000000000000000000000000000001");
    cc_size n = s->len;
    cc_unit r[n];
    
    cc_unit cr = ccn_add(t->len, r, s->units, t->units);
    ok(cr==1, "ccn_add carry KAT");
    ok(ccn_is_zero(t->len, r), "ccn_add KAT");

    cr = ccn_addn(n, r, s->units, t->len, t->units);
    ok(cr==1, "ccn_addn KAT");
    ok(ccn_is_zero(n, r), "ccn_addn KAT");
    
    cr = ccn_addn(t->len, r, s->units, t->len, t->units);
    ok(cr==1, "ccn_addn carry KAT");
    ok(ccn_is_zero(t->len, r), "ccn_add KAT");
    
    cr = ccn_add1(0, r, r, 7);
    ok(cr==7, "ccn_add1 carry KAT");
    
    free(s), free(t);
}


#define MODULUS_BITS 653
#define MODULUS_REAL_BITS 457
#define DIVISOR_BITS 1985
int ccn_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    int rc, i;
    int modulus_bits = MODULUS_BITS;
    int modulus_real_bits = MODULUS_REAL_BITS;
    int divisor_bits =DIVISOR_BITS;
    plan_tests(100308);

    /* Functional tests */
    for(int i=0; i<25000; i++){
        modulus_bits = cc_rand_unit() %753+30;
        modulus_real_bits = modulus_bits/(cc_rand_unit()%4+1)+cc_rand_unit() %5;

        divisor_bits = modulus_bits*(cc_rand_unit()%4+1)+cc_rand_unit() %7;
        rc = test_ccn_div(modulus_bits,  modulus_real_bits, divisor_bits);
        is(rc,0, "test_ccn_div() division results doesn't verify");

        divisor_bits = modulus_bits/(cc_rand_unit()%3+1)+cc_rand_unit() %7;
        rc = test_ccn_div(modulus_bits,  modulus_real_bits, divisor_bits);
        is(rc,0, "test_ccn_div() division results doesn't verify");
    }

    /* Negative tests */
    cc_unit d[2]  = {0, 0};
    cc_unit a[5] = {5, 4, 3, 2, 1};
    cc_unit q[5], r[2];

    rc = ccn_div_euclid(5, q, 2, r, 5, a, 2, d);
    is(rc,-2, "ccn_div_euclid() division by zero");
    for(i = 50; i>=1; i--){
        d[0] = i;
        rc = ccn_div_euclid(5, q, 2, r, 5, a, 2, d);
        is(rc,0, "ccn_div_euclid()");
        rc = verify_ccn_div_euclid(5, q, 2, r, 5, a, 2, d);
        is(rc,0, "ccn_div_euclid() division by small divisor");
    }
    
    //make sure arithmetic right shift is in place
    for(i=0; i<200; i++){
        cc_unit v = cc_rand_unit();
        ok(ccop_msb(v) == (ccn_bit(&v,CCN_UNIT_BITS-1)? ~(cc_unit)0: 0), "ccop_msb() produces incorrect result.");
    }

    ccn_addn_kat();
    
    return rc;
}


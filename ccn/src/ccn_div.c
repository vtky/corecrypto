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

#include <corecrypto/ccn.h>
#include <corecrypto/ccn_priv.h>
#include "cc_debug.h"

#define CCN_MOD_R_CTR_LIMIT  3

/* Computes q = a / d and r = a%d
 -q can be NULL
 -r can be NULL
 -writes nq and nr items to q and r respectively, adding leading zeros if needed
 -reads na from a and rd from d.
 -execution time depends on the size of a
 */

int ccn_div_euclid(cc_size nq, cc_unit *q, cc_size nr, cc_unit *r, cc_size na, const cc_unit *a, cc_size nd, const cc_unit *d)
{
    int status;
    CC_DECL_WORKSPACE_OR_FAIL(ws,CCN_DIV_EUCLID_WORKSPACE_SIZE(na,nd));
    status = ccn_div_euclid_ws(ws,nq,q,nr,r,na,a,nd,d);
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return status;
}

int ccn_div_euclid_ws(cc_ws_t ws, cc_size nq, cc_unit *q, cc_size nr, cc_unit *r, cc_size na, const cc_unit *a, cc_size nd, const cc_unit *d)
{
    int status;
    cc_unit *recip_d = ws->start;
    ws->start += nd+1;
    ccn_make_recip_ws(ws,nd, recip_d, d);
    status = ccn_div_use_recip_ws(ws, nq, q, nr, r, na, a, nd, d, recip_d);
    ws->start -= nd+1;
    return status;
}

// Small integers and their reciprocal as returned by ccn_make_recip():  (d, recip_d) (1, 3) (2, 7) (3, 5) (4, 15)
// The execution time depends on the operand size but not their value
// Error case may have different execution time.
int ccn_div_use_recip_ws(cc_ws_t ws, cc_size nq, cc_unit *q, cc_size nr, cc_unit *r, cc_size na, const cc_unit *a, cc_size nd, const cc_unit *d, const cc_unit *recip_d)
{
    size_t recip_bitlen = ccn_bitlen(1 + nd, recip_d);
    size_t d_bitlen = ccn_bitlen(nd, d);
    size_t nd_actual = ccn_n(nd, d);

     //if divisor is zero or reciprocal is missing return error
    if(d_bitlen==0 || recip_bitlen==0) return -2;

     // the reciprocal must be one bit longer
    cc_assert(d_bitlen == recip_bitlen -1);

    cc_size n = CC_MAX(2*nd,na);

    // each loop iteration reduces the number by 2^(bitlen-2)
    // because the substraction on the loop does a-d*q where q <= 3+a/d
    // therefore we deal with up to bitlen-2 bits at each iteration (see math below)
    size_t loop_iterations;

    if (d_bitlen>2) {
        loop_iterations=((ccn_bitsof_n(n)-1)/(d_bitlen-2));
    } else { // case where s=2, divisor d equals to one. The division loop reduces at least one bit per iteration (very slow case)
        loop_iterations=(ccn_bitsof_n(n)-2);
    }

    // Working buffers
    //      total is 2*n + n+3 + 1+n + n + n + na = 6*CC_MAX(2*nd,na) + 4 + na
    cc_unit *t1 = ws->start;              /* t1[2*(n-nd_actual+1)] */
    cc_unit *t2 = t1 + 2*(n-nd_actual+1); /* t2[3+n] */
    cc_unit *d1 = t2 + 3+n;  /* d1[1+CC_MAX(nd,n-nd_actual)] */
    cc_unit *recip1 = d1 + 1+CC_MAX(nd,n-nd_actual); /* recip1[n] */
    cc_unit *a1 = recip1+n; /* a1[n] */
    cc_unit *q1 = a1 + n;   /* q1[na] */
    ws->start=q1+na;
    cc_assert(ws->start<=ws->end);

    if (n>2+2*nd) {
        ccn_zero(n-(2+2*nd),&t2[2+2*nd]);
    }

    // Set loop initial values
    ccn_setn(n, recip1, nd+1, recip_d);
    ccn_setn(CC_MAX(nd+1,n-nd_actual+1), d1, nd, d);
    ccn_setn(n, a1, na, a);
    ccn_zero(na, q1);

    // Main loop to build an approximation
    cc_size n1=n;
    for (size_t k=0; k<loop_iterations; k++) {

        // q = (a / 2^(s-1) * (2^(2s)/d)) / 2^(s+1) is an approximation of the quotient a/d
        //Error is a/d - q <= 3. We adjust after the loop.
        ccn_shift_right_multi(n1, t2, a1, d_bitlen-1);    // a / 2^(s-1)
        ccn_mul(n1-nd_actual+1, t1, recip1, t2);            // * (2^(2s)/d)
        ccn_shift_right_multi(n1+1, t2, t1, d_bitlen+1);  // / 2^(s+1)
        ccn_add(na,q1,q1,t2);                               // quotient

        //compute the remainder
        ccn_mul(n1-nd_actual+1, t1, d1, t2);                // * d
        ccn_sub(n1, a1, a1, t1);                            // remainder

        n1 = CC_MAX(2*nd, n1-nd_actual+1); // adjust n for performance
    }

    // Adjust the result due to the quotient approximation of the last iteration
    int cond=1;
    cc_unit carry=0;
    for (unsigned int ct=0; ct < CCN_MOD_R_CTR_LIMIT; ++ct) {
        // R_index moves only if result is positive
        cc_unit c = 1 ^ ccn_sub(1 + nd, cc_muxp(cond,t1,a1), cc_muxp(cond,a1,t1), d1);
        cond ^= c;
        carry += c;
    }
    ccn_add1(na,q1,q1,carry);

    // Pointer to the result
    cc_unit *ptr_r=cc_muxp(cond,a1,t1);

    // Done
    int result = ccn_cmp(1+nd, ptr_r,d1);

    // Copy results if there is enough room and add leading zeros if needed
    // Time leak when failure occurs
    int rc=0;

    if(result>=0) {
        rc=-1; // r > d is an error
    } else {
        if(r!=NULL){ // Remainder is requested by caller
            if (nr >= nd) ccn_setn(nr, r, nd, ptr_r);
            else rc=-2;
        }
        if(q!=NULL){ // Quotient is requested by caller
            cc_assert(nq>=ccn_n(na, q1));
            if (nq >= na) ccn_setn(nq, q , na, q1);
            else ccn_set(nq, q , q1);
        }
    }
#if 0
    cc_printf("\n-- result -- nq=%zu, nr=%zu, na=%zu, nd=%zu, ----\n", nq, nr, na, nd);
    ccn_lprint(na, "a=16^^", a);
    ccn_lprint(nd, "d=16^^", d);
    ccn_lprint(nr, "r=16^^", r);
    ccn_lprint(nq, "q=16^^", q);
    cc_printf("\n");
#endif

    ws->start=t1;
    return rc;
}

/*
 A little math for a good sleep:

 The loop computes:
 q = ((s2n/2^(s+1))*R)/2^(s-1)
 where R = 2^(2s)/d is the reciprocal.

 Then it computes r = (a1 - q*d) which is an approximation of the remainder.

 Because all the divisions are integer division, the remainder needs to be adjusted to provide the exact result:
 It is possible to compute an upper bound of the adjustment by using the “ceil” of each division.
 For simplification, adding 1 to each of the intermediary quotients:

 q’ the exact quotient of iteration i
 a < 2^k where initially k=ccn_bitsof_n(a)


 q’ < ((2^k/2^(s+1) + 1)*(R+1))/2^(s-1) + 1
 <=> q’  < ( (2^k/2^(s+1)*(R+1) + (R+1) )/2^(s-1) + 1
 <=> q’  < ( (2^k/2^(s+1)*R+2^k/2^(s+1)+(R+1)  )/2^(s-1) + 1
 <=> q’  < ( (2^k/2^(s+1)*R/2^(s-1))+(2^k/2^(s+1)+(R+1))/2^(s-1)  + 1
 <=> q’  < ( q + (2^k/2^(2s) + (R+1)/2^(s-1) + 1)

 By definition of R, R=2^(2s)/d where 2^(s-1) < d < 2^s
 therefore R < 2^(s+1)
 as a consequence  (R+1)/2^(s-1) <= 2
 => q’  < ( q + (2^k/2^(2s) + 3)
 => q’ - q < (2^k/2^(2s) + 3)

 therefore
 (a1 - q*p) < (a1 - (q'-3-(2^k/2^(2s)))*p)
 (a1 - q*p) < (a1 - q'*p) + (3+2^k/2^2s)*p

 by definition of the division, (a1 - q'*p) = r < p
 (a1 - q*p) < r + (3+2^k/2^2s)*p

 with
 3+2^k/2^2s < 2^(k-2s+2)    (because 2^x+3 < 4*2^x <=> 3<2^x(4-1) <=> 1<2^x)

 it becomes
 (a1 - q*p) < r + (2^(k-2s+2))*p  and using p<2^s

 (a1 - q*p) < r + (2^(k-(s+2))

 therefore the algorithm needs at most ceiling(k/(s+2)) - 1 iterations to converge
 the math is slightly different for the last iteration since k<2s.
 For this case, please refer to the math of the function cczp_mod.
 */

#if 0
/* q*t + r == s [e.g. s/t, q=quotient, r=remainder]. */
void ccn_div(cc_size n, cc_unit *q, cc_unit *r, const cc_unit *s, const cc_unit *t) {
    if (ccn_is_zero(n, t)) {
        /* Division by zero is illegal. */
        return;
    }

    /* If s < t then q = 0, r = s */
    if (ccn_cmp(n, s, t) < 0) {
        if (r) ccn_set(n, r, s);
        if (q) ccn_zero(n, q);
        return;
    }

    cc_unit tr[n], tt[n], ta[n], tq[n];
    ccn_zero(n, tr);
    ccn_zero(n, tt);
    ccn_zero(n, ta);
    ccn_zero(n, tq);

    cc_size k = ccn_bitlen(n, s) - ccn_bitlen(n, t);
    ccn_seti(n, ta, 1);
    ccn_shift_left_multi(n, ta, ta, k);

    ccn_set(n, tr, s);

    ccn_shift_left_multi(n, tt, t, k);

    for (;;) {
        if (ccn_cmp(n, tr, tt) >= 0) {
            ccn_sub(n, tr, tr, tt);
            ccn_add(n, tq, tq, ta);
        }
        if (!k--)
            break;

        ccn_shift_left(n, tt, tt, 1);
        ccn_shift_left(n, ta, ta, 1);
    }

    if (r) {
        ccn_set(n, r, tr);
    }

    if (q) {
        ccn_set(n, q, tq);
    }
}
#endif


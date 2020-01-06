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

#define CC_DEBUG_MAKERECIP (CORECRYPTO_DEBUG && 0)

//------------------------------------------------------------------------------
// Two implementations since performance varies depending
// on performance of the multiplication / subtraction / shift
//------------------------------------------------------------------------------


/* Calculate the reciprocal r of a number d.
 r becomes the steady-state reciprocal
 2^(2b)/d, where b = bit-length of d.
 Asymptotically better than Newton Raphson
 d      is of size nd
 recip  must be of size nd+1
 */
void ccn_make_recip_shift_sub(cc_ws_t ws, cc_size nd, cc_unit *recip, const cc_unit *d)
{

    size_t b = ccn_bitlen(nd, d);
    if (b==0) {
        ccn_zero(nd+1, recip);
        return;
    }
    cc_size n = ccn_nof(b+1); // number of cc_unit to represent the reciprocal

    /* Use the following property
     2^b     = d.Qi + r
     2^(b+1) = d.2.Qi + 2r  // if 2r > d Qi+1=2.Qi + 1 otherwise Qi+1=2.Qi
     */
    cc_unit *tmp_d=ws->start;        // n units
    cc_unit *work=ws->start+n;      // 2*n units
    ws->start+=3*n;
    cc_assert(ws->start<=ws->end);
    cc_unit *R0=&work[0];
    cc_unit *R1=&work[n];

    cc_unit R_sign=0;
    long int i;
    if (nd>n)
    {
        ccn_set(n,tmp_d,d);
    }
    else
    {
        ccn_setn(n,tmp_d,nd,d);
    }

    ccn_zero(n,R0);
    ccn_set_bit(R0, b, 1);
    ccn_sub(n, R0, R0, tmp_d); // r0 = 2^b - d

    ccn_zero(nd+1,recip);
    ccn_set_bit(recip, b, 1); // 2^b/d = 1 by definition of b
    for (i=(b-1);i>=0;i-=1) {
        ccn_add(n, R0, R0, R0);         // 2*R, use add since faster than shift 1bit
        R_sign=ccn_sub(n,R1,R0,tmp_d);  // 2*R - d
        cc_mux2p((int)R_sign, (void **)&R1, (void **)&R0, R1, R0); // We keep the positive value
        ccn_set_bit(recip, i, R_sign^1);        // Set the bit to one if we had to substract
    }
    ws->start-=3*n;
}

/* Calculate the reciprocal r of a number d.
 r becomes the steady-state reciprocal
 2^(2b)/d, where b = bit-length of d.
 d      is of size nd
 recip  must be of size nd+1
 */
void ccn_make_recip_newtonraphson(cc_ws_t ws, cc_size nd, cc_unit *recip, const cc_unit *d)
{
    cc_size b;
    b = ccn_bitlen(nd, d);
    if (b==0) {
        ccn_zero(nd+1, recip);
        return;
    }
    cc_size shift_units = b / CCN_UNIT_BITS;
    cc_size shift_bits = b & (CCN_UNIT_BITS - 1);
    cc_size n = (b+1+CCN_UNIT_BITS) / CCN_UNIT_BITS;

    // Working buffers
    cc_unit *tmp2=ws->start;                // 2n units - shift_units
    cc_unit *tmp1=tmp2 + 2*n - shift_units; // 2n units
    cc_unit *tmpd=tmp1 + 2*n; // 2n units
    cc_unit *tmpr=tmpd + 2*n; // n units
    ws->start=tmpr+n;
    cc_assert(ws->start<=ws->end);

    // Locals
    if (nd<n)
    {
        ccn_zero(2*n-nd, tmpd + nd);
        ccn_set(nd, tmpd, d);
    }
    else
    {
        ccn_zero(n, tmpd + n);
        ccn_set(n, tmpd, d);
    }
    ccn_zero(n, tmpr);
    ccn_set_bit(tmpr, b+1, 1);
    ccn_sub(n, tmpr, tmpr, tmpd); // Set r as 2^(b+1)-d to skip first iteration

    // Working additional pointer to save on shift operations
    cc_unit *tmp1_shifted,*tmp2_shifted;
    tmp1_shifted=tmp1+shift_units; // Since tmp1 is at n+(n-shift_units), tmp2 has 2*n units available to tmp1_shifted
    tmp2_shifted=tmp2+shift_units;

#if CC_DEBUG_MAKERECIP
    cc_printf("cc_d[%zu] = ", b);
    ccn_print(nd, d);
    cc_printf("\n");
#endif
    // First loop: quadratic convergence toward the quotient
    // Newton–Raphson division
    cc_unit carry=1;
    if (shift_bits!=0) {
        while (carry) { //  check r' <= r equivalent to r^2/2^b * d/2^b - t > 0, if r' <= r => done
            ccn_sqr_ws(ws, n, tmp1, tmpr);   // t1 = r^2
            ccn_shift_right(2*n-shift_units, tmp1_shifted, tmp1_shifted, shift_bits); // t1 = t1/2^b = r^2/2^b
            ccn_mul_ws(ws, n, tmp2, tmpd, tmp1_shifted);                              // t2 = t1 * d = r^2/2^b * d
            ccn_shift_right(2*n-shift_units, tmp2_shifted, tmp2_shifted, shift_bits); // t2 = t2/2^b = r^2/2^b * d/2^b
            carry=ccn_sub(n, tmp2_shifted, tmp2_shifted,tmpr);                        // t2 - r = r^2/2^b * d/2^b - r
            ccn_sub(n, tmpr, tmpr, tmp2_shifted);                                     // r' = 2r
        }
    } else {
        while (carry) { //  check r' <= r equivalent to r^2/2^b * d/2^b - t > 0, if r' <= r => done
            ccn_sqr_ws(ws, n, tmp1, tmpr);   // t1 = r^2
            ccn_mul_ws(ws, n, tmp2, tmpd, tmp1_shifted);                      // t2 = t1 * d = r^2/2^b * d
            carry=ccn_sub(n, tmp2_shifted, tmp2_shifted,tmpr);                // t2 - r = r^2/2^b * d/2^b - r
            ccn_sub(n, tmpr, tmpr, tmp2_shifted);                             // r' = 2r
        }
    }

    // Second loop, find the exact quotient
    ccn_mul_ws(ws, n, tmp2, tmpr, tmpd);
    ccn_seti(n, tmp1_shifted, 1);
    while (ccn_bitlen(2 * n, tmp2) > 2 * b) {
#if CC_DEBUG_MAKERECIP
        cc_printf("cc_r2 = ");
        ccn_print(n, tmpr);
        cc_printf("\n");
#endif
        ccn_sub(n, tmpr, tmpr, tmp1_shifted);
        ccn_sub(2 * n, tmp2, tmp2, tmpd);
    }
    ccn_setn(1 + nd, recip, n, tmpr);
#if CC_DEBUG_MAKERECIP
    cc_printf("cc_r3 = ");
    ccn_print(1 + nd, recip);
    cc_printf("\n");
#endif
    ws->start=tmp2;
}

#define CC_MAKE_RECIP_NEWTONRAPHSON_OPTION  1
#define CC_MAKE_RECIP_SHIFT_SUB_OPTION      0


/* Calculate the reciprocal r of a demonimator d.
 recip becomes the steady-state reciprocal
 2^(2b)/d, where b = bit-length of d-1.
 d      is of size nd
 recip  must be of size nd+1
 */
void ccn_make_recip_ws(cc_ws_t ws, cc_size nd, cc_unit *recip, const cc_unit *d)
{
#if CC_DEBUG_MAKERECIP
    // DEBUG: Both methods and compare the result
    ccn_make_recip_newtonraphson(nd, recip, d);
    cc_printf("Newton-Raphson = ");
    ccn_print(1 + nd, recip);
    cc_printf("\n");
    cc_unit recip2[1 + nd];
    ccn_make_recip_shift_sub(nd, recip2, d);
    cc_printf("Shift sub = ");
    ccn_print(1 + nd, recip2);
    cc_printf("\n");
    cc_assert(ccn_cmp(nd+1,recip2,recip)==0);
#else
    // NO DEBUG: One method
#if CC_MAKE_RECIP_NEWTONRAPHSON_OPTION
    ccn_make_recip_newtonraphson(ws,nd, recip, d);
#endif // CC_MAKE_RECIP_NEWTONRAPHSON_OPTION

#if CC_MAKE_RECIP_SHIFT_SUB_OPTION
    ccn_make_recip_shift_sub(ws,nd, recip, d);
#endif // CC_MAKE_RECIP_SHIFT_SUB_OPTION

#if CC_MAKE_RECIP_NEWTONRAPHSON_OPTION && CC_MAKE_RECIP_SHIFT_SUB_OPTION
    #error "Two reciprocal methods have been selected"
#endif
    
#endif // CC_DEBUG_MAKERECIP

}

int ccn_make_recip(cc_size nd, cc_unit *recip, const cc_unit *d) {
    ccn_zero(nd+1,recip); // If workspace fails, recip is all zeroes
    CC_DECL_WORKSPACE_OR_FAIL(ws,CCN_MAKE_RECIP_WORKSPACE_SIZE(nd));
    ccn_make_recip_ws(ws,nd,recip,d);
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return 0;
}

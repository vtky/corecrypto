/*
 * Copyright (c) 2011,2014,2015,2016,2017,2018 Apple Inc. All rights reserved.
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

#include <corecrypto/cczp.h>
#include <corecrypto/cczp_priv.h>

#define CCN_MOD_R_CTR_LIMIT  3


/* compute r = s % d, where d=cczp_prime(zp). ns is the length of s.
   cczp_init(zp) must have been called before calling this function, since ccn_div_use_recip()
   uses the reciprocal of d.
 */

int cczp_modn(cczp_const_t zp, cc_unit *r, cc_size ns, const cc_unit *s)
{
    int status;
    CC_DECL_WORKSPACE_OR_FAIL(ws,CCN_DIV_USE_RECIP_WORKSPACE_SIZE(ns,cczp_n(zp)));
    status = ccn_div_use_recip_ws(ws, 0, NULL, cczp_n(zp), r, ns, s, cczp_n(zp), cczp_prime(zp), cczp_recip(zp));
    CC_FREE_WORKSPACE(ws);
    return status;
}

int cczp_modn_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, cc_size ns, const cc_unit *s)
{
    int status;
    status = ccn_div_use_recip_ws(ws, 0, NULL, cczp_n(zp), r, ns, s, cczp_n(zp), cczp_prime(zp), cczp_recip(zp));
    return status;
}


/* Do r = s2n % d,  where d=cczp_prime(zp). where 
 - The recip is the precalculated steady-state reciprocal of d
 - r is count cc_units in size, s2n is 2 * count units
 - d is count units in size and recip is count + 1 units in size.
 - IMPORTANT: Use only if s2n < 2^2s   (see the math section below)
 */
void cczp_mod(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *s2n) {
    cc_size n=cczp_n(zp);
    size_t s = ccn_bitlen(1 + n, cczp_recip(zp));
    cc_assert(s>3); // Sanity check on reciprocal
    s--;

    cc_unit *tmp1,*tmp2;
    cc_unit *tmpd;
    cc_size unitShift_s_minus_1=(s-1) / CCN_UNIT_BITS;
    cc_size unitShift_s_plus_1=(s+1) / CCN_UNIT_BITS;
    cc_assert(ws!=NULL);
    tmp1=ws->start;       // tmp1 is 2*n
    tmp2=&tmp1[2*n+2-unitShift_s_plus_1];    // tmp2 is 2+2*n
    tmpd=&tmp2[2*n+2];    // tmpd is n+1
    cc_assert(tmpd+n+1<=ws->end); // Check that provided workspace is sufficient
    ws->start+=5*(n+1);
    cc_unit *R0;
    cc_unit *R1;
    cc_size R_index=1;
    ccn_setn(1 + n, tmpd, n, cczp_prime(zp));
    ccn_shift_right(2*n-unitShift_s_minus_1, tmp1, &s2n[unitShift_s_minus_1], (s - 1) & (CCN_UNIT_BITS-1));
    ccn_mul_ws(ws, 1 + n, tmp2, cczp_recip(zp), tmp1);
    ccn_shift_right(2*n+2-unitShift_s_plus_1, tmp1, &tmp2[unitShift_s_plus_1], (s + 1) & (CCN_UNIT_BITS-1));
    ccn_mul_ws(ws, n, tmp2, tmpd, tmp1);
    ccn_sub(2 * n, tmp2, s2n, tmp2);
    for (unsigned int ct=0; ct < CCN_MOD_R_CTR_LIMIT; ++ct) {
        cc_mux2p((int)R_index,(void*)&R1,(void*)&R0,tmp2,tmp1);
        // R_index moves only if result is positive
        R_index^= 1 ^ ccn_sub(1 + n, R0, R1, tmpd);
    }
    R1=cc_muxp((int)R_index,tmp2,tmp1);
    cc_assert(ccn_cmp(1 + n, R1,tmpd)<0);
    ccn_set(n, r, R1);
    ws->start=tmp1;
}
/*
 A little math for CCN_MOD_R_CTR_LIMIT:

 The loop computes:
 q = ((s2n/2^(s+1))*R)/2^(s-1)
 where R = 2^(2s)/d is the reciprocal.

 Then it computes r = (s2n - q*d) which is an approximation of the remainder.

 Because all the divisions are integer division, the remainder needs to be adjusted to provide the exact result:
 It is possible to compute an upper bound of the adjustment by using the “ceil” of each division.
 For simplification, adding 1 to each of the intermediary quotients:

 q’ the exact quotient

 q’< ((s2n/2^(s+1) + 1)*(R+1))/2^(s-1) + 1
 <=> q’  < ( (s2n/2^(s+1)*(R+1) + (R+1) )/2^(s-1) + 1
 <=> q’  < ( (s2n/2^(s+1)*R+s2n/2^(s+1)+(R+1)  )/2^(s-1) + 1
 <=> q’  < ( (s2n/2^(s+1)*R/2^(s-1))+(s2n/2^(s+1)+(R+1))/2^(s-1)  + 1
 <=> q’  < ( q + (s2n/2^(2s) + (R+1)/2^(s-1) + 1)

 By definition of R, R=2^(2s)/d where 2^(s-1) < d < 2^s
 therefore R < 2^(s+1)
 as a consequence  (R+1)/2^(s-1) <= 2
 => q’  < ( q + (s2n/2^(2s) + 3)
 => q’ - q <  (s2n/2^(2s) + 3)

 As long as the input s2n is < 2^2s, at most 3 substractions are needed.

 */


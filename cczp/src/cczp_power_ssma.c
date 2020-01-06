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

#include <corecrypto/cczp.h>
#include <corecrypto/cczp_priv.h>
#include "cc_debug.h"
#include "cc_macros.h"


/* Copy the correct operand into buffer r:
 r <- *(s+kii*n) */
static void copy_mux4(int kii,
              cc_unit *r,
              cc_size n,
              const cc_unit *s) {
    cc_unit mask0,mask1,mask2,mask3;
    int ki=kii&1;
    int kj=(kii>>1)&1;
    mask0=((cc_unit)(ki | kj)-(cc_unit)1);
    mask1=((cc_unit)((1^ki) | kj)-(cc_unit)1);
    mask2=((cc_unit)(ki | (kj^1))-(cc_unit)1);
    mask3=~((cc_unit)(ki & kj)-(cc_unit)1);

    // Copy involving all 4 possible operands
    for (cc_size i=0;i<n;i++) {
        r[i] = ((mask0 & s[i])
              | (mask1 & s[i+n])
              | (mask2 & s[i+2*n])
              | (mask3 & s[i+3*n]));
    }
}

/* r = s^e (mod zp->prime).
 Implements square square multiply always: 2bit fix windows
 running in constant time. A dummy multiplication is performed when both bit
 are zeros so that the execution has a regular flow
 This approach is sensitive to cache attacks and therefore this implementation
 should be used with randomized (blinded) operands only.

 Caller provides recip of m as recip; s and r can have the same address. */
int
cczp_power_ssma_ws(cc_ws_t ws, cczp_const_t zp, cc_unit *r, const cc_unit *s, const cc_unit *e)
{
    int rc = 1;
    
    cc_size n = cczp_n(zp);
    
    /* We require s<p */
    cc_require(ccn_cmp(cczp_n(zp), s, cczp_prime(zp)) < 0, err);
 
    size_t ebitlen = ccn_bitlen(n, e);

    if (ebitlen == 0) {
        ccn_seti(n, r, 1);
        return 0;
    } else if (ebitlen == 1) {
        ccn_set(n, r, s);
        return 0;
    }
    
    /* ebitlen > 1 */
    
    cc_unit *minusone=ws->start;
    cc_unit *m1=ws->start+n;
    cc_unit *m2=ws->start+2*n;
    cc_unit *m3=ws->start+3*n;
    cc_unit *t=ws->start+4*n;
    ws->start+=5*n;

    /* Precomputations */
    ccn_sub1(n,minusone,cczp_prime(zp), 1); // Use -1 since 1 has very low hamming weight. Minus one is much less leakage prone.
    ccn_set(n,m1,s);
    cczp_sqr_ws(ws, zp, m2, s);
    cczp_mul_ws(ws, zp, m3, s, m2);
    ccn_set(n,r,minusone);

    size_t exp_bitlen=ebitlen;
    exp_bitlen= (exp_bitlen+1) & (~1); // round up to even number

    // For each cc_unit
    int i=(exp_bitlen - 2) & (CCN_UNIT_BITS-1); // First loop is shorter, start at the MSbits.
    cc_unit msword=1;
    for (size_t k=ccn_nof(exp_bitlen); k > 0; --k) {
        msword=e[k-1];

        /* 2bit fixed window */
        for (; i>=0; i-=2) {
            cczp_sqr_ws(ws, zp, r, r);
            cczp_sqr_ws(ws, zp, r, r);
            copy_mux4((int)(msword>>i),t,n,minusone);
            cczp_mul_ws(ws, zp, r, r, t);
        }
        i=CCN_UNIT_BITS-2;
    }

    /* compensate for extra -1 operation */
    cc_unit *mii = cc_muxp((int)(((msword>>1) | msword) & 1)^1, r, minusone);
    ccn_sub(n,mii,cczp_prime(zp),r);

    rc = 0;
    ws->start-=5*n; // r
    
err:
    return rc;
}




int
cczp_power_ssma(cczp_const_t zp, cc_unit *r, const cc_unit *s, const cc_unit *e) {
    int rc;
    cc_size n = cczp_n(zp);
    CC_DECL_WORKSPACE_OR_FAIL(ws, CCZP_POWER_SSMA_WORKSPACE_N(n));
    rc = cczp_power_ssma_ws(ws,zp,r,s,e);
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return rc;
}




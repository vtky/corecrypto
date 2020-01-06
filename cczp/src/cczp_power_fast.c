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

#include <corecrypto/cczp.h>
#include <corecrypto/cczp_priv.h>
#include "cc_macros.h"

/* r = s^e (mod zp->prime). Implements 2bit window method
 Leak the exponent, to be used with public values only.
 Caller provides recip of m as recip; s and r can have the same address. */
int
cczp_power_fast(cczp_const_t zp, cc_unit *r, const cc_unit *s, const cc_unit *e) {
    int rc = 1;
    
    cc_size n = cczp_n(zp);
    
    /* We require s<p */
    cc_require(ccn_cmp(cczp_n(zp), s, cczp_prime(zp)) < 0, err);
    
    size_t ebitlen = ccn_bitlen(n, e);
    
    if (ebitlen == 0) {
        ccn_seti(n, r, 1);
        return 0;
    }
    
    {
        CC_DECL_WORKSPACE_OR_FAIL(ws, CCZP_MUL_WORKSPACE_N(n)+2*n);
        cc_unit *s1=ws->start;
        cc_unit *s3=ws->start+n;
        ws->start+=2*n;
        
        ccn_set(n, r, s);
        ccn_set(n, s1, s);
        
        if (ebitlen > 32) {
            cc_size bit;
            uint8_t c;
            
            // 2bit window for the exponentiation
            
            // Precomputation
            bit=((ebitlen+1) & ~1) - 1;          // First bit to process
            cczp_sqr_ws(ws, zp, r, s1);          // s^2
            cczp_mul_ws(ws, zp, s3, r, s1);      // s^3
            
            // First iteration is different
            c=(ccn_bit(e, bit)<<1) | ccn_bit(e, bit-1);
            switch (c)
            {
                case 1:
                    ccn_set(n, r, s1); // set r to s
                    break;
                case 2:
                    // Nothing, r contains s^2 already
                    break;
                case 3:
                    ccn_set(n, r, s3); // set r to s^3
                    break;
                default:
                    // Can't happen:
                    // Most significant bit can't be zero if bitlen>0.
                    cc_assert(ccn_bit(e, ebitlen-1)==1);
                    break;
            }
            bit-=2;
            
            // Loop
            for (; bit < ebitlen; bit-=2) {
                c=(ccn_bit(e, bit)<<1) | ccn_bit(e, bit-1);
                cczp_sqr_ws(ws, zp, r, r);
                switch (c)
                {
                    case 0:
                        cczp_sqr_ws(ws, zp, r, r);
                        break;
                    case 1:
                        cczp_sqr_ws(ws, zp, r, r);
                        cczp_mul_ws(ws, zp, r, r, s1);
                        break;
                    case 2:
                        cczp_mul_ws(ws, zp, r, r, s1);
                        cczp_sqr_ws(ws, zp, r, r);
                        break;
                    case 3:
                        cczp_sqr_ws(ws, zp, r, r);
                        cczp_mul_ws(ws, zp, r, r, s3);
                        break;
                    default:
                        break;
                }
            }
        }
        else if (ebitlen > 1) {
            // Single bit exponentiation
            for (size_t bit = ebitlen - 2; bit < ebitlen; --bit) {
                cczp_sqr_ws(ws, zp, r, r);
                if (ccn_bit(e, bit)) {
                    cczp_mul_ws(ws, zp, r, r, s1);
                }
            }
        }
        
        ws->start-=2*n; // s1 & s3
        CC_CLEAR_AND_FREE_WORKSPACE(ws);
    }
    
    rc = 0;
    
err:
    return rc;
}

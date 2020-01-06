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
#include "cc_macros.h"
#include <corecrypto/ccn.h>
#include <corecrypto/ccn_priv.h>
#include <corecrypto/cczp.h>
#include "cczp_inv.h"

static int validate_result(cczp_const_t zp, const cc_unit *xi, const cc_unit *x)
{
    int status;
    const cc_unit *p = cczp_prime(zp);
    cc_size n = cczp_n(zp);

    //cczp_mul() doesn't support small moduli well
    n = ccn_n(n, p); // get the real n
    if(n==1 && *p<0xFFFF){ //to work on both 32 and 64 kernel
        cc_unit r = (xi[0] * x[0]) % p[0];
        return r==1?0:-1;
    }

    cczp_decl_n(n, zp2);
    CCZP_N(zp2) = n; //need to define another zp we cannot modify the length of the original zp
    ccn_set(n, CCZP_PRIME(zp2), p);
    cc_unit r[n];//vla
    cc_require((status=cczp_init(zp2))==0,errOut);
    cczp_mul(zp2, r, xi, x);
    status = ccn_is_one(n, r)?0:CCZP_INV_NO_INVERSE; // We are about to return a value which is not the inverse.
errOut:
    return status;
}

#define is_even(a) ((a[0]&1)==0)
int cczp_inv(cczp_const_t zp, cc_unit *r, const cc_unit *a)
{
    const cc_size n =cczp_n(zp);
    const cc_unit *p = cczp_prime(zp);

    //zeros must be checked, otherwise the function gets stuck in an infinit loop.
    if (ccn_is_zero(n, p))
        return CCZP_INV_INVALID_INPUT;

    //zero has no inverse
    if(ccn_is_zero(n, a))
        return CCZP_INV_INVALID_INPUT;

    //there is no need to check for a and p both even, XGCD handles that correctly

    //XGCD expects p>a
    //this will take care of p==1 as well
    cc_unit a1[n];//vla
    int rc = ccn_cmp(n, p, a);
    if(rc==0){
        //we return here because we have the information to make the right decision.
        //otherwise, XGCD handles p==a case correctly
        return CCZP_INV_NO_INVERSE; //there is no inverse
    }else if(rc<0){
        rc = ccn_div_euclid(0, NULL, n, a1, n, a, n, p);
        //we cannot call cczp_init(zp) and cczp_modn(zp, a1, n, a) because zp is passed as constant
        if(ccn_is_zero(n, a1)) return CCZP_INV_NO_INVERSE;
        if(rc!=0) return rc;
    }else
        ccn_set(n, a1, a);

#if 0
    //activate this code on systems with a slow multiplier or without a multiplier,
    //where xgcd() is slower than the binary algoritm
    if(!is_even(p)){
        return cczp_mod_inv_odd(zp, _r, a1);
    }
#endif

    //X and Y are signed and need to be of size n+1
    cc_unit Y[n+1];//vla
#if PERFORM_FULL_XGCD
    cc_unit X[n+1];//vla
#else
    cc_unit *X=NULL;
#endif

    rc=xgcd(n, X, Y, p, a1);
    if(Y[n+1-1]) //check Y sign. Sign can also be addressed by considering one of the inputs negative, as well
        ccn_sub(n, Y, p, Y);

    if(rc==0)
        rc = validate_result(zp, Y, a1);

    if (rc==0)//do the data transfer, if inverse exists
        ccn_set(n, r, Y);
    
    return rc;
}

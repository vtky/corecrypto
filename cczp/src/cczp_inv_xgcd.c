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
#include <corecrypto/cc_priv.h>
#include "cc_debug.h"
#include "cczp_inv.h"

// General extended GCD implementation, only for use in cczp_inv().
// Improving the Multiprecision Euclidean Algorithm, Tudor Jbelean, June 10,1993

//configuration parameters
#define FAST_INVERSE    1

#define is_zero(n, V) ccn_is_zero(n-1, V)
#define is_one(n, V)  ccn_is_one(n, V)  //equivelent to: ccn_is_one(n-1, V) && V[n-1]==0
#define msbit(a)      ((a)&(CC_ONE<<(CCN_UNIT_BITS-CC_ONE)))

//- signed arithmetic ----------------------------------------------------------
// R=A+B, R is of size n+1
typedef cc_unit (*addsub_t)(cc_size count, cc_unit *r, const cc_unit *s, const cc_unit *t);
static void add_signed(cc_size n, cc_unit *R, const cc_unit *A, const cc_unit *B)
{
    unsigned d;
    cc_unit *A1, *B1;
    addsub_t f;
    cc_unit sa = A[n-1];
    cc_unit sb = B[n-1];
    cc_assert(sa==0 || sa==1);
    cc_assert(sb==0 || sb==1);

    d  = ccn_cmp(n-1, A, B)<0;
    A1 = cc_muxp(d, B, A);
    B1 = cc_muxp(d, A, B);
    f  = (addsub_t)cc_muxp((sa^sb)!=0, ccn_sub, ccn_add);
    R[n-1] = f(n-1, R, A1, B1);
    CC_MUXU(R[n],d, sb, sa);//extends array R. set the sign is redundant when sa==sb
}

#if FAST_INVERSE
// R = a*X
// a and X are either positive or negative
// result R size is n+1
static void aX(const cc_size n, cc_unit *R, const cc_unit *X, cc_int _a)
{
    cc_int a;
    CC_MUXU(a, _a<0, -_a, _a);
    R[n-1] = ccn_mul1(n-1, R, X, (cc_unit)a);
    R[n] = (_a<0) ^ X[n-1]; //sign of the output
}

// R = a*X + b*Y
// X & Y are positive or negative.
// result R can be the same as X or Y pointers
// R is signed and of size n+2
static void aX_plus_bY(const cc_size n, cc_unit *R, cc_int a, const cc_unit *X, cc_int b, const cc_unit *Y)
{
    cc_unit Yb[n+1], Xa[n+1];//vla

    aX(n, Xa, X, a);
    aX(n, Yb, Y, b);
    add_signed(n+1, R, Xa, Yb);
}

//X, Y = a0*X+b0*Y, a1*X+b1*Y
//input and outputs are signed
//not a general function. Size of X and Y stays the same
static void aX_plus_bY_pair(const cc_size n, cc_int a0, cc_int a1, cc_int b0, cc_int b1, cc_unit *X, cc_unit *Y)
{
    cc_unit T1[n+2], T2[n+2];//vla

    aX_plus_bY(n, T1, a0, X, b0, Y);
    aX_plus_bY(n, T2, a1, X, b1, Y);

    ccn_set(n, X, T1);
    ccn_set(n, Y, T2);

    //this assert makes sure the computed X and Y are of size n-1 and have not
    //increased in size due to X = a0*X+b0*Y. That is the property of XGCD
    //computation
    cc_assert(X[n-1]==0);
    X[n-1] = T1[n+2-1];
    cc_assert(Y[n-1]==0);
    Y[n-1] = T2[n+2-1];
}

//- shadow GCD -----------------------------------------------------------------
//get the most significant digit, remove leading zeros
static cc_int get_msd(cc_size n, cc_size cnt, const cc_unit *U)
{
    cc_unit u;
    cc_unit Z[2] = {0, U[0]};
    cc_unit *T = cc_muxp(n>=2, U, Z);
    CC_MUXU(n,n==1, 2, n);

    cc_dunit dU = hl(T[n-1], T[n-2]);
#if CCN_UINT128_SUPPORT_FOR_64BIT_ARCH
    // remove if() after fix
    if(cnt==0){
        dU = (dU) >> 2;
    }else{
        dU = (dU << cnt) >> 2;
    }
#else
    if(cnt==0){
        shr_128(&dU, 2);
    }else{
        shl_128(&dU, cnt);
        shr_128(&dU, 2);
    }
    
#endif
    u = hi(dU);

    /* above, is the onstant-time version of the following code
     if(n>=2){
        cc_dunit dU = hl(U[n-1], U[n-2]);
        dU = (dU << cnt) >> 2;
        u = hi(dU);
     } else { //n==1
        u = (U[0] << cnt) >> 2;
     }
     */
    return u;
}

static void get_msds(cc_int *u, cc_int *v, cc_size n, const cc_unit *U, const cc_unit *V)
{
    n = ccn_n(n-1, U); //ditch the sign, although U is positive
    cc_assert(n>=1);

    cc_assert(U[n-1]!=0);
    cc_size cnt = count_leading_zeros(U[n-1]);
    *u = get_msd(n, cnt, U);
    *v = get_msd(n, cnt, V);
}

#if CCN_UINT128_SUPPORT_FOR_64BIT_ARCH
 #define next(z, q) z##2 = (cc_int)(z##0-(cc_dint)q*z##1)
#else
 #define next(z, q)  z##2 = next_xgcd(z##0, z##1, q)
#endif

#define rotate(z)  z##0=z##1; z##1=z##2
static void xgcd_step_shadow(const cc_size n, cc_unit *U, cc_unit *V,
#if PERFORM_FULL_XGCD
                             cc_unit *A, cc_unit *B,
#else
                             cc_unit *A CC_UNUSED, cc_unit *B CC_UNUSED,
#endif
                             cc_unit *C, cc_unit *D)
{
    cc_int x0, x1, x2, y0, y1, y2, u0, u1, u2, q;
    int i, done;

    //check memory corruption and make sure U and V are sane
    cc_assert(ccn_cmp(n-1, U, V) >=0 && U[n-1]==0 &&  V[n-1]==0);

    get_msds(&u1, &u2, n, U, V);
    x1=1, x2=0, y1=0, y2=1, done=i=0;
    while(!done){
        rotate(x); rotate(y); rotate(u);
        q=u0/u1;
        next(x, q); next(y, q); next(u, q);
        i++;
        CC_MUXU(done,i&1, (u2< -y2) || (u1-u2<x2-x1), (u2< -x2) || (u1-u2<y2-y1));
    }

    //extra rotate is going to speed up the inverse, but requires slight code modification
    //rotate(x); rotate(y); rotate(u);

    aX_plus_bY_pair(n, x0, x1, y0, y1, U, V);
#if PERFORM_FULL_XGCD
    aX_plus_bY_pair(n, x0, x1, y0, y1, A, B);
#endif
    aX_plus_bY_pair(n, x0, x1, y0, y1, C, D);
}

#endif //FAST_INV

//- extended GCD ---------------------------------------------------------------
// compute remainder
// A,B = B, A-B*Q. This is NOT a general function for computing remainder
// Q is positive
static void rem(cc_size n, cc_unit *A, cc_unit *B, cc_unit *Q)
{
    const cc_size nn = 2*(n-1)+1;
    cc_unit TT[nn+1], AA[nn];//vla

    //prepare AA <- A, but with double length
    ccn_setn(nn, AA, n-1, A); AA[nn-1] = A[n-1];

    ccn_zero(nn, TT);
    //make it little bit faster
    if(ccn_n(n-1, Q)==1)
        ccn_mul1(n-1, TT, B, Q[0]); //this is the case most of the time
    else
        ccn_mul(n-1, TT, B, Q);

    TT[nn-1] = B[n-1] ^ Q[n-1];
    TT[nn-1] = !TT[nn-1]; //A-BQ

    add_signed(nn, TT, AA, TT); //now TT is one word larger
    ccn_set(n, A, B);
    ccn_set(n-1, B, TT); B[n-1] = TT[nn+1-1];
}


#if 0
//print function for debug
static void prn_QUV(const cc_size n CC_UNUSED, const cc_unit *Q CC_UNUSED, const cc_unit *U CC_UNUSED, const cc_unit *V CC_UNUSED,  const char *msg CC_UNUSED)
{
    cc_printf("\n%s", msg);
    if( U!= NULL) ccn_lprint(n, "\nU=", U);
    if( V!= NULL) ccn_lprint(n, "\nV=", V);
    if( Q!= NULL) ccn_lprint(n, "\nQ=", Q);
}
#endif

// Q = U/V, R=U%V
// U, V = V, R
static int xgcd_step(const cc_size n, cc_unit *Q, cc_unit *U, cc_unit *V)
{
    //if this condition is not met, something is wrong with the code
    int rc = (U[n-1]==0) && (V[n-1]==0) ? 0 : CCZP_INV_ERROR;
    cc_assert(ccn_cmp(n-1, U, V) >=0 && U[n-1]==0 &&  V[n-1]==0);

    cc_unit R[n];//vla

    //skip sign
    rc|=ccn_div_euclid_sp(n-1, Q, R, U, V);
    ccn_set(n-1, U, V);
    ccn_set(n-1, V, R);
    Q[n-1]=U[n-1]=V[n-1]=0;

    return rc;
}

#define bitlen(n, T) ccn_bitlen(n-1, T)
// the returned values X and Y must be of size n+1, because they are signed
// inputs U and V are undigned and are of size n
int xgcd(const cc_size _n, cc_unit *X,  cc_unit *Y, const cc_unit *_U, const cc_unit *_V)
{
    /* perform these tests if XGCD is going to be used standalone.
     GCD(0,v) == v; GCD(u,0) == u, GCD(0,0) == 0
     if (u == 0) return v;
     if (v == 0) return u;
     */

    //A=X, C=Y;
    int rc=0;
    const cc_size n = _n + 1;
    cc_unit *C=Y, *A=X, D[n], U[n], V[n];//vla
#if PERFORM_FULL_XGCD
    cc_unit B[n];//vla
#else
    cc_unit *B=NULL;
#endif
    ccn_set(n-1, U, _U); U[n-1]=0;
    ccn_set(n-1, V, _V); V[n-1]=0;

#if !FAST_INVERSE
    if(B!=NULL) ccn_seti(n, A, 1);
    if(B!=NULL) ccn_zero(n, B);
#endif
    
#if PERFORM_FULL_XGCD
    ccn_seti(n, A, 1);
    ccn_zero(n, B);
#endif
    ccn_zero(n, C);
    ccn_seti(n, D, 1);
    while(rc==0 && !is_zero(n, V)){
#if FAST_INVERSE
        cc_size k =CCN_UNIT_BITS-2;
        cc_size lu=bitlen(n, U);
        cc_size lv=bitlen(n, V);
        if(lu>k && lu-lv<k/2){
            xgcd_step_shadow(n, U, V, A, B, C, D);
        }
#endif
        cc_unit Q[n];//vla
        rc = xgcd_step(n, Q, U, V);
        rem(n, C, D, Q);
#if PERFORM_FULL_XGCD
        rem(n, A, B, Q);
#endif
    }
#if 0
    ccn_lprint(0, "\n===XGCD", U);
    ccn_lprint(n-1, "_U=", _U);
    ccn_lprint(n-1, "_V=", _V);
    ccn_lprint(n, " U=", U);
    ccn_lprint(n, " V=", V);
    ccn_lprint(n, " A=", A);
    ccn_lprint(n, " B=", B);
    ccn_lprint(n, " C=", C);
    ccn_lprint(n, " D=", D);
#endif

    if(rc==0){
        rc = is_one(n, U)? 0 : CCZP_INV_NO_INVERSE;
    }
    
    return rc;
}

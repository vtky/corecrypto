/*
 * Copyright (c) 2010,2015,2016,2017,2018 Apple Inc. All rights reserved.
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
#include <corecrypto/ccec_priv.h>
#include "cc_macros.h"
#include "cc_debug.h"

#if defined(DEBUG) && 0
#define CCEC_MULT_DEBUG 1
#else
#define CCEC_MULT_DEBUG 0
#endif

// Configuration
#define EC_CURVE_SUPPORT_ONLY_A_MINUS_3

#define SCA_MASK_BITSIZE 32
#define SCA_MASK_N ccn_nof(SCA_MASK_BITSIZE)
#define SCA_MASK_MSBIT (((cc_unit)1)<<(SCA_MASK_BITSIZE-1))

/*!
 @function   XYCZadd_ws
 @abstract   (X,Y)-only co-Z addition with update

 @param      P         Input: X:Y Jacobian coordinate for P
                        Output: X:Y Jacobian coordinate for (P + Q)
 @param      Q        Input: X:Y Jacobian coordinate for Q
                        Output: X:Y Jacobian coordinate for P'
 @param      ws        Worskpace for internal computations
                        To be cleaned up by the caller.
 @result
            Given the twos points P and Q and a curve cp,
            Compute P' and P+Q where
            P' ~= P (same point in the equivalence class)
            P' and (P+Q) have the same Z coordinate
            Z coordinate omitted in output
 */
#define CCEC_XYCZadd_ws_WORKSPACE_N(n) (2*(n))
static void XYCZadd_ws(cc_ws_t ws,
                    ccec_const_cp_t cp,
                    cc_unit *P,
                    cc_unit *Q)
{
    cc_size n=ccec_cp_n(cp);
    cc_unit *t1=&P[0],*t2=&P[n],
            *t3=&Q[0],*t4=&Q[n];
    cc_unit *t5=ws->start;
    cc_unit *t6=ws->start+n;
    ws->start+=2*n;
    cc_assert((ws->start)<=ws->end); // Check that provided workspace is sufficient;

 /*
    Algo 18
    modified to have input and output in same buffer
    use more RAM but less than XYCZaddC_ws so that it does not matter
    Cost: 2S + 4M + 7sub
 */
    cczp_const_decl(zp, ccec_cp_zp(cp));

    cczp_sub_ws(ws, zp, t5, t3, t1);       //  X2-X1
    cczp_sqr_ws(ws, zp, t5, t5);       // (X2-X1)^2=A
    cczp_mul_ws(ws, zp, t6, t3, t5);   // X2.A=C
    cczp_mul_ws(ws, zp, t3, t1, t5);   // X1.A=B
    cczp_sub_ws(ws, zp, t5, t4, t2);       // Y2-Y1
    cczp_sqr_ws(ws, zp, t1, t5);       // (Y2-Y1)^2 = D
    cczp_sub_ws(ws, zp, t1, t1, t3);       // D - B

    cczp_sub_ws(ws, zp, t1, t1, t6);       // X3
    cczp_sub_ws(ws, zp, t6, t6, t3);       // C - B
    cczp_mul_ws(ws, zp, t4, t2, t6);   // Y1 (C - B)
    cczp_sub_ws(ws, zp, t2, t3, t1);       // B - X3
    cczp_mul_ws(ws, zp, t2, t5, t2);   // (Y2-Y1) (B - X3)
    cczp_sub_ws(ws, zp, t2, t2, t4);       // (Y2-Y1)(B - X3) - Y1 (C - B)

    ws->start=t5; // restore workspace starting point. 
}

/*!
 @function   XYCZaddC_ws
 @abstract   (X,Y)-only co-Z conjugate addition with update

 @param      P        Input: X:Y Jacobian coordinate for P
                        Output: X:Y Jacobian coordinate for (P+Q)
 @param      Q        Input: X:Y Jacobian coordinate for Q
                        Output: X:Y Jacobian coordinate for (P-Q)
 @param      ws        Worskpace for internal computations
                        To be cleaned up by the caller.
 @result
             Given the twos points P and Q and a curve cp,
             Compute P' and P+Q where
             P' ~= P (same point in the equivalence class)
             (P-Q) and (P+Q) have the same Z coordinate
             Z coordinate omitted in output
 */

#define CCEC_XYCZaddC_ws_WORKSPACE_N(n) (7*(n))
static void XYCZaddC_ws(cc_ws_t ws,
                     ccec_const_cp_t cp,
                     cc_unit *P,
                     cc_unit *Q)
{
    cc_size n=ccec_cp_n(cp);
    cc_unit *t1=&P[0],*t2=&P[n],
        *t3=&Q[0],*t4=&Q[n];

    cc_unit *t5=ws->start;
    cc_unit *t6=ws->start+n;
    cc_unit *t7=ws->start+2*n;
    ws->start+=3*n;
    cc_assert((ws->start)<=ws->end); // Check that provided workspace is sufficient;

    /*
     Algo 19
     Modified to have same input and output buffers
     Cost: 3S + 5M + 11add/sub
     */
    cczp_const_decl(zp, ccec_cp_zp(cp));

    cczp_sub_ws(ws, zp, t5, t3, t1);       //  X2-X1
    cczp_sqr_ws(ws, zp, t5, t5);       // (X2-X1)^2=A
    cczp_mul_ws(ws, zp, t6, t1, t5);   // X1 * A = B
    cczp_mul_ws(ws, zp, t1, t3, t5);   // X2 * A = C
    cczp_add_ws(ws, zp, t5, t4, t2);       // Y2+Y1
    cczp_sub_ws(ws, zp, t4, t4, t2);       // Y2-Y1
    cczp_sub_ws(ws, zp, t3, t1, t6);       // C - B
    cczp_mul_ws(ws, zp, t7, t2, t3);   // Y1 * (C-B)
    cczp_add_ws(ws, zp, t3, t1, t6);       // C + B

    cczp_sqr_ws(ws, zp, t1, t4);       // (Y2-Y1)^2
    cczp_sub_ws(ws, zp, t1, t1, t3);       // X3 = (Y2-Y1)^2 - (C+B)
    cczp_sub_ws(ws, zp, t2, t6, t1);       // B - X3
    cczp_mul_ws(ws, zp, t2, t4, t2);   // (Y2-Y1) * (B-X3)

    cczp_sub_ws(ws, zp, t2, t2, t7);       // Y3 = (Y2-Y1)*(B-X3) - Y1*(C-B)
    cczp_sqr_ws(ws, zp, t4, t5);       // F = (Y2+Y1)^2
    cczp_sub_ws(ws, zp, t3, t4, t3);       // X3' = F - (C+B)
    cczp_sub_ws(ws, zp, t4, t3, t6);       // X3' - B
    cczp_mul_ws(ws, zp, t4, t4, t5);   // (X3'-B) * (Y2+Y1)
    cczp_sub_ws(ws, zp, t4, t4, t7);       // Y3' = (X3'-B)*(Y2+Y1) - Y1*(C-B)

    ws->start=t5; // restore workspace starting point.
}


/*!
 @function   XYCZdblJac_ws
 @abstract   Point Doubling in Jacobian with Co-Z output

 @param      twoP      Output: X:Y Jacobian coordinate for 2P
 @param      P         Output: X:Y Jacobian coordinate for P'
 @param      p         Input: P in Jacobian coordinates
 @param      ws        Worskpace for internal computations
                       To be cleaned up by the caller.
 @result
            Given a point P and a curve cp,
            Compute 2P and P' where
            P' ~= P (same point in the equivalence class)
            2P and P' have the same Z coordinate
            Z coordinate omitted in output
 */
#define CCEC_XYCZdblJac_ws_WORKSPACE_N(n) (3*(n))
static void XYCZdblJac_ws(cc_ws_t ws,
                       ccec_const_cp_t cp,
                       cc_unit *twoP,
                       cc_unit *P,
                       ccec_const_projective_point_t p)
{
    cczp_const_decl(zp, ccec_cp_zp(cp));

    cc_size n=ccec_cp_n(cp);
    cc_unit *t1=&twoP[0],*t2=&twoP[n],
        *t3=&P[0],*t4=&P[n];
    cc_unit *t5=ws->start;
    cc_unit *t6=ws->start+n;
    cc_unit *t7=ws->start+2*n;
    ws->start+=3*n;
    cc_assert((ws->start)<=ws->end); // Check that provided workspace is sufficient;
    /*
    Cost (a=-3)     : 6S + 2M + 12add/sub
    Cost (generic)  : 6S + 3M + 10add/sub
     */

    cczp_sqr_ws(ws, zp, t7, ccec_const_point_x(p,cp));       //  X1^2 
    cczp_add_ws(ws, zp, t4, t7, t7);       //  2*X1^2
    cczp_add_ws(ws, zp, t7, t7, t4);       //  3*X1^2
    cczp_sqr_ws(ws, zp, t3, ccec_const_point_z(p,cp));       //  Z1^2 
    cczp_sqr_ws(ws, zp, t3, t3);       //  Z1^4 

#ifdef EC_CURVE_SUPPORT_ONLY_A_MINUS_3
    cczp_add_ws(ws, zp, t5, t3, t3);       //  2*Z1^4
    cczp_add_ws(ws, zp, t5, t5, t3);       //  3*Z1^4
    cczp_sub_ws(ws, zp, t7, t7, t5);       //  B = 3*X1^2 - 3.Z1^4
#else
    cczp_mul_ws(ws, zp, t5, ccec_cp_a(cp), t3);//  a.Z1^4 
    cczp_add_ws(ws, zp, t7, t7, t5);       //  B = 3*X1^2 + a.Z1^4
#endif
    cczp_sqr_ws(ws, zp, t4, ccec_const_point_y(p,cp));       //  Y1^2 
    cczp_add_ws(ws, zp, t4, t4, t4);       //  2Y1^2
    cczp_add_ws(ws, zp, t5, t4, t4);       //  4Y1^2
    cczp_mul_ws(ws, zp, t3, t5, ccec_const_point_x(p,cp));   //  A = 4Y1^2.X1 
    cczp_sqr_ws(ws, zp, t6, t7);       //  B^2 

    cczp_sub_ws(ws, zp, t6, t6, t3);       //  B^2 - A
    cczp_sub_ws(ws, zp, t1, t6, t3);       //  X2 = B^2 - 2.A
    cczp_sub_ws(ws, zp, t6, t3, t1);       //  A - X2

    cczp_mul_ws(ws, zp, t6, t6, t7);   //  (A - X2)*B 
    cczp_sqr_ws(ws, zp, t4, t4);       //  (2Y1^2)^2 
    cczp_add_ws(ws, zp, t4, t4, t4);       //  8.Y1^4 = Y1'
    cczp_sub_ws(ws, zp, t2, t6, t4);       //  Y2 = (A - X2)*B - 8.Y1^4

    ws->start=t5; // restore workspace starting point.
}

/*!
 @function   XYCZrecoverCoeffJac
 @abstract   Recover Z and lambdaX, lambdaY coefficients for the result point
    if b=0 => R1 - R0 = -P
    if b=1 => R1 - R0 = P

 @param      lambdaX    Output: Correcting coefficient for X
 @param      lambdaY    Output: Correcting coefficient for Y
 @param      Z          Output: Z coordinate
 @param      R0         Input: X:Y Jacobian coordinates for P
 @param      R1         Input: X:Y Jacobian coordinates for Q
 @param      b          Input: Last bit of the scalar
 @param       p          Input: input point to the scalar multiplication
 @param      ws         Worskpace for internal computations
                        To be cleaned up by the caller.
 @result
    {lambaX, lambdaY, Z} so that the result point is recovered from R0
    after the last iteration.
 */
#define CCEC_XYCZrecoverCoeffJac_WORKSPACE_N(n) (0)
static void XYCZrecoverCoeffJac(cc_ws_t ws,ccec_const_cp_t cp,
                                cc_unit *lambdaX, cc_unit *lambdaY,
                                cc_unit *Z,
                                const cc_unit *R0,
                                const cc_unit *R1,
                                int bit,
                                ccec_const_projective_point_t p) {
    cc_size n=ccec_cp_n(cp);
    cczp_const_decl(zp, ccec_cp_zp(cp));

    cc_unit *t1=lambdaX,*t2=lambdaY, *t3=Z;

    cczp_sub_ws(ws, zp, t3, R1, R0);// X1 - X0
    cczp_mul_ws(ws, zp, t3, cc_muxp(bit, &R1[n], &R0[n])  , t3);// Yb * (X1-X0)
    cczp_mul_ws(ws, zp, t3, ccec_const_point_x(p,cp), t3);// XP * Yb*(X1-X0)
    cczp_mul_ws(ws, zp, t3, ccec_const_point_z(p,cp), t3);// ZP * XP*Yb*(X1-X0)

    cczp_mul_ws(ws, zp, t2, cc_muxp(bit, R1, R0)  , ccec_const_point_y(p,cp));// Xb*YP
    cczp_sqr_ws(ws, zp, t1, t2);       // (Xb*YP)^2
    cczp_mul_ws(ws, zp, t2, t2, t1);   // (Xb*YP)^3

     // {T1,T2,T3}
}

/* Conditionally swap the content of R0 and R1 points in constant time
 R0:R1 <- R1*k1 + R0*(k1-1)   */
static void cond_swap_points(cc_size n,
                      int ki,
                      cc_unit *R0,
                      cc_unit *R1) {
    cc_unit mask0,mask1;
    cc_assert(ki==0 || ki==1);
    mask0=((cc_unit)ki-(cc_unit)1);
    mask1=~mask0;
    // Copy involving the possible operands
    // Copy 2*n cc_units
    cc_size i=0;
    for (cc_size j=0;j<n;j++) {
        cc_unit u0 =R0[i];
        cc_unit u00=R0[i+1];
        cc_unit u1 =R1[i];
        cc_unit u11=R1[i+1];
        R0[i] = (  (mask0 & u0)
                 | (mask1 & u1));
        R0[i+1] = ((mask0 & u00)
                 | (mask1 & u11));
        R1[i++] = ((mask1 & u0)
                 | (mask0 & u1));
        R1[i++] = ((mask1 & u00)
                 | (mask0 & u11));
    }
}

// Requires the point s to have been generated by "ccec_projectify"
static int ccec_mult_edge_cases(cc_ws_t ws, ccec_const_cp_t cp,
                                ccec_projective_point_t r,
                                const cc_unit *d,
                                size_t dbitlen,
                                ccec_const_projective_point_t s) {
    int status;
    cc_size n=ccec_cp_n(cp);
    cczp_const_decl(zp, ccec_cp_zp(cp));
    cc_unit *dtmp=ws->start;      // dtmp[n+1]
    ws->start+=n+1;
    cc_assert((ws->start)<=ws->end); // Check that provided workspace is sufficient;
    ccn_sub1(n,dtmp,cczp_prime(ccec_cp_zq(cp)),1); // q-1

    // Scalar d must be <= q to
    // prevent intermediary results to be the point at infinity
    // corecrypto to take care to meet this requirement
    if ((dbitlen >= ccec_cp_order_bitlen(cp))
        && (ccn_cmp(n,d,cczp_prime(ccec_cp_zq(cp)))>0)) {
        // d > q
        status = -1; // error
    } else if (dbitlen < 1) {
        // d == 0
        ccn_clear(n, ccec_point_x(r, cp));
        ccn_clear(n, ccec_point_y(r, cp));
        ccn_clear(n, ccec_point_z(r, cp));
        status = 1; // done
    } else if (dbitlen == 1) {
        // If d=1 => r=s
        ccn_set(n, ccec_point_x(r, cp), ccec_const_point_x(s, cp));
        ccn_set(n, ccec_point_y(r, cp), ccec_const_point_y(s, cp));
        ccn_set(n, ccec_point_z(r, cp), ccec_const_point_z(s, cp));
        status = 1; // done
    } else if ((dbitlen >= ccec_cp_order_bitlen(cp))
               && (ccn_cmp(n,d, dtmp)==0)) {
        // If d=(q-1) => r=-s
        // Case not handled by Montgomery Ladder because R1-R0 = s.
        // On the last iteration r=R0 => R1 is equal to infinity which is not supported
        ccn_set(n, ccec_point_x(r, cp), ccec_const_point_x(s, cp));
        ccn_sub(n, ccec_point_y(r, cp), cczp_prime(zp), ccec_const_point_y(s, cp));
        ccn_set(n, ccec_point_z(r, cp), ccec_const_point_z(s, cp));
        status = 1; // done
    } else {
        status = 0;
    }
    ws->start-=n+1;
    return status;
}

/*!
 @function   ccec_mult_ws
 @abstract   Scalar multiplication on the curve cp

 @param      cp    Curve parameter
 @param      r     Output point d.s
 @param      d     Scalar of size ccec_cp_n(cp)+1 cc_units.
                    Required to verify d<=q where q is the order of the curve
 @param      s     Input point in Jacobian projective representation
 @param      rng   Random for randomization
 @param      ws         Worskpace for internal computations
            To be cleaned up by the caller.
 @result
 */

#define CCEC_MULT_WORKSPACE_SIZE(n) (14*(n)+2)
static int ccec_mult_ws(cc_ws_t ws,
                        ccec_const_cp_t cp,
                        ccec_projective_point_t r,
                        const cc_unit *d,
                        size_t dbitlen,
                        ccec_const_projective_point_t s) {

    cczp_const_decl(zp, ccec_cp_zp(cp));
    cc_size n=ccec_cp_n(cp);

    int status = ccec_mult_edge_cases(ws,cp,r,d,dbitlen,s);
    if (status>0) {
        return 0;
    }

    cc_unit *R0=ws->start;          // R0 and R1 are full points:
    cc_unit *R1=ws->start+2*n;      // X in [0..n-1] and Y in [n..2n-1]
    ws->start+=4*n;
    cc_assert((ws->start)<=ws->end); // Check that provided workspace is sufficient;

    // Core of the EC scalar multiplication
    int dbit; // Bit of d at index i
    XYCZdblJac_ws(ws,cp,R1,R0,s);

    // Main loop
    // Assumes that MSB is set: d_dbitlen-1 is == 1
    // This algo does not read it to verify it is indeed one.
    for (size_t i = dbitlen - 2; i>0; --i) {
        dbit=(int)ccn_bit(d, i);
        // Use buffer copy instead of pointer handling to prevent cache attacks
        cond_swap_points(n,dbit,R0,R1);
        XYCZaddC_ws(ws,cp,R0,R1);
        XYCZadd_ws(ws,cp,R0,R1);
        cond_swap_points(n,dbit,R0,R1);
        // Per Montgomery Ladder:
        // Invariably, R1 - R0 = P at this point of the loop
    }

    // Last iteration
    dbit=(int)ccn_bit(d, 0);

    cond_swap_points(n,dbit,R0,R1);
    XYCZaddC_ws(ws,cp,R0,R1);
    cond_swap_points(n,dbit,R0,R1);

    // If d0 =      0           1
    //          R1-R0=-P     R1-R0=P
    // Therefore we can reconstruct the Z coordinate
    // To save an inversion and keep the result in Jacobian projective coordinates,
    //  we compute coefficient for X and Y.
    XYCZrecoverCoeffJac(ws,cp,
                        ccec_point_x(r, cp),
                        ccec_point_y(r, cp),
                        ccec_point_z(r, cp),
                        R1,R0,
                        dbit,
                        s);
    cond_swap_points(n,dbit,R0,R1);
    XYCZadd_ws(ws,cp,R0,R1);
    cond_swap_points(n,dbit,R0,R1);
    
    // Apply coefficients to get Z
    cczp_mul_ws(ws, zp, ccec_point_x(r, cp), ccec_point_x(r, cp), &R0[0]); // X0 * lambdaX
    cczp_mul_ws(ws, zp, ccec_point_y(r, cp), ccec_point_y(r, cp), &R0[n]); // Y0 * lambdaY

#if CCEC_MULT_DEBUG
    ccn_lprint(n, "Result X:", ccec_point_x(r, cp));
    ccn_lprint(n, "Result Y:", ccec_point_y(r, cp));
    ccn_lprint(n, "Result Z:", ccec_point_z(r, cp));
#endif
    ws->start-=4*n;

    return 0;
}

#if 0
int ccec_mult(ccec_const_cp_t cp, ccec_projective_point_t r, const cc_unit *d,
              ccec_const_projective_point_t s,
              CC_UNUSED struct ccrng_state *rng) {
    int status=-1;
    cc_size n=ccec_cp_n(cp);
    size_t dbitlen=ccn_bitlen(n,d);
    CC_DECL_WORKSPACE_OR_FAIL(ws,CCEC_MULT_WORKSPACE_SIZE(n));

    // Manage edge cases
    status = ccec_mult_edge_cases(ws,cp,r,d,dbitlen,s);
    if (status>0) {
        status=0;      // done
        goto errOut;
    } else if (status < 0) {
        goto errOut; // error
    }

    // Make sure to process a constant number of bits
    // This addition has a carry with (2^32-1)/2^32) for P-256, higher for other NIST curves
    cc_unit *dtmp=ws->start;      // dtmp[n+1]
    ws->start+=n+1;
    cc_assert((ws->start)<=ws->end); // Check that provided workspace is sufficient;
    dtmp[n]=ccn_add(n,dtmp,d,cczp_prime(ccec_cp_zq(cp)));
    dbitlen=ccn_bitlen(n+1,dtmp);

    // Do the computation
    status=ccec_mult_ws(ws,cp,r,dtmp,dbitlen,s);
    ws->start-=n+1;

errOut:
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return status;
}
#endif

// Requires the point s to have been generated by "ccec_projectify"
int ccec_mult(ccec_const_cp_t cp, ccec_projective_point_t R, const cc_unit *d,
              ccec_const_projective_point_t S,
              CC_UNUSED struct ccrng_state *rng) {
    int status;
    cc_size n=ccec_cp_n(cp);
    size_t dbitlen=ccn_bitlen(n,d);

    CC_DECL_WORKSPACE_OR_FAIL(ws,CCEC_MULT_WORKSPACE_SIZE(n));
    ccec_projective_point *Q = (ccec_projective_point *)(ws->start);
    cc_unit *dtmp1=ws->start;      // dtmp1[n+1], ok to overlap with Q
    cc_unit *dtmp2=ws->start+n+1;  // dtmp2[n+1], ok to overlap with Q
    ws->start+=(ccec_point_size_n(cp))+2;
    cc_assert((ws->start)<=ws->end); // Check that provided workspace is sufficient;
    cc_assert(ccec_point_size_n(cp)>=2*n);

    // Manage edge cases
    status = ccec_mult_edge_cases(ws,cp,R,d,dbitlen,S);
    cc_require(status>=0,errOut); // error
    if (status>0) {
        status=0;      // done
        goto errOut;
    }

    // Scalar splitting
    // (d + q - 2*SCA_MASK_MSBIT) to avoid leaking the bit size of scalars
    size_t q_bitlen=ccec_cp_order_bitlen(cp);
    ccn_zero(n,dtmp2);
    ccn_set_bit(dtmp2,SCA_MASK_BITSIZE, 1);
    ccn_sub(n,dtmp1,cczp_prime(ccec_cp_zq(cp)),dtmp2);  // q - 2*SCA_MASK_MSBIT, no carry
    dtmp2[n]=ccn_add(n,dtmp2,dtmp1,d); // q + d - 2*SCA_MASK_MSBIT
    dtmp1[n]=dtmp2[n]+ccn_add(n,dtmp1,dtmp2,cczp_prime(ccec_cp_zq(cp))); // 2*q + d - 2*SCA_MASK_MSBIT

    // Choose either dtmp1 or dtmp2 to have the desired bitsize
    ccn_cond_swap(n+1, (int)ccn_bit(dtmp2,q_bitlen), dtmp2, dtmp1);
    cc_assert(ccn_bitlen(n+1,dtmp1)==ccec_cp_order_bitlen(cp)+1);

    // Now the mask
    cc_unit mask=1;
    cc_unit b=0;
    cc_assert(SCA_MASK_N==1);
#if CCEC_MASKING
    if (rng) ccn_random_bits(SCA_MASK_BITSIZE, &mask, rng);
#endif
    mask |= SCA_MASK_MSBIT;


    // (d + q - 2*SCA_MASK_MSBIT) = a.mask + b
    // => a.mask + (b+2*SCA_MASK_MSBIT) = d + q
    status=ccn_div_euclid_ws(ws,n+1, dtmp1, SCA_MASK_N, &b, n+1, dtmp1, SCA_MASK_N, &mask);
    cc_require(status==0,errOut);

    // a.S
    dbitlen=ccn_bitlen(n+1,dtmp1);
    status=ccec_mult_ws(ws,cp,Q,dtmp1,dbitlen,S);
    cc_require(status==0,errOut);

    // mask.a.S
    dbitlen=SCA_MASK_BITSIZE;
    status=ccec_mult_ws(ws,cp,R,&mask,dbitlen,Q);
    cc_require(status==0,errOut);

    // b.S
    dbitlen=SCA_MASK_BITSIZE+1; // equivalent to b+(2*SCA_MASK_MSBIT)
    status=ccec_mult_ws(ws,cp,Q,&b,dbitlen,S);
    cc_require(status==0,errOut);

    // mask.a.S + b.S
    ccec_add_ws(ws,cp,R,R,Q,0); // If either point is infinity, result is infinity


    status = 0;
errOut:
    ws->start=dtmp1;
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    return status;
}




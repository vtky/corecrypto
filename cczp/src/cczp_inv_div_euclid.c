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
#include <corecrypto/cc.h>
#include <corecrypto/ccn.h>
#include "cc_debug.h"

#include "cczp_inv.h"

// this is a specific version of ccn_div_euclid(), hence ccn_div_euclid_sp(),
// to be used specifically in cczp_inv() becuse the current ccn_div_euclid()
// is too slow. This function can be removed if ccn_div_euclid() provides
// satisfactory performance for all sizes of operands.

#define BASE (((cc_dunit)1)<<CCN_UNIT_BITS)
#define HALF_BASE (((cc_unit)1)<<(CCN_UNIT_BITS/2))
#define CCN_UNIT_HALF_BITS (CCN_UNIT_BITS/2)
#define CCN_UNIT_LO_MASK (CCN_UNIT_MASK>>CCN_UNIT_HALF_BITS)

#if (CCN_IOS && (CCN_UNIT_SIZE==8))  || !CCN_UINT128_SUPPORT_FOR_64BIT_ARCH

// xxx0 / xx
CC_INLINE cc_unit divmod32(cc_unit *r, cc_dunit a, cc_unit d)
{
    cc_unit ah = hi(a);
    cc_unit dh = d>>CCN_UNIT_HALF_BITS;
    cc_assert(dh!=0);

    cc_unit q = ah/dh;
    if(q>= HALF_BASE)
        q = HALF_BASE-1;

#if CCN_UINT128_SUPPORT_FOR_64BIT_ARCH
    cc_dint rr = (cc_dint)(a>>CCN_UNIT_HALF_BITS) - (cc_dint)q*d; //-q*d does not not overflow
    while(rr<0){
        rr+=d;
        q--;
    }
#else
    cc_dunit rr = a;
    shr_128(&rr, CCN_UNIT_HALF_BITS);
    cc_dunit qd = mul_128(q, d);
    cc_int cry = (cc_int)sub_128(&rr, &qd);
    cc_assert((cry!=0 && (cc_int)rr.h<0) || (cry==0&&(cc_int)rr.h>=0));
    (void) cry;
    while((cc_int)rr.h <0){
        add1_128(&rr, d);
        q--;
    }
#endif
    
    *r  = lo(rr);
    return  q; //this is half of cc_unit actually
}

// xxxx / xx
CC_INLINE cc_unit divmod42(cc_unit *r, cc_dunit a, cc_unit d)
{
    cc_assert(d!=0);

    cc_unit q1 = divmod32(r, a, d);
#if CCN_UINT128_SUPPORT_FOR_64BIT_ARCH
    a = (((cc_dunit)(*r))<<CCN_UNIT_HALF_BITS)|(lo(a)& CCN_UNIT_LO_MASK);
    a <<= CCN_UNIT_HALF_BITS;
#else
    cc_unit t = a.l & CCN_UNIT_LO_MASK;
    a = *(cc_dunit *)r;
    shl_128(&a, CCN_UNIT_HALF_BITS);
    a.l |= t;
    shl_128(&a, CCN_UNIT_HALF_BITS);
#endif
    cc_unit q0 = divmod32(r, a, d);
    cc_unit q  = (q1<<CCN_UNIT_HALF_BITS)|q0;

    return q;
}

#define UNIT_MSBIT_MASK  (CC_ONE<<(CCN_UNIT_BITS-1))
#define DUNIT_MSBIT_MASK (((cc_dunit)1)<<(2*CCN_UNIT_BITS-1))
CC_INLINE cc_dunit div42(cc_dunit a, cc_unit d)
{
    cc_unit  r;
    cc_dunit qq1;

#if CCN_UINT128_SUPPORT_FOR_64BIT_ARCH
    if(hi(a)>=d){
        a  = hl(hi(a)-d, lo(a));
        qq1 = (((cc_dunit)1)<<CCN_UNIT_BITS);
    }else{
        qq1 = 0;
    }

    cc_unit q0 = divmod42(&r, a, d);
    cc_dunit qq = qq1|q0;
#else
    if(hi(a)>=d){
        a  = hl(hi(a)-d, lo(a));
        qq1.l=0; qq1.h=1;
    }else{
        qq1.l = qq1.h = 0;
    }
    
    cc_unit q0 = divmod42(&r, a, d);
    cc_dunit qq; qq.h=qq1.h; qq.l=qq1.l|q0;
#endif
    return qq;
}

#else
CC_INLINE cc_dunit div42(cc_dunit a, cc_unit d)
{
    cc_assert(d!=0);
    return a/d;
}
#endif

//compute the quotient
static cc_unit comp_q(cc_size n, const cc_unit *a, const cc_unit *d)
{
    cc_unit cnt = count_leading_zeros(d[n-1]);
    cc_dunit qq;

#if CCN_UINT128_SUPPORT_FOR_64BIT_ARCH
    if(cnt==0 || n==1){
        qq = a[n-1]/d[n-1];
    }
    else{
        qq = div42(hl(a[n-1], a[n-2]), hi(hl(d[n-1], d[n-2])<<cnt));
        qq= qq>>(CCN_UNIT_BITS-cnt);
        if(qq>=BASE)
            qq = BASE-1;
    }
#else
    if(cnt==0 || n==1){
        qq.l = a[n-1]/d[n-1];
        qq.h=0;
    }else{
        cc_dunit t = hl(d[n-1], d[n-2]);
        shl_128(&t, cnt);
        qq = div42(hl(a[n-1], a[n-2]), t.h);
        shr_128(&qq, CCN_UNIT_BITS-cnt);
        if(qq.h>0)
            qq.h=0, qq.l = ~0;
    }
#endif

    return lo(qq);
}

//division when a and d have the same number of digits n, with no leading zeros.
cc_unit ccn_div_equal_size(cc_size n, cc_unit *r, const cc_unit *a, const cc_unit *d)
{
    cc_assert(ccn_n(n, d)==ccn_n(n, a));

    cc_unit q = comp_q(n, a, d);

    //It would be more efficient if mul() and sub() were lumped
    //qd = q * d
    cc_unit qd[n+1], r1[n];//vla
    qd[n]=ccn_mul1(n, qd, d, q);

    //a-q*d
    int b=-(int)(qd[n]+ccn_sub(n, r1, a, qd));

    //add back if q too large
    cc_unit *rx[2] =  {r1, qd};
    int good_one=0;

    for(int i=0; i<2; i++){
        int  b2= b+(int)ccn_add(n, rx[1^good_one], rx[good_one], d);
        /*
         if(b!=0){
         good_one=!good_one;
         q--;
         b=b2;
         }*/
        int  cond = b!=0;
        good_one = cond ^ good_one;
        q -= cond;
        b = cond & b2;
    }

    ccn_set(n, r, rx[good_one]);
    return q;
}

// a specific version of ccn_div_euclid()
int ccn_div_euclid_sp(cc_size n, cc_unit *q, cc_unit *r, const cc_unit *a, const cc_unit *d)
{
    cc_assert(ccn_cmp(n, a, d)>0);

    //removing leading zeros for performance
    cc_size nd = ccn_n(n, d);
    cc_size na = ccn_n(n, a);

    if(nd==0)
        return -1;

    //divide by one works but it is slow
    if(nd==1 && d[0]==1){//instead of ccn_is_one(nd, d)
        ccn_set(n, q, a);
        ccn_seti(n, r, 0);
        return 0;
    }

    int rc;
    if(na==nd){
        cc_unit r1[n];//vla
        ccn_zero(n, q);
        q[0] = ccn_div_equal_size(na , r1, a, d); //expects a>d
        ccn_setn(n, r, na, r1);
        rc = (q[0] >=1)? 0:-1; //since a>b, we must have q>=1
    } else {
        rc = ccn_div_euclid(n, q, n, r, na, a, nd, d); //expects a>d
    }
    
    return rc;
}

//------------------------------------------------------------------------------
#if  !CCN_UINT128_SUPPORT_FOR_64BIT_ARCH

#if defined(_WIN64) && defined(_WIN32) && !defined(__clang__)
#include <Windows.h>

cc_dunit mul_128(cc_unit a, cc_unit b)
{
	cc_assert(sizeof(cc_unit) == sizeof(uint64_t));
    cc_dunit r;

	r.l = UnsignedMultiply128(a, b, &r.h);
    return r;
}

#else
cc_dunit mul_128(cc_unit a, cc_unit b)
{
    cc_dunit r;
    //ccn_mul(1, (cc_unit*)&r, &a, &b);

    uint32_t a0 = (uint32_t)a;
    uint32_t a1 = a>>32;
    uint32_t b0 = (uint32_t)b;
    uint32_t b1 = b>>32;
    
    uint64_t a0b0 = (uint64_t)a0*b0;
    uint64_t a0b1 = (uint64_t)a0*b1;
    uint64_t a1b0 = (uint64_t)a1*b0;
    uint64_t a1b1 = (uint64_t)a1*b1;
    
    a0b1 += (uint32_t)(a0b0>>32);
    a0b1 += (uint32_t)a1b0;
    
    r.h = a1b1 + (uint32_t)(a1b0>>32) + (uint32_t)(a0b1>>32);
    r.l = a0b1<<32 | (a0b0&0xFFFFffff);
    
    return r;
}
#endif

cc_unit sub_128(cc_dunit *r, cc_dunit *b)
{
    return ccn_sub(2, (cc_unit*)r, (cc_unit*)r, (cc_unit*)b);
}

cc_unit add1_128(cc_dunit *r, cc_unit b)
{
    return ccn_add1(2, (cc_unit*)r, (const cc_unit*)r, b);
}

cc_unit shr_128(cc_dunit *r, cc_unit cnt){
    return ccn_shift_right(2, (cc_unit *)r, (const cc_unit *)r, cnt);
}

cc_unit shl_128(cc_dunit *r, cc_unit cnt){
    return ccn_shift_left(2, (cc_unit *)r, (const cc_unit *)r, cnt);
}

//#define next(z, q) z##2 = (cc_int)(z##0-(cc_dint)q*z##1)
cc_int next_xgcd(cc_int z0, cc_int z1, cc_int q){

    cc_dunit qz1 = mul_128(q, z1);
    cc_dunit zz0; zz0.l = z0; zz0.h = 0;

    sub_128(&zz0, &qz1);
    return zz0.l;
}

#endif



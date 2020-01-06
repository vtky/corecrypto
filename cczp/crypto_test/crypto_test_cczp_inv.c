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

#include <corecrypto/ccrng.h>
#include <corecrypto/cczp.h>
#include "cc_debug.h"
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccn_priv.h>
#include "crypto_test_cczp_inv.h"
#include "testmore.h"
#include <limits.h>

static int is_hex(int ch){
    return (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f');
}

static size_t nofh(const char *h){
    cc_size n = 0;

    for(cc_size i=0; h[i]!=0; i++){
        if (is_hex(h[i]))
            n++;
    }
    return cc_ceiling(n, 2*CCN_UNIT_SIZE);
}

static unsigned to_int(int ch)
{
    unsigned n;

    if (ch >= '0' && ch <= '9')
        n = (ch - '0');
    else if (ch >= 'A' && ch <= 'F')
        n = (ch - 'A' + 10);
    else if (ch >= 'a' && ch <= 'f')
        n = (ch - 'a' + 10);
    else n = 0;

    return n;
}

static size_t h2u (size_t len, const char *s, cc_unit *u)
{
    const char *r  = s+len-1;
    cc_unit x, rv = 0;
    cc_size cnt = 0;
    int ch;

    while (len!=0 && cnt<CCN_UNIT_SIZE*2) {
        ch = *r--;
        len --;

        if(!is_hex(ch))
            continue;

        x = to_int(ch);
        rv += x<<(cnt*4);
        cnt++;
    }

    *u =rv;
    return len;
}

#define FULL_LEN (CCN_UNIT_SIZE*2)
static size_t h2bi(const char *h, size_t n, cc_unit *bi)
{
    size_t len = strlen(h);
    size_t i=0;

    while (len) {
        len = h2u(len, h, &bi[i++]);
    }

    //fill in the rest with zeros
    while (i<n)
        bi[i++]=0;
    return i;
}

//extended version of cczp_mul() that accepts leading zero cc_unit's on p
//only for test purpose and very slow
static int cczp_mul_ex(cczp_const_t zp, cc_unit *t, const cc_unit *x, const cc_unit *y)
{
    const cc_unit *p=cczp_prime(zp);
    cc_unit  n = cczp_n(zp);

    cc_unit r2n[2*n];
    ccn_mul(n, r2n, x, y);
    ccn_mod(n, t, 2*n, r2n, n, p);
    int rc = ccn_is_one(n, t)?0:-1;

    return rc;
}

//computes gcd. This function is meant for test purpose and is not efficient. Don't use it in corecrypto.
static int is_coprime(cc_size n, cc_unit *_u, cc_unit *_v)
{
    cc_unit r1[n], u1[n], v1[n];
    cc_unit *r=r1, *v=v1, *u=u1, *t;
    ccn_set(n, v, _v);
    ccn_set(n, u, _u);

    if (ccn_cmp(n, u, v)<0)
        CC_SWAP(u, v);

    while(!ccn_is_zero(n, v)){
        n = ccn_n(n, u); //we know u>v
        ccn_mod(n, r, n, u, n, v);
        t = u;
        u = v;
        v = r;
        r = t;
    }

    return ccn_is_one(n, u)==1?1:0;
}

struct cczp_inv_kat {
    char *a;
    char *d;
    char *ai;
}cczp_inv_kat[] = {
    {"00000000000000000000000E", "000000000000003", "2"},
    {"10000000000000000000000D", "000000000000000000000000000000000000000000000003", "2"},
    {"00000000000000000000000E", "000000000000000000000003", "2"},
    {"000000000000000000F", "1000000000000000000000000000000000000000000000000000000000000000000003", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbe"},
    {NULL, NULL, NULL}
};
static int test_cczp_inv_kat(struct cczp_inv_kat *kat)
{
    int rc=0;

    cc_size n = CC_MAX(nofh(kat->a), nofh(kat->d));
    cc_unit a[n+1], d[n+1], ai[n+1];
    h2bi(kat->a, n, a);
    h2bi(kat->d, n, d);
    h2bi(kat->ai, n, ai);

    cczp_decl_n(n, zp);
    CCZP_N(zp) = n;
    ccn_set(n, CCZP_PRIME(zp), d);

    rc=cczp_inv(zp, a, a); ok(rc==0, "cczp_inv()");
    rc = ccn_cmp(n, ai, ai); ok(rc==0, "test_cczp_inv_kat()");

    return 0;
}


// corner cases: for both p even and odd
int test_cczp_inv_corner_cases(void)
{
    const cc_size nbits=4096+3;
    const cc_size n = ccn_nof(nbits);
    cc_unit a[n], ai[n];
    int rc;

    cczp_decl_n(n, zp);
    cc_unit *p=CCZP_PRIME(zp);

    //////fix p
    rc=ccn_random(n, p, global_test_rng); ok(rc==0, "ccn_random()");
    CCZP_N(zp) = ccn_n(n, p);
    if (p[n-1]==0) { //make sure zp size is at exactly n n
        p[n-1]=1;
    }
    cczp_init(zp);

    // inv of 0
    ccn_seti(n, a, 0);
    rc=cczp_inv(zp, ai, a); ok(rc<0, "inverse of zero");

    //inv of 1
    ccn_seti(n, a, 1);
    rc=cczp_inv(zp, ai, a); ok(rc==0, "generating inverse of one");
    cczp_mul(zp, ai, ai, a); ok(ccn_is_one(n, ai), "checking inverse of one");

    //a > p;
    ccn_set(n, a, p);
    ccn_add1(n, a, a, 5);
    int expected_rc = is_coprime(n, p, a)?0:-2;
    rc=cczp_inv(zp, ai, a); ok(rc==expected_rc, "generating inverse of a>p");
    if(expected_rc==0){
        cczp_mul_ex(zp, a, ai, a); ok(ccn_is_one(n, a), "checking inverse of a>p");
    }else
        ok(1, "");

    //a = p/32
    p[0] &= ~0x1F;
    ccn_set(n, a, p);
    ccn_shift_right(n, a, a, 5);
    rc=cczp_inv(zp, ai, a); ok(rc<0, "inverse of a=p/32");

    //a=p
    ccn_set(n, a, p);
    rc=cczp_inv(zp, ai, a); ok(rc<0, "a and p are equal");

    //////touch both a and p
    rc=ccn_random(n, a, global_test_rng); if(rc!=0) return(-1);
    p[0] &= ~1; a[0] &= ~1;
    rc=cczp_inv(zp, ai, a); ok(rc<0, "a and p are both even");

    //////fix a
    rc=ccn_random(n, a, global_test_rng); if(rc!=0) return(-1);

    //p is zero
    ccn_seti(n, p, 0);
    rc=cczp_inv(zp, ai, a); ok(rc<0, "inverse for p=0");

    //p is one
    ccn_seti(n, p, 1);
    rc=cczp_inv(zp, ai, a); ok(rc<0, "inverse for p=1");

    //p is 2^CCN_UNIT_BITS-1 and a>p
    cc_unit t[n];
    ccn_seti(n, p, -1);
    expected_rc = is_coprime(n, p, a)?0:-2;
    rc=cczp_inv(zp, ai, a); ok(rc==expected_rc, "inverse for p=2^CCN_UNIT_BITS-1");
    if(expected_rc==0){
        cczp_mul_ex(zp, t, ai, a);
        ok(ccn_is_one(n, t), "checking inverse of p=2^CCN_UNIT_BITS-1");
    }else
        ok(1, "");

    //p is 2^n-1
    memset(p, -1, n*sizeof(*p));
    expected_rc = is_coprime(n, p, a)?0:-2;
    rc=cczp_inv(zp, ai, a); ok(rc==expected_rc, "inverse for p=2^n-1");
    if(expected_rc==0){
        cczp_mul_ex(zp, a, ai, a); ok(ccn_is_one(n, a), "checking inverse of p=2^n-1");
    }else
        ok(1, "");

    return 0;
}

int test_cczp_inv(const cc_size nbits)
{
    int ntests=CCN_UNIT_SIZE;
    int st, rc, i, expected_rc;
    const cc_size n = ccn_nof(nbits);
    cc_unit a[n], ai[n], ai_slow[n], r[n];

    cczp_decl_n(n, zp);
    CCZP_N(zp) = n;
    cc_unit *p = CCZP_PRIME(zp);

    for(i=0; i< ntests; i++){
        st=ccn_random(n, a,global_test_rng); if(st!=0) return (-1);
        st=ccn_random(n, p,global_test_rng); if(st!=0) return(-1);

        expected_rc = is_coprime(n, p, a)?0:-2;

        rc = cczp_inv(zp, ai, a); ok(rc==expected_rc, "cczp_inv()");
        if (expected_rc==0) {
            cczp_init(zp);
            cczp_modn(zp, a, n, a);
            cczp_mul(zp, r, ai, a);
            rc=ccn_is_one(n, r); ok(rc==1, "cczp_inv() returned wrong result");
            if(rc!=1){//this is a bad error
                cczp_inv_slow(zp, ai_slow, a);

                cc_printf("\n-cczp_inv() failed----");
                cc_printf("\na="); ccn_print(n, a);
                cc_printf("\nai="); ccn_print(n, ai);
                cc_printf("\nai_slow="); ccn_print(n, ai_slow);
                cc_printf("\np="); ccn_print(n, cczp_prime(zp));
                return -1;
            }
        }else{ //there is no inverse, no further processing is required
            ok(1, "");
        }

    }
    return 0;
}

//vectors for 32-bit and 64-bit must be different
struct div_test_vect {
    char *a;
    char *d;
}div_test_vect[] = {
#include "../test_vectors/div_test_vect32.inc"
#if CN_UNIT_SIZE==8
#include "../test_vectors/div_test_vect64.inc"
#endif
{NULL, NULL}

};

static int test_ccn_div_equal_size(const char *as, const char *ds)
{
    int rc=0;

    cc_size n = CC_MAX(nofh(as), nofh(ds));
    cc_unit a[n], d[n], r1[n], r2[n], q2[n];
    h2bi(as, n, a);
    h2bi(ds, n, d);

    cc_unit na = ccn_n(n, a);
    cc_unit nd = ccn_n(n, d);
    if (na!=nd) {
        ccn_lprint(na, "\na=", a);
        ccn_lprint(nd, "d=", d);
    }
    ok_or_fail(na==nd, "ccn_div_equal_size() bad test vector");

    n = na;
    cc_unit q1 = ccn_div_equal_size(n, r1, a, d);
    ccn_div_euclid(n, q2, n, r2, n, a, n, d);
    rc = ccn_cmp(n, r1, r2); ok(rc==0, "ccn_div_equal_size() remainder");
    is(q1,q2[0], "ccn_div_equal_size() quotient");

    return 0;
}

int test_cczp_inv_kats(void) {

    for(int i=0; div_test_vect[i].a!=NULL; i++)
        test_ccn_div_equal_size(div_test_vect[i].a, div_test_vect[i].d);

    for (int i=0; cczp_inv_kat[i].a!=NULL; i++)
        test_cczp_inv_kat(&cczp_inv_kat[i]);

    return 0;
}


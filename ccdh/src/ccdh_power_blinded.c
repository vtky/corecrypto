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

#include <corecrypto/ccdh.h>
#include <corecrypto/ccdh_priv.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/cczp_priv.h>
#include <corecrypto/cc_macros.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/cc_memory.h>

#define SCA_MASK_BITSIZE 32
#define SCA_MASK_MSBIT (((cc_unit)1)<<(SCA_MASK_BITSIZE-1))
#define SCA_MASK_MASK  ((SCA_MASK_MSBIT-1) <<1 | 1)    /* required to be a power of 2 */
#define SCA_MASK_N ccn_nof(SCA_MASK_BITSIZE)
#define NB_MASK 3*SCA_MASK_N   // base, exponent, modulus

int ccdh_power_blinded(struct ccrng_state *blinding_rng,
               ccdh_const_gp_t gp,
               cc_unit *r, const cc_unit *s, const cc_unit *e) {
    int status;

    // Allocate a ZP which will be used to extend p for randomization
    cc_size np=ccdh_gp_n(gp);
    cc_size nu=np+SCA_MASK_N;
    cczp_decl_n(nu,zu_masked);

    // (s<p) requirement enforced during public key verification, here for debug only
    cc_assert(ccn_cmp(np, s, ccdh_gp_prime(gp))<0);

    // Allocate working memory
    CC_DECL_WORKSPACE_OR_FAIL(ws, 3*nu+SCA_MASK_N+CCZP_POWER_SSMA_WORKSPACE_N(nu));
    cc_unit *e0=ws->start;                      // [SCA_MASK_N];
    cc_unit *e1=ws->start+SCA_MASK_N;           // [nu];
    cc_unit *s_star=ws->start + nu + SCA_MASK_N;// [nu];
    cc_unit *tmp=ws->start + 2*nu + SCA_MASK_N; // [nu];
    ws->start += 3*nu+SCA_MASK_N;

    // Random for masking. One call to reduce latency
    cc_unit rnd[SCA_MASK_N*NB_MASK];
    cc_require((status=ccn_random(NB_MASK, rnd, blinding_rng))==0,errOut);

    /*
     Modulus blinding:   p_star = rnd[0]*p
     Exponent blinding:  e1 = e/rnd[1], e0 = e % rnd[1]
       such that (e1*rnd[1] + e0) == e
     Base blinding:      s_star = (x + rnd[2]*p) mod p_star
     */

    /* Modulus blinding:   p_star = rnd[0]*p */
    cc_assert(SCA_MASK_N==1); // because we use mul1 for masks
    CCZP_N(zu_masked)=nu;
    rnd[0] &= SCA_MASK_MASK; // truncate as needed
    rnd[0] |= (SCA_MASK_MSBIT|1); // Odd and big
    *(CCZP_PRIME(zu_masked)+np)=ccn_mul1(np,CCZP_PRIME(zu_masked),ccdh_gp_prime(gp),rnd[0]);
    cczp_init_ws(ws, zu_masked);

    /* Exponent blinding:  e1 = e/rnd[1], e0 = e % rnd[1] */
    rnd[1] &= SCA_MASK_MASK; // truncate as needed
    rnd[1] |= SCA_MASK_MSBIT; // non zero and big
    cc_require((status=ccn_div_euclid_ws(ws, nu, e1, SCA_MASK_N, e0, np, e, SCA_MASK_N, &rnd[1]))==0,errOut);

    /* Base blinding:      s_star = (x + rnd[2]*p) mod p_star */
    ccn_set(np,tmp,s);
    rnd[2] &= SCA_MASK_MASK; // truncate as needed
    tmp[np]=ccn_addmul1(np,tmp,ccdh_gp_prime(gp), rnd[2]);    /* tmp = rnd[2] * p */
    cc_require((status=cczp_modn_ws(ws, zu_masked,s_star,nu,tmp))==0,errOut);

#if 0 //CORECRYPTO_DEBUG
    ccn_lprint(np,"p     ", ccdh_gp_prime(gp));
    ccn_lprint(nu,"p_star", CCZP_PRIME(zu_masked));
    ccn_lprint(np,"e     ", e);
    ccn_lprint(SCA_MASK_N,"rnd[0]   ", &rnd[0]);
    ccn_lprint(SCA_MASK_N,"rnd[1]   ", &rnd[1]);
    ccn_lprint(SCA_MASK_N,"rnd[2]   ", &rnd[2]);
    ccn_lprint(np,"s     ", s);
    ccn_lprint(nu,"s_star", s_star);

    ccn_mul1(nu,tmp,e1,rnd[1]);
    ccn_add1(nu,tmp,tmp,*e0);
    cc_assert(ccn_cmp(np,tmp,e)==0);
#endif

    /* Actual computations */
    cc_require((status=cczp_power_ssma_ws(ws,zu_masked, tmp, s_star, e1))==0,errOut);   /* s_star^e1 */
    ccn_setn(nu,e1,SCA_MASK_N,&rnd[1]);
    cc_require((status=cczp_power_ssma_ws(ws,zu_masked, tmp, tmp, e1))==0,errOut);   /* (s_star^e1)^rnd[1] */
    ccn_setn(nu,e1,SCA_MASK_N,e0);
    cc_require((status=cczp_power_ssma_ws(ws,zu_masked, s_star, s_star, e1))==0,errOut);/* s_star^e0 */
    cczp_mul_ws(ws, zu_masked, s_star, s_star, tmp); /* (s_star^e1)^rnd[1] * s_star^e0 = s_star^e */
    status=cczp_modn_ws(ws,ccdh_gp_zp(gp),r,nu,s_star);

errOut:
    ws->start=e0; // Reset to pointer value set at allocation time
    // Clear working buffers
    CC_CLEAR_AND_FREE_WORKSPACE(ws);
    cczp_clear_n(nu,zu_masked);
    return status;
}

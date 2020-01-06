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
#include "testmore.h"
#include "testbyteBuffer.h"
#include "testccnBuffer.h"

#include <corecrypto/ccec.h>
#include <corecrypto/ccec_priv.h>
#include <corecrypto/ccrng_test.h>
#include "crypto_test_ec.h"


static int verbose = 0;

const struct ccecdh_vector ccecdh_vectors[]=
{
#include "../test_vectors/ecdh.inc"
};

static int
ECDH_KATTesting(const struct ccecdh_vector *testvec) {
    int status;
    int rc=1;

    ccec_const_cp_t cp = testvec->curve();
    size_t keySize=ccec_cp_prime_bitlen(cp);
    ccec_full_ctx_decl_cp(cp, full_ec_key);
    ccec_pub_ctx_decl_cp(cp, pub_ec_key);

    byteBuffer QCAVSx = hexStringToBytes(testvec->QCAVSx);
    byteBuffer QCAVSy = hexStringToBytes(testvec->QCAVSy);
    byteBuffer dIUT   = hexStringToBytes(testvec->dIUT);
    byteBuffer QIUTx  = hexStringToBytes(testvec->QIUTx);
    byteBuffer QIUTy  = hexStringToBytes(testvec->QIUTy);
    byteBuffer ZIUT   = hexStringToBytes(testvec->ZIUT);
    int expected_status=testvec->status;

    uint8_t Z[ZIUT->len];
    size_t Z_len=sizeof(Z);
    memset(Z,0,sizeof(Z));

    is(ccec_make_priv(keySize,
                      QIUTx->len, QIUTx->bytes,
                      QIUTy->len, QIUTy->bytes,
                      dIUT->len,  dIUT->bytes,
                      full_ec_key),0,"Make priv");
    is(ccec_make_pub(keySize,
                     QCAVSx->len, QCAVSx->bytes,
                     QCAVSy->len, QCAVSy->bytes,
                     pub_ec_key),0,"Make pub");

    status=ccecdh_compute_shared_secret(full_ec_key, pub_ec_key, &Z_len, Z, global_test_rng);
    rc&=is(status,expected_status, "Return value as expected");
    if (expected_status==0) {
        rc&=is(Z_len,ZIUT->len,"Z length");
        rc&=ok_memcmp(Z, ZIUT->bytes, ZIUT->len, "Known answer test failure");
    } else {
        pass("ECDH"); // for the test counter
        pass("ECDH"); // for the test counter
    }
    free(QCAVSx);
    free(QCAVSy);
    free(dIUT);
    free(QIUTx);
    free(QIUTy);
    free(ZIUT);
    return rc;
}


static int
ECDH_negativeTesting(ccec_const_cp_t cp)
{
    size_t n=ccec_cp_n(cp);
    ccec_full_ctx_decl_cp(cp, full_key); ccec_ctx_init(cp, full_key);
    uint8_t out[ccec_ccn_size(cp)];
    size_t  out_len=sizeof(out);
    uint32_t status=0;
    uint32_t nb_test=0;
    int result=0;
    
    // Set a dummy private key
    ccn_seti(n, ccec_ctx_k(full_key), 2);

    /* 0) Sanity: valid arguments */
    ccn_set(n,ccec_ctx_x(full_key),ccec_const_point_x(ccec_cp_g(cp),cp));
    ccn_set(n,ccec_ctx_y(full_key),ccec_const_point_y(ccec_cp_g(cp),cp));
    ccn_seti(n, ccec_ctx_z(full_key), 1);
    ccec_pub_ctx_t pub_key = ccec_ctx_pub(full_key);

    if (ccec_validate_pub(pub_key) &&
        (ccecdh_compute_shared_secret(full_key,pub_key,&out_len, out,global_test_rng)==0))
    {
        status|=1<<nb_test;
    }
    nb_test++;
    
    /* 1) Set x to p */
    ccn_set(n,ccec_ctx_x(full_key),ccec_ctx_prime(full_key));
    ccn_set(n,ccec_ctx_y(full_key),ccec_const_point_y(ccec_cp_g(cp),cp));
    ccn_seti(n, ccec_ctx_z(full_key), 1);
    if (!ccec_validate_pub(pub_key) &&
        (ccecdh_compute_shared_secret(full_key, pub_key,&out_len, out,global_test_rng)!=0))
    {
        status|=1<<nb_test;
    }
    nb_test++;
    
    /* 2) Set y to p */
    ccn_set(n,ccec_ctx_x(full_key),ccec_const_point_x(ccec_cp_g(cp),cp));
    ccn_set(n,ccec_ctx_y(full_key),ccec_ctx_prime(full_key));
    ccn_seti(n, ccec_ctx_z(full_key), 1);
    if (!ccec_validate_pub(pub_key) &&
         (ccecdh_compute_shared_secret(full_key, pub_key,&out_len, out,global_test_rng)!=0))
    {
        status|=1<<nb_test;
    }
    nb_test++;

    // The point (0,0) can't be on the curve with equation y^2=x^3-3x+b.
    if (ccn_is_zero(n,ccec_cp_b(cp)))
    {   // The point (1,1) can't be on the curve with equation y^2=x^3-3x+0.
        ccn_seti(n,ccec_ctx_x(full_key),1);
        ccn_seti(n,ccec_ctx_y(full_key),1);
    }
    else
    {   // The point (0,0) can't be on the curve with equation y^2=x^3-3x+b with b!=0
        ccn_zero(n,ccec_ctx_x(full_key));
        ccn_zero(n,ccec_ctx_y(full_key));
    }

    if (!ccec_validate_pub(pub_key) &&
        (ccecdh_compute_shared_secret(full_key, pub_key,&out_len, out,global_test_rng)!=0))
    {
        status|=1<<nb_test;
    }
    nb_test++;

    /* 4) Output is infinite point  */
    ccn_set(n,ccec_ctx_x(full_key),ccec_const_point_x(ccec_cp_g(cp),cp));
    ccn_set(n,ccec_ctx_y(full_key),ccec_const_point_y(ccec_cp_g(cp),cp));
    ccn_set(n,ccec_ctx_k(full_key),cczp_prime(ccec_cp_zq(cp)));

    if (ccecdh_compute_shared_secret(full_key, pub_key,&out_len, out,global_test_rng)!=0)
    {
        status|=1<<nb_test;
    }
    nb_test++;

    /* 5) Sanity: valid arguments */
    ccn_seti(n, ccec_ctx_k(full_key), 2);
    ccn_set(n,ccec_ctx_x(full_key),ccec_const_point_x(ccec_cp_g(cp),cp));
    ccn_set(n,ccec_ctx_y(full_key),ccec_const_point_y(ccec_cp_g(cp),cp));
    ccn_seti(n, ccec_ctx_z(full_key), 1);
    if (ccecdh_compute_shared_secret(full_key,pub_key,&out_len, out,global_test_rng)==0)
    {
        status|=1<<nb_test;
    }
    nb_test++;

    // 6) Set a zero scalar key
    ccn_zero(n, ccec_ctx_k(full_key));
    if (ccecdh_compute_shared_secret(full_key,pub_key,&out_len, out,global_test_rng)!=0)
    {
        status|=1<<nb_test;
    }
    nb_test++;

    // 7) Set a big scalar key
    ccn_set(ccec_cp_n(cp),ccec_ctx_k(full_key),cczp_prime(ccec_cp_zq(cp)));
    if (ccecdh_compute_shared_secret(full_key,pub_key,&out_len, out,global_test_rng)!=0)
    {
        status|=1<<nb_test;
    }
    nb_test++;

    /* Test aftermath */
    if ((nb_test==0) || (status!=((1<<nb_test)-1)))
    {
        result=0;
    }
    else
    {
        result=1; // Test is successful, Yeah!
    }

    return result;
}

int
ecdh_known_answer_tests(void) {
    int status=1;


    if(verbose) diag("ECDH Known Answer Tests");
    size_t i=0;
    while(ccecdh_vectors[i].curve!=NULL) {
        status&=ok(ECDH_KATTesting(&ccecdh_vectors[i]), "ECDH KAT Test failed: %d",i);
        i++;
    }

    return status;
}

int
ecdh_negative_tests(void) {
    int status=1;

    if(verbose) diag("ECDH Negative Tests");
    status&=ok(ECDH_negativeTesting(ccec_cp_192()), "ECDH Negative testing on 192 bit curve");
    status&=ok(ECDH_negativeTesting(ccec_cp_224()), "ECDH Negative testing on 224 bit curve");
    status&=ok(ECDH_negativeTesting(ccec_cp_256()), "ECDH Negative testing on 256 bit curve");
    status&=ok(ECDH_negativeTesting(ccec_cp_384()), "ECDH Negative testing on 384 bit curve");
    status&=ok(ECDH_negativeTesting(ccec_cp_521()), "ECDH Negative testing on 521 bit curve");

    return status;
}



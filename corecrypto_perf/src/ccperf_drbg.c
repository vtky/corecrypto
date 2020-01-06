/*
 * Copyright (c) 2017,2018 Apple Inc. All rights reserved.
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

#include <corecrypto/ccperf.h>
#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccaes.h>
#include <corecrypto/ccsha2.h>

static struct ccdrbg_nistctr_custom  custom_ctr; // DRBG - NIST CTR
static struct ccdrbg_nisthmac_custom custom_hmac; // DRBG - NIST HMAC

const char drbg_init_salt[] ="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 64bytes
const char drbg_init_nonce[]="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 32bytes
const char drbg_init_personalization[]="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 32bytes

static double perf_f_ccdrbg_hmac_sha256_reseed(size_t loops, size_t nbytes)
 {
     CC_UNUSED int status;
     uint8_t results[nbytes];
     double time;

     struct ccdrbg_info info;
     ccdrbg_factory_nisthmac(&info, &custom_hmac);
     struct ccdrbg_state *state = malloc(info.size);
     status = ccdrbg_init(&info, state,
         sizeof(drbg_init_salt), drbg_init_salt,
         sizeof(drbg_init_nonce), drbg_init_nonce,
         sizeof(drbg_init_personalization), drbg_init_personalization
         );
     cc_assert(status==0);
     perf_start();
     memset(results,'b',nbytes);
     do {
         status = ccdrbg_reseed(&info,state, nbytes, results,0,NULL);
         cc_assert(status==0);
     } while (--loops != 0);
     time=perf_seconds();
     free(state);
     return time;
 }

static double perf_f_ccdrbg_hmac_sha256_generate(size_t loops, size_t nbytes)
{
    CC_UNUSED int status;
    uint8_t results[nbytes];
    double time;

    struct ccdrbg_info info;
    ccdrbg_factory_nisthmac(&info, &custom_hmac);
    struct ccdrbg_state *state = malloc(info.size);
    status = ccdrbg_init(&info, state,
                         sizeof(drbg_init_salt), drbg_init_salt,
                         sizeof(drbg_init_nonce), drbg_init_nonce,
                         sizeof(drbg_init_personalization), drbg_init_personalization
                         );
    cc_assert(status==0);
    perf_start();
    do {
        status = ccdrbg_generate(&info,state, nbytes, results,0,NULL);
        cc_assert(status==0);
    } while (--loops != 0);
    time=perf_seconds();
    free(state);
    return time;
}
static double perf_f_ccdrbg_hmac_sha256_oneshot(size_t loops, size_t nbytes)
{
    CC_UNUSED int status;
    uint8_t results[nbytes];
    double time;

    struct ccdrbg_info info;
    ccdrbg_factory_nisthmac(&info, &custom_hmac);
    struct ccdrbg_state *state = malloc(info.size);
    perf_start();
    do {
        status = ccdrbg_init(&info, state,
                             sizeof(drbg_init_salt), drbg_init_salt,
                             sizeof(drbg_init_nonce), drbg_init_nonce,
                             sizeof(drbg_init_personalization), drbg_init_personalization
                             );
        cc_assert(status==0);
        status = ccdrbg_generate(&info,state, nbytes, results,0,NULL);
        cc_assert(status==0);
    } while (--loops != 0);
    time=perf_seconds();
    free(state);
    return time;
}


static double perf_f_ccdrbg_ctr_aes256_reseed(size_t loops, size_t nbytes)
{
    CC_UNUSED int status;
    uint8_t results[nbytes];
    double time;

    struct ccdrbg_info info;
    ccdrbg_factory_nistctr(&info, &custom_ctr);
    struct ccdrbg_state *state = malloc(info.size);
    status = ccdrbg_init(&info, state,
        sizeof(drbg_init_salt), drbg_init_salt,
        sizeof(drbg_init_nonce), drbg_init_nonce,
        sizeof(drbg_init_personalization), drbg_init_personalization
        );
    cc_assert(status==0);
    perf_start();
    memset(results,'b',nbytes);
    do {
        status = ccdrbg_reseed(&info,state, nbytes, results,0,NULL);
        cc_assert(status==0);
    } while (--loops != 0);
    time=perf_seconds();
    free(state);
    return time;
}


static double perf_f_ccdrbg_ctr_aes256_generate(size_t loops, size_t nbytes)
{
    CC_UNUSED int status;
    uint8_t results[nbytes];
    double time;

    struct ccdrbg_info info;
    ccdrbg_factory_nistctr(&info, &custom_ctr);
    struct ccdrbg_state *state = malloc(info.size);
    status = ccdrbg_init(&info, state,
                         sizeof(drbg_init_salt), drbg_init_salt,
                         sizeof(drbg_init_nonce), drbg_init_nonce,
                         sizeof(drbg_init_personalization), drbg_init_personalization
                         );
    cc_assert(status==0);
    perf_start();
    do {
        status = ccdrbg_generate(&info,state, nbytes, results,0,NULL);
        cc_assert(status==0);
    } while (--loops != 0);
    time=perf_seconds();
    free(state);
    return time;
}

static double perf_f_ccdrbg_ctr_aes256_oneshot(size_t loops, size_t nbytes)
{
    CC_UNUSED int status;
    uint8_t results[nbytes];
    double time;

    struct ccdrbg_info info;
    ccdrbg_factory_nistctr(&info, &custom_ctr);
    struct ccdrbg_state *state = malloc(info.size);
    perf_start();
    do {
        status = ccdrbg_init(&info, state,
                             sizeof(drbg_init_salt), drbg_init_salt,
                             sizeof(drbg_init_nonce), drbg_init_nonce,
                             sizeof(drbg_init_personalization), drbg_init_personalization
                             );
        cc_assert(status==0);
        status = ccdrbg_generate(&info,state, nbytes, results,0,NULL);
        cc_assert(status==0);
    } while (--loops != 0);
    time=perf_seconds();
    free(state);
    return time;
}

#define _TEST(_x) { .name = #_x, .func = perf_f_ ## _x}
static struct ccdrbg_perf_test {
    const char *name;
    double(*func)(size_t loops, cc_size nbytes);
} ccdrbg_perf_tests[] = {
    _TEST(ccdrbg_ctr_aes256_reseed),
    _TEST(ccdrbg_ctr_aes256_generate),
    _TEST(ccdrbg_ctr_aes256_oneshot),
    _TEST(ccdrbg_hmac_sha256_reseed),
    _TEST(ccdrbg_hmac_sha256_generate),
    _TEST(ccdrbg_hmac_sha256_oneshot),
};

static double perf_ccdrbg(size_t loops, size_t size, const void *arg)
{
    const struct ccdrbg_perf_test *test=arg;
    return test->func(loops, size);
}

static struct ccperf_family family;


struct ccperf_family *ccperf_family_ccdrbg(int argc, char *argv[])
{
    CC_UNUSED int status;

    // DRBG - NIST CTR
    struct ccdrbg_nistctr_custom drbg_ctr = {
        .ctr_info = ccaes_ctr_crypt_mode(),
        .keylen = 32,
        .strictFIPS = 0,
        .use_df = 1,
    };

    // DRBG - NIST HMAC
    struct ccdrbg_nisthmac_custom drbg_hmac = {
        .di = ccsha256_di(),
        .strictFIPS = 0,
    };

    memcpy(&custom_ctr,&drbg_ctr,sizeof(custom_ctr));
    memcpy(&custom_hmac,&drbg_hmac,sizeof(custom_hmac));

        F_GET_ALL(family, ccdrbg);
    static const size_t sizes[]={16,32,256,1024,32*1024};
    F_SIZES_FROM_ARRAY(family,sizes);
    family.size_kind=ccperf_size_bytes;
    return &family;
}


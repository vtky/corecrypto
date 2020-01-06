/*
 * Copyright (c) 2011,2012,2014,2015,2016,2017,2018 Apple Inc. All rights reserved.
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
#include <corecrypto/ccec.h>
#include <corecrypto/ccec_priv.h>

static ccec_const_cp_t ccec_cp(size_t size) {
    switch (size) {
        case (192):
            return ccec_cp_192();
        case (224):
            return ccec_cp_224();
        case (256):
            return ccec_cp_256();
        case (384):
            return ccec_cp_384();
        case (521): /* -- 544 = 521 rounded up to the nearest multiple of 32*/
            return ccec_cp_521();
        default:
            return (ccec_const_cp_t)(const struct cczp* )0;
    }
}

static struct ccec_full_ctx* gkey=NULL;

static void update_gkey(ccec_const_cp_t cp) {
    if (gkey==NULL || (ccec_cp_prime_bitlen(ccec_ctx_cp(gkey))!=ccec_cp_prime_bitlen(cp))) {
        gkey = realloc(gkey, ccec_full_ctx_size(ccec_ccn_size(cp)));
        int status=ccec_generate_key_internal_fips(cp, rng, gkey);
        if (status) abort();
    }
}

static double perf_ccec_compact_import_pub(size_t loops, ccec_const_cp_t cp)
{
    if (ccec_cp_prime_bitlen(cp)==224) {
        return 0; // not supported
    }

    update_gkey(cp);

    size_t  export_pubsize = ccec_compact_export_size(0, ccec_ctx_pub(gkey));
    uint8_t exported_pubkey[export_pubsize];
    ccec_pub_ctx_decl_cp(ccec_ctx_cp(gkey), reconstituted_pub);
    ccec_compact_export(0, exported_pubkey, gkey);
    
    perf_start();
    do {
        int status=ccec_compact_import_pub(ccec_ctx_cp(gkey), export_pubsize, exported_pubkey, reconstituted_pub);
        if (status) abort();
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccec_generate_key_legacy(size_t loops, ccec_const_cp_t cp)
{
    ccec_full_ctx_decl_cp(cp, key);

    perf_start();
    do {
        int status=ccec_generate_key_legacy(cp, rng, key);
        if (status) abort();
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccec_generate_key_fips(size_t loops, ccec_const_cp_t cp)
{
    ccec_full_ctx_decl_cp(cp, key);

    perf_start();
    do {
        int status=ccec_generate_key_fips(cp, rng, key);
        if (status) abort();
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccec_compact_generate_key(size_t loops, ccec_const_cp_t cp)
{
    ccec_full_ctx_decl_cp(cp, key);

    perf_start();
    do {
        int status=ccec_compact_generate_key(cp, rng, key);
        if (status) abort();
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccec_generate_key_internal_fips(size_t loops, ccec_const_cp_t cp)
{
    ccec_full_ctx_decl_cp(cp, key);

    perf_start();
    do {
        int status=ccec_generate_key_internal_fips(cp, rng, key);
        if (status) abort();
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccec_sign(size_t loops, ccec_const_cp_t cp)
{
    size_t siglen = ccec_sign_max_size(cp);
    uint8_t sig[siglen];
    uint8_t digest[24] = "012345678912345678901234";

    update_gkey(cp);

    perf_start();
    do {
        int status=ccec_sign(gkey, sizeof(digest), digest, &siglen, sig, rng);
        if (status) abort();
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccec_verify(size_t loops, ccec_const_cp_t cp)
{
    size_t siglen = ccec_sign_max_size(cp);
    uint8_t sig[siglen];
    uint8_t digest[24] = "012345678912345678901234";
    bool ok;

    update_gkey(cp);

    ccec_sign(gkey, sizeof(digest), digest, &siglen, sig, rng);

    perf_start();
    do {
        int status=ccec_verify(ccec_ctx_pub(gkey), sizeof(digest), digest, siglen, sig, &ok);
        if (status) abort();
    } while (--loops != 0);
    return perf_seconds();
}

static double perf_ccecdh_compute_shared_secret(size_t loops, ccec_const_cp_t cp)
{
    ccec_full_ctx_decl_cp(cp, key2);
    uint8_t out1[ccec_ccn_size(cp)];
    size_t out1_len;

    // Key 1
    update_gkey(cp);

    // Key 2
    int status=ccec_generate_key_internal_fips(cp, rng, key2);
    if (status) abort();

    perf_start();
    do {
        out1_len=sizeof(out1);
        status=ccecdh_compute_shared_secret(gkey, ccec_ctx_pub(key2), &out1_len, out1, NULL);
        if (status) abort();
    } while (--loops != 0);
    return perf_seconds();
}

#define _TEST(_x) { .name = #_x, .func = perf_ ## _x}
static struct ccec_perf_test {
    const char *name;
    double(*func)(size_t loops, ccec_const_cp_t cp);
} ccec_perf_tests[] = {

    _TEST(ccec_generate_key_internal_fips),
    _TEST(ccec_generate_key_fips),
    _TEST(ccec_generate_key_legacy),
    _TEST(ccec_compact_generate_key),
    _TEST(ccec_sign),
    _TEST(ccec_verify),
    _TEST(ccec_compact_import_pub),
    _TEST(ccecdh_compute_shared_secret),
};

static double perf_ccec(size_t loops, size_t size, const void *arg)
{
    const struct ccec_perf_test *test=arg;
    return test->func(loops, ccec_cp(size));
}

static struct ccperf_family family;

struct ccperf_family *ccperf_family_ccec(int argc, char *argv[])
{
    F_GET_ALL(family, ccec);

    static const size_t sizes[]={192,224,256,384,521};
    F_SIZES_FROM_ARRAY(family,sizes);

    family.size_kind=ccperf_size_bits;
    return &family;
}

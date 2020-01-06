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

#include <corecrypto/ccperf.h>
#include <corecrypto/ccchacha20poly1305.h>
#include <corecrypto/ccchacha20poly1305_priv.h>

static double perf_ccchacha_init(size_t loops, size_t size CC_UNUSED, const void *test CC_UNUSED)
{
    ccchacha20_ctx		ctx;

    uint8_t key[32];
    cc_zero(32,key);

    uint8_t nonce[12];
    cc_zero(12,nonce);

    uint32_t counter = 0;

    perf_start();
    while (loops--) {
        ccchacha20_init(&ctx, key);
        ccchacha20_setnonce(&ctx, nonce);
        ccchacha20_setcounter(&ctx, counter);
    }

    return perf_seconds();
}

static double perf_ccchacha_update(size_t loops, size_t size, const void *test CC_UNUSED)
{
    ccchacha20_ctx		ctx;

    uint8_t key[32];
    cc_zero(32,key);

    uint8_t nonce[12];
    cc_zero(12,nonce);

    uint32_t counter = 0;

    unsigned char temp[size];
    
    ccchacha20_init(&ctx, key);
    ccchacha20_setnonce(&ctx, nonce);
    ccchacha20_setcounter(&ctx, counter);

    perf_start();
    while(loops--)
        ccchacha20_update(&ctx, size, temp, temp);

    return perf_seconds();
}

static double perf_ccchacha_one_shot(size_t loops, size_t size, const void *test CC_UNUSED)
{
    uint8_t key[32];
    cc_zero(32,key);

    uint8_t nonce[12];
    cc_zero(12,nonce);

    uint32_t counter = 0;

    unsigned char temp[size];

    perf_start();
    while(loops--)
        ccchacha20(key, nonce, counter, size, temp, temp);

    return perf_seconds();
}

static struct ccperf_family family_init;
static struct ccperf_family family_update;
static struct ccperf_family family_one_shot;

static struct ccperf_test init[] = {
    {.name="ccchacha_init"}
};

struct ccperf_family *ccperf_family_ccchacha_init(int argc CC_UNUSED, char *argv[] CC_UNUSED)
{
    family_init.name="ccchacha_init";
    family_init.func=perf_ccchacha_init;
    family_init.loops=1;
    family_init.nsizes=1;
    family_init.sizes=malloc(family_init.nsizes*sizeof(size_t));
    family_init.sizes[0]=1;
    family_init.size_kind=ccperf_size_iterations;
    family_init.ntests=1;
    family_init.tests=malloc(family_init.ntests*sizeof(struct ccperf_test *));
    family_init.tests[0]=init;
    return &family_init;
}

static struct ccperf_test update[] = {
    {.name="ccchacha_update"}
};

struct ccperf_family *ccperf_family_ccchacha_update(int argc CC_UNUSED, char *argv[] CC_UNUSED)
{
    family_update.name="ccchacha_update";
    family_update.func=perf_ccchacha_update;
    family_update.loops=1;
    F_SIZES(family_update, 6, 1024);
    family_update.size_kind=ccperf_size_bytes;
    family_update.ntests=1;
    family_update.tests=malloc(family_update.ntests*sizeof(struct ccperf_test *));
    family_update.tests[0]=update;
    return &family_update;
}

static struct ccperf_test final[] = {
    {.name="ccchacha_update"}
};

struct ccperf_family *ccperf_family_ccchacha_one_shot(int argc CC_UNUSED, char *argv[] CC_UNUSED)
{
    family_one_shot.name="ccchacha_one_shot";
    family_one_shot.func=perf_ccchacha_one_shot;
    family_one_shot.loops=1;
    F_SIZES(family_one_shot, 6, 1024);
    family_one_shot.size_kind=ccperf_size_bytes;
    family_one_shot.ntests=1;
    family_one_shot.tests=malloc(family_one_shot.ntests*sizeof(struct ccperf_test *));
    family_one_shot.tests[0]=final;
    return &family_one_shot;
}

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

static double perf_ccchachapoly_encrypt_and_sign(size_t loops, size_t size, const void *test CC_UNUSED)
{
    uint8_t key[32];
    cc_zero(32,key);

    uint8_t nonce[8];
    cc_zero(8,nonce);

    uint8_t authtag[16];
    cc_zero(16,authtag);

    unsigned char temp[size];
    
    const struct ccchacha20poly1305_info *info = ccchacha20poly1305_info();

    perf_start();
    while(loops--)
        ccchacha20poly1305_encrypt_oneshot(info, key, nonce, 0, NULL, size, temp, temp, authtag);
    
    return perf_seconds();
}

static double perf_ccchachapoly_decrypt_and_verify(size_t loops, size_t size, const void *test CC_UNUSED)
{
    // From benchmarking, this test is suspiciously fast, which makes me suspect
    // that there is a "fail early" fast path; We aren't even trying to supply
    // a valid auth tag here.

    uint8_t key[32];
    cc_zero(32,key);

    uint8_t nonce[8];
    cc_zero(8,nonce);

    uint8_t authtag[16];
    cc_zero(16,authtag);

    unsigned char temp[size];
    
    const struct ccchacha20poly1305_info *info = ccchacha20poly1305_info();

    perf_start();
    while(loops--)
        ccchacha20poly1305_decrypt_oneshot(info, key, nonce, 0, NULL, size, temp, temp, authtag);
    
    return perf_seconds();
}

static struct ccperf_family family_encrypt_one_shot;
static struct ccperf_family family_decrypt_one_shot;

static struct ccperf_test encrypt_and_sign[] = {
    {.name="ccchachapoly_encrypt_and_sign"}
};

struct ccperf_family *ccperf_family_ccchachapoly_encrypt_and_sign(int argc CC_UNUSED, char *argv[] CC_UNUSED)
{
    family_encrypt_one_shot.name="ccchachapoly_encrypt_and_sign";
    family_encrypt_one_shot.func=perf_ccchachapoly_encrypt_and_sign;
    family_encrypt_one_shot.loops=1;
    F_SIZES(family_encrypt_one_shot, 6, 1024);
    family_encrypt_one_shot.size_kind=ccperf_size_bytes;
    family_encrypt_one_shot.ntests=1;
    family_encrypt_one_shot.tests=malloc(family_encrypt_one_shot.ntests*sizeof(struct ccperf_test *));
    family_encrypt_one_shot.tests[0]=encrypt_and_sign;
    return &family_encrypt_one_shot;
}

static struct ccperf_test decrypt_and_verify[] = {
    {.name="ccchachapoly_decrypt_and_verify"}
};

struct ccperf_family *ccperf_family_ccchachapoly_decrypt_and_verify(int argc CC_UNUSED, char *argv[] CC_UNUSED)
{
    family_decrypt_one_shot.name="ccchachapoly_decrypt_and_verify";
    family_decrypt_one_shot.func=perf_ccchachapoly_decrypt_and_verify;
    family_decrypt_one_shot.loops=1;
    F_SIZES(family_decrypt_one_shot, 6, 1024);
    family_decrypt_one_shot.size_kind=ccperf_size_bytes;
    family_decrypt_one_shot.ntests=1;
    family_decrypt_one_shot.tests=malloc(family_decrypt_one_shot.ntests*sizeof(struct ccperf_test *));
    family_decrypt_one_shot.tests[0]=decrypt_and_verify;
    return &family_decrypt_one_shot;
}

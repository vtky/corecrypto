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

#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha1.h>
#include <corecrypto/ccsha2.h>

#include "cavs_common.h"

const struct ccdigest_info *cavs_find_digest_info(cavs_sha_is is, cavs_digest digest)
{
    switch (is) {
    case CAVS_SHA_IS_GEN:
        switch (digest) {
#if CC_KERNEL           // Kernel specific general digest support
        case CAVS_DIGEST_SHA1:      return ccsha1_di();   break;
        case CAVS_DIGEST_SHA224:    return ccsha224_di(); break;
        case CAVS_DIGEST_SHA256:    return ccsha256_di(); break;
        case CAVS_DIGEST_SHA384:    return ccsha384_di(); break;
        case CAVS_DIGEST_SHA512:    return ccsha512_di(); break;
#else                   // Userland specific general digest support
        case CAVS_DIGEST_SHA1:      return &ccsha1_ltc_di;   break;
        case CAVS_DIGEST_SHA224:    return &ccsha224_ltc_di; break;
        case CAVS_DIGEST_SHA256:    return &ccsha256_ltc_di; break;
        case CAVS_DIGEST_SHA384:    return &ccsha384_ltc_di; break;
        case CAVS_DIGEST_SHA512:    return &ccsha512_ltc_di; break;
#endif
        default:                    return NULL;             break;
        }

#if !CC_UNITTEST
#if (defined(__arm__) || defined(__arm64__)) && CC_USE_ASM
    case CAVS_SHA_IS_VNG:
        switch (digest) {
        case CAVS_DIGEST_SHA1:      return &ccsha1_vng_armv7neon_di;   break;
        case CAVS_DIGEST_SHA224:    return &ccsha224_vng_armv7neon_di; break;
        case CAVS_DIGEST_SHA256:    return &ccsha256_vng_armv7neon_di; break;
        case CAVS_DIGEST_SHA384:    return &ccsha384_ltc_di;           break;
        case CAVS_DIGEST_SHA512:    return &ccsha512_ltc_di;           break;
        default:                    return NULL;                       break;
        }
#endif
            
#if defined(__x86_64__) || defined(__i386__)
#if !CC_KERNEL
    case CAVS_SHA_IS_NOSSE:
        switch (digest) {
        case CAVS_DIGEST_SHA1:      return &ccsha1_ltc_di;   break;
        case CAVS_DIGEST_SHA224:    return &ccsha224_ltc_di; break;
        case CAVS_DIGEST_SHA256:    return &ccsha256_ltc_di; break;
        case CAVS_DIGEST_SHA384:    return &ccsha384_ltc_di; break;
        case CAVS_DIGEST_SHA512:    return &ccsha512_ltc_di; break;
        default:                    return NULL;             break;
        }
#endif
 
#if CC_USE_ASM
    case CAVS_SHA_IS_SSE:
        switch (digest) {
        case CAVS_DIGEST_SHA1:      return &ccsha1_vng_intel_SupplementalSSE3_di;   break;
        case CAVS_DIGEST_SHA224:    return &ccsha224_vng_intel_SupplementalSSE3_di; break;
        case CAVS_DIGEST_SHA256:    return &ccsha256_vng_intel_SupplementalSSE3_di; break;
        case CAVS_DIGEST_SHA384:    return &ccsha384_ltc_di;                        break;
        case CAVS_DIGEST_SHA512:    return &ccsha512_ltc_di;                        break;
        default:                    return NULL;                                    break;
        }
#endif
            
#if defined(__x86_64__) && CC_USE_ASM
    case CAVS_SHA_IS_AVX1:
        switch (digest) {
        case CAVS_DIGEST_SHA1:      return &ccsha1_vng_intel_AVX1_di;   break;
        case CAVS_DIGEST_SHA224:    return &ccsha224_vng_intel_AVX1_di; break;
        case CAVS_DIGEST_SHA256:    return &ccsha256_vng_intel_AVX1_di; break;
        case CAVS_DIGEST_SHA384:    return &ccsha384_vng_intel_AVX1_di; break;
        case CAVS_DIGEST_SHA512:    return &ccsha512_vng_intel_AVX1_di; break;
        default:                    return NULL;                        break;
        }
            
    case CAVS_SHA_IS_AVX2:
        switch (digest) {
        case CAVS_DIGEST_SHA1:      return &ccsha1_vng_intel_AVX2_di;   break;
        case CAVS_DIGEST_SHA224:    return &ccsha224_vng_intel_AVX2_di; break;
        case CAVS_DIGEST_SHA256:    return &ccsha256_vng_intel_AVX2_di; break;
        case CAVS_DIGEST_SHA384:    return &ccsha384_vng_intel_AVX2_di; break;
        case CAVS_DIGEST_SHA512:    return &ccsha512_vng_intel_AVX2_di; break;
        default:                    return NULL;                        break;
        }
#endif

#endif
#endif // CC_UNITTEST
    default:                    return NULL;                        break;
    }
    return NULL;
}

cavs_digest cavs_find_digest_by_len(int len)
{
    switch (len)
    {
        case CCSHA1_OUTPUT_SIZE:    return CAVS_DIGEST_SHA1;
        case CCSHA224_OUTPUT_SIZE:  return CAVS_DIGEST_SHA224;
        case CCSHA256_OUTPUT_SIZE:  return CAVS_DIGEST_SHA256;
        case CCSHA384_OUTPUT_SIZE:  return CAVS_DIGEST_SHA384;
        case CCSHA512_OUTPUT_SIZE:  return CAVS_DIGEST_SHA512;
        default:                    return CAVS_DIGEST_UNKNOWN;
    }
}

const struct ccdigest_info *cavs_find_digest_info_by_len(cavs_sha_is is, int len)
{
    return cavs_find_digest_info(is, cavs_find_digest_by_len(len));
}

int cavs_digest_to_output(cavs_digest digest)
{
    switch (digest)
    {
        case CAVS_DIGEST_SHA1:      return CCSHA1_OUTPUT_SIZE;
        case CAVS_DIGEST_SHA224:    return CCSHA224_OUTPUT_SIZE;
        case CAVS_DIGEST_SHA256:    return CCSHA256_OUTPUT_SIZE;
        case CAVS_DIGEST_SHA384:    return CCSHA384_OUTPUT_SIZE;
        case CAVS_DIGEST_SHA512:    return CCSHA512_OUTPUT_SIZE;

        case CAVS_DIGEST_SHA3_224:  return CCSHA224_OUTPUT_SIZE;
        case CAVS_DIGEST_SHA3_256:  return CCSHA256_OUTPUT_SIZE;
        case CAVS_DIGEST_SHA3_384:  return CCSHA384_OUTPUT_SIZE;
        case CAVS_DIGEST_SHA3_512:  return CCSHA512_OUTPUT_SIZE;
        default:                    return 0;
    }
}


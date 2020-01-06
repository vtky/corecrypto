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
#ifndef _CORECRYPTO_FIPSPOST_GET_HMAC_H_
#define _CORECRYPTO_FIPSPOST_GET_HMAC_H_

#include <corecrypto/ccsha2.h>

struct mach_header;

/*
 * The pre-calculated SHA256 HMAC gets placed here for integrity
 * testing.  The current value is a random number.  Use a different random
 * number for each architecture type supported.
 */
#define FIPSPOST_PRECALC_HMAC_SIZE CCSHA256_OUTPUT_SIZE
#define FIPSPOST_HMAC_VALUE fipspost_precalc_hmac
#define FIPSPOST_PRECALC_HMAC_VARIABLE                                      \
const unsigned char FIPSPOST_HMAC_VALUE[FIPSPOST_PRECALC_HMAC_SIZE]

#define FIPSPOST_PRECALC_HMAC(ARCH, MODE)                                   \
      { ARCH, MODE, 0x10, 0xdc, 0xe5, 0x34, 0x6f, 0x01,                     \
        0xdd, 0x82, 0xf8, 0xad, 0xe5, 0x8f, 0xa1, 0xcc,                     \
        0xc1, 0x32, 0xe5, 0xa8, 0x53, 0xc8, 0x39, 0xa3,                     \
        0x84, 0x5f, 0x3b, 0xcb, 0x39, 0x9e, 0xd1, 0x7b }

/* Comprehensive list, in the order of mach/machine.h */
#define FIPSPOST_PRECALC_HMAC_VALUE_X86_64      FIPSPOST_PRECALC_HMAC(0x86, 0x64)
#define FIPSPOST_PRECALC_HMAC_VALUE_X86_32      FIPSPOST_PRECALC_HMAC(0x86, 0x32)
#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_4T      FIPSPOST_PRECALC_HMAC(0xa4, 0x01)
#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_6       FIPSPOST_PRECALC_HMAC(0xa6, 0x00)
#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_V5TEJ   FIPSPOST_PRECALC_HMAC(0xa5, 0x01)
#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_XSCALE  FIPSPOST_PRECALC_HMAC(0xa5, 0x02)
#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_7A      FIPSPOST_PRECALC_HMAC(0xa7, 0x0a)
#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_7F      FIPSPOST_PRECALC_HMAC(0xa7, 0x0f)
#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_7S      FIPSPOST_PRECALC_HMAC(0xa7, 0x05)
#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_7K      FIPSPOST_PRECALC_HMAC(0xa7, 0x04)
#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_6M      FIPSPOST_PRECALC_HMAC(0xa6, 0x01)
#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_7M      FIPSPOST_PRECALC_HMAC(0xa7, 0x06)
#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_7EM     FIPSPOST_PRECALC_HMAC(0xa7, 0x07)

#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_64      FIPSPOST_PRECALC_HMAC(0xa8, 0x64)
#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_64_V8   FIPSPOST_PRECALC_HMAC(0xa8, 0x68)
#define FIPSPOST_PRECALC_HMAC_VALUE_ARM_64E     FIPSPOST_PRECALC_HMAC(0xa8, 0x6e)

#define FIPSPOST_CREATE_PRECALC_HMAC(ARCH, VARIANT)                         \
    FIPSPOST_PRECALC_HMAC_VARIABLE = FIPSPOST_PRECALC_HMAC_VALUE ## _ ## ARCH ## _ ## VARIANT;

/*
 * Declare the individual variants based on the current architecture. Use the
 * raw compiler flags because each archive must have a different value, even if
 * they're all classed as '__arm__', to avoid duplicate values in a FAT file.
 */
#if defined(__x86_64__)
#define FIPSPOST_DECLARE_PRECALC_HMAC FIPSPOST_CREATE_PRECALC_HMAC(X86, 64)
#elif defined(__i386__)
#define FIPSPOST_DECLARE_PRECALC_HMAC FIPSPOST_CREATE_PRECALC_HMAC(X86, 32)
#elif defined(__ARM_ARCH_4T__)
#define FIPSPOST_DECLARE_PRECALC_HMAC FIPSPOST_CREATE_PRECALC_HMAC(ARM, 4T)
#elif defined(__ARM_ARCH_6K__)
#define FIPSPOST_DECLARE_PRECALC_HMAC FIPSPOST_CREATE_PRECALC_HMAC(ARM, 6)
#elif defined (__ARM_ARCH_7A__) && !defined (__ARM_ARCH_7K__)
#define FIPSPOST_DECLARE_PRECALC_HMAC FIPSPOST_CREATE_PRECALC_HMAC(ARM, 7A)
#elif defined (__ARM_ARCH_7F__)
#define FIPSPOST_DECLARE_PRECALC_HMAC FIPSPOST_CREATE_PRECALC_HMAC(ARM, 7F)
#elif defined (__ARM_ARCH_7S__)
#define FIPSPOST_DECLARE_PRECALC_HMAC FIPSPOST_CREATE_PRECALC_HMAC(ARM, 7S)
#elif defined (__ARM_ARCH_7K__)
#define FIPSPOST_DECLARE_PRECALC_HMAC FIPSPOST_CREATE_PRECALC_HMAC(ARM, 7K)
#elif defined(__ARM_ARCH_6M__)
#define FIPSPOST_DECLARE_PRECALC_HMAC FIPSPOST_CREATE_PRECALC_HMAC(ARM, 6M)
#elif defined (__ARM_ARCH_7M__)
#define FIPSPOST_DECLARE_PRECALC_HMAC FIPSPOST_CREATE_PRECALC_HMAC(ARM, 7M)
#elif defined(__ARM_ARCH_7EM__)
#define FIPSPOST_DECLARE_PRECALC_HMAC FIPSPOST_CREATE_PRECALC_HMAC(ARM, 7EM)
#else
#error Unsupported architecture type; add as necessary in the order of mach/machine.h.
#endif


#define FIPSPOST_EXTERN_PRECALC_HMAC extern FIPSPOST_PRECALC_HMAC_VARIABLE;

int fipspost_get_hmac(const struct mach_header* pmach_header, unsigned char* sha256HMACBuffer, size_t max_offset);

#endif

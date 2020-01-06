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

#include "testmore.h"
#include "testbyteBuffer.h"
#include <corecrypto/cc_runtime_config.h>

#include "cavs_common.h"
#include "cavs_dispatch.h"
#include "cavs_op_digest.h"

#include "crypto_test_digest.h"

static void fipscavs_tests_digest_generic(void)
{
    {
        struct cavs_op_digest vector = {.vector = CAVS_VECTOR_DIGEST, .digest = CAVS_DIGEST_SHA512, .sha_is = CAVS_SHA_IS_GEN, .message_len = 0, .message = (uint8_t *)"", .digest_len = 64};
        size_t len = vector.digest_len;
        uint8_t *wksp = NULL;

        is(CAVS_STATUS_OK, cavs_dispatch(CAVS_TARGET_USER, vector.vector, &vector, &wksp, &len), "dispatch");

        const char *result = "\xCF\x83\xE1\x35\x7E\xEF\xB8\xBD\xF1\x54\x28\x50\xD6\x6D\x80\x07\xD6\x20\xE4\x05\x0B\x57\x15\xDC\x83\xF4\xA9\x21\xD3\x6C\xE9\xCE\x47\xD0\xD1\x3C\x5D\x85\xF2\xB0\xFF\x83\x18\xD2\x87\x7E\xEC\x2F\x63\xB9\x31\xBD\x47\x41\x7A\x81\xA5\x38\x32\x7A\xF9\x27\xDA\x3E";
        is(len, vector.digest_len, "expected length");
        ok_memcmp(result, wksp, vector.digest_len, "expected result");
    }
	/* CAVS_VECTOR_DIGEST */
	{
		struct cavs_op_digest v = {.vector = CAVS_VECTOR_DIGEST, .digest = CAVS_DIGEST_SHA512, .sha_is = CAVS_SHA_IS_GEN, .message_len = 192, .message = (uint8_t *)"\x6E\x04\x32\x85\xE4\xF5\xA8\x8D\xD7\x3B\xB6\xFC\xF4\xE0\x12\x4B\x25\x36\x94\x7A\xB6\x6A\x83\x49\xB7\x5C\x12\xAB\xA1\xAE\x2A\x78\x3C\x1C\x6A\x62\xBF\x0B\x6D\x2A\x39\x64\x4B\x14\x31\xA2\x62\x98\x89\x2A\x56\x5A\xA9\xDB\x56\x5C\xD9\xE7\xA1\x72\xED\xE1\x49\xF7\x6E\x04\x32\x85\xE4\xF5\xA8\x8D\xD7\x3B\xB6\xFC\xF4\xE0\x12\x4B\x25\x36\x94\x7A\xB6\x6A\x83\x49\xB7\x5C\x12\xAB\xA1\xAE\x2A\x78\x3C\x1C\x6A\x62\xBF\x0B\x6D\x2A\x39\x64\x4B\x14\x31\xA2\x62\x98\x89\x2A\x56\x5A\xA9\xDB\x56\x5C\xD9\xE7\xA1\x72\xED\xE1\x49\xF7\x6E\x04\x32\x85\xE4\xF5\xA8\x8D\xD7\x3B\xB6\xFC\xF4\xE0\x12\x4B\x25\x36\x94\x7A\xB6\x6A\x83\x49\xB7\x5C\x12\xAB\xA1\xAE\x2A\x78\x3C\x1C\x6A\x62\xBF\x0B\x6D\x2A\x39\x64\x4B\x14\x31\xA2\x62\x98\x89\x2A\x56\x5A\xA9\xDB\x56\x5C\xD9\xE7\xA1\x72\xED\xE1\x49\xF7", .digest_len = 64, };
		size_t len = 64;
		uint8_t *wksp = NULL;
		is(CAVS_STATUS_OK, cavs_dispatch(CAVS_TARGET_USER, v.vector, &v, &wksp, &len), "dispatch");
		const char *exp_result = "\x7B\xDB\x9F\x42\x1F\xC9\xDF\xA6\x59\x97\xFB\x3A\xA5\x41\xC7\x80\xB6\xAA\x0A\x52\xB6\xDC\x03\x2A\x36\xC3\xEE\x26\xF4\xCA\x70\xA4\x97\x11\xCA\x50\x72\xF8\x79\xD0\x65\x24\x2C\x93\x0E\x99\x71\xE7\xE7\x6E\xA9\x12\x2F\x44\x4C\x4B\x4D\x73\xCB\xC6\x83\x71\xB0\x5B";
		is(len, (size_t)64, "expected length");
		ok_memcmp(exp_result, wksp, 64, "expected result");
	}
}

void fipscavs_tests_digest(void)
{
    fipscavs_tests_digest_generic();
}


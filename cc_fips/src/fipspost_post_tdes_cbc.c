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
#include <corecrypto/cc_debug.h>
#include <corecrypto/ccdes.h>

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_tdes_cbc.h"

// Test the TDES CBC mode
int fipspost_post_tdes_cbc(int fips_mode)
{
    size_t keyLength = 24;

    // TDES Encryption Test Data
    unsigned char* keyEncryptBuffer = (unsigned char*)"\x5e\xe4\xdb\x0c\xdf\xdf\x71\x9e\x40\xfc\x96\x2d\x2f\x31\xf4\x16\xd9\xaa\x0f\x22\x8d\x89\xe0\x7f";
    unsigned char* ivEncryptBuffer = (unsigned char*)"\x88\x13\x7a\x56\x2b\xea\xb0\xe2";
    unsigned char* inputEncryptBuffer = (unsigned char*)"\xb9\x09\x69\xd0\x50\x3f\x61\xf3";

    unsigned char* outputEncryptBuffer;
    outputEncryptBuffer = POST_FIPS_RESULT_STR("\x68\xc0\x6c\x8a\xf7\x72\xab\xff");


    // TDES Decryption Test Data
    unsigned char* keyDecryptBuffer = (unsigned char*)"\x68\x88\x8a\x1b\xba\xe5\x77\x23\x89\x61\x3e\x8e\xdf\x6a\xfd\x3b\x8b\x85\x69\xce\x70\x60\x7d\x6b";
    unsigned char* ivDecryptBuffer = (unsigned char*)"\x47\x2f\x3a\xcb\x19\x70\x7d\xe8";
    unsigned char* inputDecryptBuffer = (unsigned char*)"\x61\xe3\x3a\x22\xad\x7c\xfa\x71";
    unsigned char* outputDecryptBuffer = (unsigned char*)"\x75\xda\xfe\x5c\x63\x1c\xeb\x35";

    unsigned char outputBuffer[CCDES_BLOCK_SIZE];
    int memCheckResult = CCERR_GENERIC_FAILURE; // Guilty until proven


    const struct ccmode_cbc*  cbc_mode_dec = ccdes3_cbc_decrypt_mode();
    const struct ccmode_cbc*  cbc_mode_enc = ccdes3_cbc_encrypt_mode();

    // Encryption Test
    cccbc_one_shot(cbc_mode_enc, keyLength, keyEncryptBuffer,
                   ivEncryptBuffer, 1,  inputEncryptBuffer, outputBuffer);

    memCheckResult  = memcmp(outputEncryptBuffer, outputBuffer, CCDES_BLOCK_SIZE);

    if (memCheckResult == 0)
    {
        // Decryption Test
        cccbc_one_shot(cbc_mode_dec, keyLength, keyDecryptBuffer,
                       ivDecryptBuffer, 1,  inputDecryptBuffer, outputBuffer);

        memCheckResult = memcmp(outputDecryptBuffer, outputBuffer, CCDES_BLOCK_SIZE);
    }

    if (memCheckResult)
    {
        failf("cycle");
        return CCERR_KAT_FAILURE;
    }

    return memCheckResult; // passed
}

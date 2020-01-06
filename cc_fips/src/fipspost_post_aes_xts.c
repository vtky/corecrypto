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
#include <corecrypto/ccaes.h>

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_aes_xts.h"

int fipspost_post_aes_xts(int fips_mode)
{
    size_t key128Length = 16;

    //Key = 3970cbb4b09a50f428890024876607d04f9b3621728d8a67549f74aa082d58ef
    unsigned char* key_data;
    key_data = POST_FIPS_RESULT_STR("\x39\x70\xcb\xb4\xb0\x9a\x50\xf4\x28\x89\x00\x24\x87\x66\x07\xd0");

    unsigned char* key2_data = (unsigned char*)"\x4f\x9b\x36\x21\x72\x8d\x8a\x67\x54\x9f\x74\xaa\x08\x2d\x58\xef";
    // PT = 18147bb2a205974d1efd386885b24797
    unsigned char* pt_enc_data =  (unsigned char *)"\x18\x14\x7b\xb2\xa2\x05\x97\x4d\x1e\xfd\x38\x68\x85\xb2\x47\x97";

    // CT = b91a3884ffd4e6151c5aaaaecb5fa9ff
    unsigned char* ct_enc_data =  (unsigned char *)"\xb9\x1a\x38\x84\xff\xd4\xe6\x15\x1c\x5a\xaa\xae\xcb\x5f\xa9\xff";
    unsigned int	dataUnitSeqNumber = 41;

    int8_t         tweak_buffer[CCAES_BLOCK_SIZE];

    memset(tweak_buffer, 0, CCAES_BLOCK_SIZE);
    unsigned char* dataUnitSeqNumberPtr = (unsigned char*)&dataUnitSeqNumber;
    size_t numBytes = sizeof(dataUnitSeqNumber);
    for(size_t iCnt = 0; iCnt < numBytes; iCnt++)
    {
        tweak_buffer[iCnt] = (unsigned char)*dataUnitSeqNumberPtr;
        dataUnitSeqNumberPtr++;
    }

    const struct ccmode_xts* xts_enc =  ccaes_xts_encrypt_mode();

    unsigned char output[16];
    memset(output, 0, 16);

    ccxts_one_shot(xts_enc, key128Length, key_data, key2_data, tweak_buffer, 1, pt_enc_data, output);
    if (memcmp(output, ct_enc_data, 16))
    {
        failf("encrypt");
        return CCERR_KAT_FAILURE;
    }

    const struct ccmode_xts* xts_dec =  ccaes_xts_decrypt_mode();
    memset(output, 0, 16);
    ccxts_one_shot(xts_dec, key128Length, key_data, key2_data, tweak_buffer, 1, ct_enc_data, output);
    if (memcmp(output, pt_enc_data, 16))
    {
        failf("decrypt");
        return CCERR_KAT_FAILURE;
    }

    return 0; // passed
}

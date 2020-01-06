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
#include "fipspost_post_aes_cbc.h"

// Test the AES CBC mode
int fipspost_post_aes_cbc(int fips_mode)
{
    size_t key128Length = 16;

    typedef struct
    {
        size_t				keyLength;
        int                 forEncryption;
        unsigned char*		keyData;
        unsigned char*		ivData;
        unsigned char*		inputData;
        unsigned char*		outputData;
    } testData;

    // AES 128 Encryption Test Data
    unsigned char* key128EncryptBuffer = (unsigned char*)"\x34\x49\x1b\x26\x6d\x8f\xb5\x4c\x5c\xe1\xa9\xfb\xf1\x7b\x09\x8c";
    unsigned char* iv128EncryptBuffer = (unsigned char*)"\x9b\xc2\x0b\x29\x51\xff\x72\xd3\xf2\x80\xff\x3b\xd2\xdc\x3d\xcc";
    unsigned char* input128EncryptBuffer = (unsigned char*)"\x06\xfe\x99\x71\x63\xcb\xcb\x55\x85\x3e\x28\x57\x74\xcc\xa8\x9d";

    unsigned char* output128EncryptBuffer;
    output128EncryptBuffer = POST_FIPS_RESULT_STR("\x32\x5d\xe3\x14\xe9\x29\xed\x08\x97\x87\xd0\xa2\x05\xd1\xeb\x33");

    // AES 128 Decryption Test Data
    unsigned char* key128DecryptBuffer = (unsigned char*)"\xc6\x8e\x4e\xb2\xca\x2a\xc5\xaf\xee\xac\xad\xea\xa3\x97\x11\x94";
    unsigned char* iv128DecryptBuffer = (unsigned char*)"\x11\xdd\x9d\xa1\xbd\x22\x3a\xcf\x68\xc5\xa1\xe1\x96\x4c\x18\x9b";
    unsigned char* input128DecryptBuffer = (unsigned char*)"\xaa\x36\x57\x9b\x0c\x72\xc5\x28\x16\x7b\x70\x12\xd7\xfa\xf0\xde";
    unsigned char* output128DecryptBuffer = (unsigned char*)"\x9e\x66\x1d\xb3\x80\x39\x20\x9a\x72\xc7\xd2\x96\x40\x66\x88\xf2";

    
    testData dataToTest[] =
    {
        {key128Length, 1, key128EncryptBuffer, iv128EncryptBuffer, input128EncryptBuffer, output128EncryptBuffer},
        {key128Length, 0, key128DecryptBuffer, iv128DecryptBuffer, input128DecryptBuffer, output128DecryptBuffer}
        
    };

    const struct ccmode_cbc* mode_enc = ccaes_cbc_encrypt_mode();
    const struct ccmode_cbc* mode_dec = ccaes_cbc_decrypt_mode();


    struct {
        const struct ccmode_cbc*	enc_mode_ptr;
        const struct ccmode_cbc*	dec_mode_ptr;
    } impl[] = {
        {mode_enc, mode_dec},
    };

    int memCheckResult = 0;
    unsigned char outputBuffer[CCAES_BLOCK_SIZE];

    int numDataToTest = 2;
    int numModesToTest = 1;

    for (int iCnt = 0; iCnt < numDataToTest; iCnt++)
    {
        for(int jCnt = 0; jCnt < numModesToTest; jCnt++)
        {

            cccbc_one_shot((dataToTest[iCnt].forEncryption ?
                            impl[jCnt].enc_mode_ptr :
                            impl[jCnt].dec_mode_ptr),
                           dataToTest[iCnt].keyLength, dataToTest[iCnt].keyData,
                           dataToTest[iCnt].ivData,
                           1, /* Only 1 block */
                           dataToTest[iCnt].inputData, outputBuffer);
            
            memCheckResult = (0 == memcmp(dataToTest[iCnt].outputData, outputBuffer, CCAES_BLOCK_SIZE));
            
            
            if (!memCheckResult)
            {
                failf("test %d", iCnt * numDataToTest + jCnt);
                return CCERR_KAT_FAILURE;
            }
        }
    }

    return 0; // passed
}

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
#include <corecrypto/ccdrbg.h>

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_drbg_ctr.h"

// Test CTR DRBG
int fipspost_post_drbg_ctr(int fips_mode)
{
	int result = CCERR_GENERIC_FAILURE;

    unsigned char*  entropyInputBuffer;
    entropyInputBuffer = POST_FIPS_RESULT_STR("\x74\x7a\xe6\x1f\x3d\xb3\x31\x52\x9a\x13\xc3\x6d\xc6\xeb\xd2\xef");


	size_t entropyInputBufferLength = 16;
	unsigned char* nonceBuffer = (unsigned char *)"\xff\xbd\xdc\xdf\x7f\xdd\xce\xa4";
	size_t nonceBufferLength = 8;
	unsigned char* personalizationStringBuffer = (unsigned char *)"\xbd\x93\xc6\xd5\x6b\x07\x7b\xf3\xca\x13\x0c\xc3\xef\xbf\xc7\x10";
	size_t personalizationStringBufferLength = 16;
	unsigned char* additionalInput1Buffer = (unsigned char *)"\xdf\xb1\xe7\x83\x82\xc8\xdb\xd7\xef\x1a\x20\x0b\x13\x67\x1a\xe2";
	size_t additionalInput1BufferLength = 16;
	unsigned char* entropyInputPR1Buffer = (unsigned char *)"\x34\x83\x2e\xc3\x2b\x10\x58\xc9\x8d\x72\xb0\xb6\x89\xa8\xda\xe2";
	size_t entropyInputPR1BufferLength = 16;
	unsigned char* additionalInput2Buffer = (unsigned char *)"\xca\x83\xd6\x45\x5e\x98\xcd\x09\xd6\x65\x86\xe2\x63\x92\x6d\xe6";
	size_t additionalInput2BufferLength = 16;
	unsigned char* entropyInputPR2Buffer = (unsigned char *)"\xbe\xe1\x92\xef\x26\xdd\xbb\x23\x6a\xf8\x29\xd0\xc7\xd8\x49\xb7";
	size_t entropyInputPR2BufferLength = 16;
	unsigned char* returnedBitsBuffer = (unsigned char *)"\x52\x58\xdd\xef\x4b\xda\x42\xed\x49\x9e\x57\xf1\x51\x74\xb0\x87";
	size_t returnedBitsBufferLength = 16;
	
	uint8_t resultBuffer[16];
	memset(resultBuffer, 0, 16);

    static struct ccdrbg_info info;
 	struct ccdrbg_nistctr_custom custom;
   	custom.ctr_info = ccaes_ctr_crypt_mode();
    custom.keylen = 16;
    custom.strictFIPS = 0;
    custom.use_df = 1;
	ccdrbg_factory_nistctr(&info, &custom);

	uint8_t state[info.size];
    struct ccdrbg_state* rng = (struct ccdrbg_state *)state;
    int rc;

	rc = ccdrbg_init(&info, rng, entropyInputBufferLength, entropyInputBuffer,
                         nonceBufferLength, nonceBuffer, personalizationStringBufferLength, personalizationStringBuffer);
	if (rc)
	{
		failf("ccdrbg_init");
		return CCERR_GENERIC_FAILURE;
	}

	rc = ccdrbg_reseed(&info, rng, entropyInputPR1BufferLength, entropyInputPR1Buffer,
                                  additionalInput1BufferLength, additionalInput1Buffer);
	if (rc)
	{
		failf("ccdrbg_reseed");
		return CCERR_GENERIC_FAILURE;
	}

	rc = ccdrbg_generate(&info, rng, 16, resultBuffer, 0, NULL);
	if (rc)
	{
		failf("ccdrbg_generate");
		return CCERR_GENERIC_FAILURE;
	}	

	rc = ccdrbg_reseed(&info, rng, 
                                  entropyInputPR2BufferLength, entropyInputPR2Buffer,  
                                  additionalInput2BufferLength, additionalInput2Buffer);
	if (rc)
	{
		failf("ccdrbg_reseed 2");
		return CCERR_GENERIC_FAILURE;
	}

	rc = ccdrbg_generate(&info, rng, 16, resultBuffer, 0, NULL);
	if (rc)
	{
		failf("ccdrbg_generate 2");
		return CCERR_GENERIC_FAILURE;
	}
         
	result = (memcmp(resultBuffer, returnedBitsBuffer, returnedBitsBufferLength)) ? CCERR_KAT_FAILURE : 0;
	if (result)
	{
		failf("memcmp");
		return result;
	}

	return 0;
}

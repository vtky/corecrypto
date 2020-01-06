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
#include "fipspost_post_aes_gcm.h"

// Test the AES GCM mode
int fipspost_post_aes_gcm(int fips_mode)
{
	// Decryption data
	unsigned char* keyBufferDecPtr = (unsigned char* )"\x53\xcd\x05\xee\xac\xe3\x60\xbb\x84\x22\xde\xee\xde\xe0\x9d\x85";
	size_t keyBufferDecPtrLength = 16;
	unsigned char* ivBufferDecPtr = (unsigned char* )"\x65\x48\x7a\x4d\x2a\x0e\xc7\x33\xf5\x25\x2b\x9e";
	size_t ivBufferDecPtrLength = 12;

    unsigned char* resultTagDecPtr;
    resultTagDecPtr = POST_FIPS_RESULT_STR("\xf2\xa1\x24\x6b\xff\x2d\x89\x3a\xef\xcd\xe5\x90\x7a\x12\x07\x9b");

	// Encryption Data
	unsigned char* keyBufferEncPtr = (unsigned char* )"\x70\xc8\xbf\xb6\x02\x76\xe2\x18\xa0\xed\xa2\xaa\xd1\xfd\xc1\x9c";
	size_t keyBufferEncPtrLength = 16;
	unsigned char* ivBufferEncPtr = 	(unsigned char* )"\x74\x17\x07\xcb\x56\x6f\x68\xe8\x5d\x00\xc7\xbf";	
	size_t ivBufferEncPtrLength = 12;

    unsigned char* resultTagEncPtr;
    resultTagEncPtr = POST_FIPS_RESULT_STR("\x26\x86\xf5\xa1\x1f\x0c\x4b\x53\x81\x0a\x5b\x32\xb0\xa8\xff\xbc");

	size_t aDataLen		= 0;
	const void*	aData	= NULL;
	size_t dataInLength = 0;
    const void*	dataIn	= NULL;
	uint8_t dataOut[16];
	
	size_t tagLength = 16;
    
	uint8_t tag[16];
	memset(tag, 0, 16);
		
	// Test Decrypt First
	const struct ccmode_gcm* mode_dec_ptr = ccaes_gcm_decrypt_mode();

	ccgcm_one_shot(mode_dec_ptr, keyBufferDecPtrLength, keyBufferDecPtr, 
			ivBufferDecPtrLength, ivBufferDecPtr,
			aDataLen, aData,
			dataInLength, dataIn, dataOut,
			tagLength, tag);


	if (memcmp(tag, resultTagDecPtr, 16))
	{
		failf("ccgcm_one_shot decrypt");
		return CCERR_KAT_FAILURE;
	}
	
	// Test Encryption
	aDataLen	= 0;
	aData		= NULL;
	dataInLength = 0;
    dataIn		= NULL;
	tagLength 	= 16;

	memset(tag, 0, 16);
       
    const struct ccmode_gcm* mode_enc_ptr = ccaes_gcm_encrypt_mode();
	
	ccgcm_one_shot(mode_enc_ptr, keyBufferEncPtrLength, keyBufferEncPtr, 
                      ivBufferEncPtrLength, ivBufferEncPtr,
                      aDataLen, aData,
                      dataInLength, dataIn, dataOut,
                      tagLength, tag);


	if (memcmp(tag, resultTagEncPtr, 16))
	{
		failf("ccgcm_one_shot encrypt");
		return CCERR_KAT_FAILURE;
	}

	return 0; // passed
}


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

/* --------------------------------------------------------------------------
    The Documentation for the NSIT DRBG test can be found at
    http://csrc.nist.gov/groups/STM/cavp/documents/drbg/DRBGVS.pdf
   -------------------------------------------------------------------------- */

extern "C" {
#include "cavs_common.h"
#include "cavs_dispatch.h"

#include "cavs_op_drbg.h"
}

#import "CavsDRBGTest.h"

@interface CavsDRBGTest (PrivateMethods)
@end

@implementation CavsDRBGTest

+ (void)setupTest
{ }

+ (void)cleanUpTest
{ }

- (id)initWithFileParser:(TestFileParser *)fileParser
    withTestDictionary:(NSDictionary *)testsToRun
{
    return [super initWithFileParser:fileParser withTestDictionary:testsToRun];
}

- (BOOL)runTest:(TestFileData *)testData withCounter:(NSInteger)counter
{
    struct cavs_op_drbg request;
    memset(&request, 0, sizeof(struct cavs_op_drbg));

    if (TTHMACDRBG == testData.testType) {
        request.vector = CAVS_VECTOR_HMAC_DRBG;
        request.digest = CipherTypeToDigest(testData.cipherType);
        request.random_len = (uint32_t)CC_BITLEN_TO_BYTELEN([testData.returnedBitsLen intValue]);
    } else {
        request.vector = CAVS_VECTOR_DRBG;
        request.digest = CAVS_DIGEST_UNKNOWN;
        request.random_len = (uint32_t)16;
    }
    request.aes_is = cavs_key_to_aes_is([self.keyString UTF8String]);
    request.target = self.testTarget;
    request.pred = (uint32_t)((testData.predictionResistance) ? 1 : 0);

    request.ent_in_len = (uint32_t)[testData.entropyInput length];
    request.ent_in = (uint8_t *)[testData.entropyInput bytes];
    request.nonce_len = (uint32_t)[testData.nonce length];
    request.nonce = (uint8_t *)[testData.nonce bytes];
    request.pers_str_len = (uint32_t)[testData.personalizationString length];
    request.pers_str = (uint8_t *)[testData.personalizationString bytes];

    NSData* add1Data        = [testData.additionalInput objectAtIndex:0];
    NSData* add2Data        = [testData.additionalInput objectAtIndex:1];
    NSData* entropy1Data    = [testData.additionalEntropyInput objectAtIndex:0];
    NSData* entropy2Data    = [testData.additionalEntropyInput objectAtIndex:1];

    request.add_in1_len = (uint32_t)[add1Data length];
    request.add_in1 = (uint8_t *)[add1Data bytes];
    request.add_ent1_len = (uint32_t)[entropy1Data length];
    request.add_ent1 = (uint8_t *)[entropy1Data bytes];
    request.add_in2_len = (uint32_t)[add2Data length];
    request.add_in2 = (uint8_t *)[add2Data bytes];
    request.add_ent2_len = (uint32_t)[entropy2Data length];
    request.add_ent2 = (uint8_t *)[entropy2Data bytes];

    size_t len = request.random_len;
    uint8_t *wksp = NULL;
    int ret = cavs_dispatch(testData.testTarget, request.vector, &request, &wksp, &len);
    if (ret != CAVS_STATUS_OK) {
        errorf("failed cavs_dispatch");
        return NO;
    }

    [self outputFormat:@"COUNT = %d", (int)counter];
    [testData print:_outputFile];
    [self outputFormat:@"ReturnedBits = %@", BufToHexString(wksp, request.random_len)];
    [self outputString:nil];

    return YES;
}

@end

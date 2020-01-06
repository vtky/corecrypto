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

#include "cavs_common.h"
#include "cavs_dispatch.h"

#include "cavs_op_cipher.h"

#include <corecrypto/ccmode.h>

#import "CavsAESXTSTest.h"

@implementation CavsAESXTSTest

- (id)initWithFileParser:(TestFileParser *)fileParser
      withTestDictionary:(NSDictionary *)testsToRun
{
    self = [super initWithFileParser:fileParser withTestDictionary:testsToRun];
    return self;
}

- (BOOL)runTest:(TestFileData *)testData
            withCounter:(NSInteger) counter
{
    BOOL result = NO;

    int enc = testData.encryption;

    /* Generate the tweak from the sequence number. */
    uint32_t seq = testData.dataUnitSeqNumber ? [testData.dataUnitSeqNumber unsignedIntValue] : 0;

    /* Needed to construct the tweak buffer. */
    const struct ccmode_xts *xts_mode;
    xts_mode = (const struct ccmode_xts *)cavs_find_ccmode(
            cavs_key_to_aes_is([self.keyString UTF8String]),
            CAVS_CIPHER_ENC_AES, CAVS_CIPHER_MODE_XTS, enc);

    uint8_t tweak_buffer[CCAES_BLOCK_SIZE];
    memset(tweak_buffer, 0, CCAES_BLOCK_SIZE);
    memcpy(tweak_buffer, &seq, sizeof(seq));

    struct cavs_op_cipher request;
    memset(&request, 0, sizeof(struct cavs_op_cipher));

    request.vector    = enc ? CAVS_VECTOR_XTS_ENC_INIT : CAVS_VECTOR_XTS_DEC_INIT;
    request.cipher    = CAVS_CIPHER_ENC_AES;
    request.mode      = CAVS_CIPHER_MODE_XTS;
    request.target    = testData.testTarget;
    request.aes_is    = cavs_key_to_aes_is([self.keyString UTF8String]);
    request.key_len   = (uint32_t)[testData.key length];
    request.key       = (uint8_t *)[testData.key bytes];
    request.extra_len = CCAES_BLOCK_SIZE;
    request.extra     = tweak_buffer;

    /* Create the context. */
    size_t len = sizeof(uint8_t);
    uint8_t *wksp = NULL;
    int ret = cavs_dispatch(testData.testTarget, request.vector, &request, &wksp, &len);
    if (ret != CAVS_STATUS_OK) {
        errorf("failed cavs_dispatch");
        goto out;
    }

    /* Now that a context has been made, do the work of the cipher. */
    size_t data_in_len = [testData.plainText length];
    size_t nblocks = data_in_len / CCAES_BLOCK_SIZE;
    size_t blocksize = CCAES_BLOCK_SIZE;

    uint8_t *data_in = testData.plainText ? (uint8_t*)[testData.plainText bytes] : NULL;
    uint8_t *data_out = (uint8_t*)malloc(data_in_len);

    /* Reset the structure. */
    memset(&request, 0, sizeof(struct cavs_op_cipher));

    request.vector      = CAVS_VECTOR_XTS_OP;
    request.cipher      = CAVS_CIPHER_ENC_AES;
    request.mode        = CAVS_CIPHER_MODE_XTS;
    request.target      = testData.testTarget;
    request.key_len     = (uint32_t)[testData.key length];
    request.key         = (uint8_t *)[testData.key bytes];
    request.extra_len   = CCAES_BLOCK_SIZE;
    request.extra       = tweak_buffer;
    request.input_len   = CCAES_BLOCK_SIZE;
    request.output_len  = request.input_len;

    // Process a block at a time
    for (int i = 0; i < nblocks; i++) {
        request.input = &data_in[i * blocksize];

        len = request.output_len;
        wksp = NULL;
        ret = cavs_dispatch(testData.testTarget, request.vector, &request, &wksp, &len);
        if (ret != CAVS_STATUS_OK) {
            errorf("failed cavs_dispatch");
            free(data_out);
            goto out;
        }

        memcpy(&data_out[i * blocksize], wksp, request.output_len);
    }

    // Clean up the context
    memset(&request, 0, sizeof(struct cavs_op_cipher));
    request.vector = CAVS_VECTOR_XTS_FINISH;
    request.cipher = CAVS_CIPHER_ENC_AES;
    request.mode   = CAVS_CIPHER_MODE_XTS;
    request.target = testData.testTarget;

    len = sizeof(uint8_t);
    wksp = NULL;
    ret = cavs_dispatch(testData.testTarget, request.vector, &request, &wksp, &len);
    if (ret != CAVS_STATUS_OK) {
        errorf("failed cavs_dispatch");
        free(data_out);
        goto out;
    }

    // print out results
    [self outputFormat:@"COUNT = %d", (uint32_t)counter + 1];

    [self outputFormat:@"DataUnitLen = %d", [testData.dataUnitLen intValue]];
    [self outputFormat:@"Key = %@", DataToHexString(testData.key)];
    [self outputFormat:@"DataUnitSeqNumber = %d", [testData.dataUnitSeqNumber intValue]];
    [self outputFormat:@"%s = %@", enc ? "PT" : "CT", DataToHexString(testData.plainText)];
    [self outputFormat:@"%s = %@", enc ? "CT" : "PT", BufToHexString(data_out, data_in_len)];

    [self outputString:nil];

    result = YES;
    free(data_out);
out:
    return result;
}

@end

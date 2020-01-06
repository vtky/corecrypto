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

#import "CavsMonteCarloHelper.h"

// =============================================================================
// Class implementation MonteCarloHelper
// =============================================================================
#pragma mark MonteCarloHelper

@implementation MonteCarloHelper

@synthesize keyData =       _keyData;
@synthesize ivData =        _ivData;
@synthesize testTarget =    _testTarget;
@synthesize aes_is =        _aes_is;
@synthesize forAES =        _forAES;
@synthesize forEncryption = _forEncryption;
@synthesize fipsMode =      _fipsMode;
@synthesize doUpdate =      _doUpdate;


- (MonteCarloHelper *)initForMode:(TFModeType)mode
    withKeyString:(NSString *)keyString
    withEncryptionCipher:(Encryption_Cipher)cipherType
    forEncryption:(BOOL)forEncryption
    withKey:(NSData *)keyData
    withIV:(NSData *)ivData
    testTarget:(cavs_target)testTarget
{
    if ((self = [super init])) {
        _testTarget = testTarget;
        _kernelConnection = 0;
        _forAES = (cipherType == kAES_Encryption_Cipher);
        _forEncryption = forEncryption;
        _fipsMode = ModeTypeToMode(mode);
        _aes_is = cavs_key_to_aes_is([keyString UTF8String]);

        /* Allocations to free. */
        _keyData = [keyData copy];
        _ivData = [ivData copy];
    }
    return self;
}

- (void)dealloc
{
    [_keyData release];
    [_ivData release];

    [self clearContext];

    [super dealloc];
}

- (BOOL)makeInitRequest:(struct cavs_op_cipher *)request
{
    memset(request, 0, sizeof(struct cavs_op_cipher));
    request->vector = self.forEncryption ? CAVS_VECTOR_MONTECARLO_ENC_INIT : CAVS_VECTOR_MONTECARLO_DEC_INIT;
    request->cipher = self.forAES ? CAVS_CIPHER_ENC_AES : CAVS_CIPHER_ENC_TDES;
    request->mode = self.fipsMode;
    request->target = self.testTarget;
    request->aes_is = self.aes_is;
    request->key_len = (uint32_t)[self.keyData length];
    request->key = (uint8_t *)[self.keyData bytes];

    if (self.ivData != nil) {
        request->extra_len = (uint32_t)[self.ivData length];
        request->extra = (uint8_t *)[self.ivData bytes];
    }

    return YES;
}

- (BOOL)makeOpRequest:(struct cavs_op_cipher *)request input:(NSData *)input
{
    memset(request, 0, sizeof(struct cavs_op_cipher));
    /* Piggyback on the defaults. */
    [self makeInitRequest:request];

    request->vector = self.forEncryption ? CAVS_VECTOR_MONTECARLO_ENC_OP : CAVS_VECTOR_MONTECARLO_DEC_OP;

    // Get the input data
    request->input_len = (uint32_t)[input length];
    request->input = (uint8_t *)[input bytes];

    // Set up room for the output data
    request->output_len = request->input_len;

    return YES;
}

- (BOOL)makeFinishRequest:(struct cavs_op_cipher *)request
{
    memset(request, 0, sizeof(struct cavs_op_cipher));

    request->vector = CAVS_VECTOR_MONTECARLO_FINISH;
    request->cipher = self.forAES ? CAVS_CIPHER_ENC_AES : CAVS_CIPHER_ENC_TDES;
    request->mode = self.fipsMode;
    request->target = self.testTarget;

    return YES;
}

- (BOOL)initializeContext
{
    if (_initialized) {
        return YES;
    }

    // Need to send the init message
    struct cavs_op_cipher request;
    [self makeInitRequest:&request];

    size_t len = 0;
    uint8_t *wksp = NULL;
    int ret = cavs_dispatch(self.testTarget, request.vector, &request, &wksp, &len);
    if (ret != CAVS_STATUS_OK) {
        errorf("failed cavs_dispatch");
        return NO;
    }

    _initialized = YES;

    return _initialized;
}

- (void)clearContext
{
    /* Clear the block to drop the references. */
    self.doUpdate = nil;

    struct cavs_op_cipher request;
    [self makeFinishRequest:&request];

    size_t len = sizeof(uint8_t);
    uint8_t *wksp = NULL;
    int ret = cavs_dispatch(self.testTarget, request.vector, &request, &wksp, &len);
    if (ret != CAVS_STATUS_OK) {
        errorf("failed cavs_dispatch");
    }
}

- (NSData *)update:(NSData*)input
{
    if (input == nil) {
        return nil;
    }

    // ensure that the context for this operation has been set up
    if (!_initialized) {
        if (![self initializeContext]) {
            errorf("unable to initalize context");
            return nil;
        }
    }

    NSData *result = NULL;

    struct cavs_op_cipher request;
    [self makeOpRequest:&request input:input];

    size_t len = request.input_len;
    uint8_t *wksp = NULL;
    int ret = cavs_dispatch(self.testTarget, request.vector, &request, &wksp, &len);
    if (ret != CAVS_STATUS_OK) {
        errorf("failed cavs_dispatch");
        goto out;
    }

    result = [NSData dataWithBytes:wksp length:request.input_len];

out:
    return result;
}

@end

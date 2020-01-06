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

#include "cavs_op_ec25519.h"

/* Included for the various key types. */
#include <corecrypto/ccec25519.h>

#include "CavsCurve25519Test.h"

@interface CavsCurve25519Tests  (PrivateMethods)

- (void)makeRequest:(struct cavs_op_ec25519 *)request
       withTestData:(TestFileData *)testData;

- (void)printGenerateShared:(TestFileData *)testData
                 withPubKey:(NSString *)pubKey
                withPrivKey:(NSString *)privKey
                 withShared:(NSString *)shared;

- (BOOL)runGenerateShared:(TestFileData *)testData
              withCounter:(NSInteger)counter;

- (void)printVerify:(TestFileData *)testData
              wrap1:(NSString *)wrap1
              wrap2:(NSString *)wrap2;

- (BOOL)runVerify:(TestFileData *)testData
      withCounter:(NSInteger)counter;

- (void)printKeyVerify:(TestFileData *)testData
             publicKey:(ccec25519pubkey *)eph_pub_key
                result:(int)valid;

- (BOOL)runKeyVerify:(TestFileData *)testData
         withCounter:(NSInteger)counter;

- (BOOL)runKeyGenerate:(TestFileData *)testData
           withCounter:(NSInteger)counter;

@end

@implementation CavsCurve25519Tests

+ (void)setupTest
{
    return;
}

+ (void)cleanUpTest
{
    return;
}

- (id)initWithFileParser:(TestFileParser *)fileParser
      withTestDictionary:(NSDictionary *)testsToRun
{
    self = [super initWithFileParser:fileParser withTestDictionary:testsToRun];
    return self;
}

- (void)makeRequest:(struct cavs_op_ec25519*)request
       withTestData:(TestFileData *)testData
{
    memset(request, 0, sizeof(struct cavs_op_ec25519));
    switch(testData.testType) {
    case TTECDHCurve25519GenerateShared: 	request->vector = CAVS_VECTOR_EC25519_GENERATE_SHARED; break;
    case TTECDHCurve25519VerifyShared: 		request->vector = CAVS_VECTOR_EC25519_VERIFY_SHARED;   break;
    case TTECDHCurve25519KeyGenerate: 		request->vector = CAVS_VECTOR_EC25519_GENERATE_KEY;    break;
    case TTECDHCurve25519KeyVerify: 		request->vector = CAVS_VECTOR_EC25519_VERIFY_KEY;      break;
    }
    request->curve = CipherTypeToCurve(testData.cipherType);
    request->pub_key_len = (uint32_t)[testData.classBStaticPubKey length];
    request->pub_key = (uint8_t *)[testData.classBStaticPubKey bytes];
    request->priv_key_len = (uint32_t)[testData.classBStaticPrivKey length];
    request->priv_key = (uint8_t *)[testData.classBStaticPrivKey bytes];
    request->eph_pub_key_len = (uint32_t)[testData.classBEphemPubKey length];
    request->eph_pub_key = (uint8_t *)[testData.classBEphemPubKey bytes];
    request->eph_priv_key_len = (uint32_t)[testData.classBEphemPrivKey length];
    request->eph_priv_key = (uint8_t *)[testData.classBEphemPrivKey bytes];
    request->shared_len = (uint32_t)[testData.classBSharedSecret length];
    request->shared = (uint8_t *)[testData.classBSharedSecret bytes];
}

- (void)printGenerateShared:(TestFileData *)testData
                 withPubKey:(NSString *)pubKey
                withPrivKey:(NSString *)privKey
                 withShared:(NSString *)shared
{ 
    [self outputFormat:@"Static-PublicKey = %@", DataToHexString(testData.classBStaticPubKey)];
    [self outputFormat:@"Static-PrivateKey = %@", DataToHexString(testData.classBStaticPrivKey)];
    [self outputFormat:@"Ephemeral-PublicKey = %@", pubKey];
    [self outputFormat:@"Ephemeral-PrivateKey = %@", privKey];
    [self outputFormat:@"Shared-Secret = %@", shared];
    [self outputString:nil];
}

- (BOOL)runGenerateShared:(TestFileData *)testData
                    withCounter:(NSInteger)counter
{
    struct cavs_op_ec25519 request;
    [self makeRequest:&request withTestData:testData];
    BOOL result = NO;

    size_t len = sizeof(ccec25519pubkey) + 3 * sizeof(ccec25519secretkey);
    uint8_t *wksp = NULL;
    int ret = cavs_dispatch(testData.testTarget, request.vector, &request, &wksp, &len);
    if (ret != CAVS_STATUS_OK) {
        errorf("failed cavs_dispatch");
        goto out;
    }

    ccec25519pubkey *pub_key = (ccec25519pubkey *)wksp;
    ccec25519secretkey *eph_priv_key = (ccec25519secretkey *)(pub_key + 1);
    ccec25519secretkey *wrapping_key1 = eph_priv_key + 1;

    // Output all of our results as required
    [self printGenerateShared:testData withPubKey:BufToHexString((uint8_t *)pub_key, sizeof(ccec25519pubkey))
            withPrivKey:BufToHexString((uint8_t *)eph_priv_key, sizeof(ccec25519secretkey))
            withShared:BufToHexString((uint8_t *)wrapping_key1, sizeof(ccec25519secretkey))];

    result = YES;
out:
    return result;
}

- (void)printVerify:(TestFileData *)testData
              result:(int)valid
{
    [self outputFormat:@"Static-PublicKey = %@", DataToHexString(testData.classBStaticPubKey)];
    [self outputFormat:@"Static-PrivateKey = %@", DataToHexString(testData.classBStaticPrivKey)];
    [self outputFormat:@"Ephemeral-PublicKey = %@", DataToHexString(testData.classBEphemPubKey)];
    [self outputFormat:@"Ephemeral-PrivateKey = %@", DataToHexString(testData.classBEphemPrivKey)];
    [self outputFormat:@"Shared-Secret = %@", DataToHexString(testData.classBSharedSecret)];

    if (valid) {
        [self outputString:@"Result = P"];
    } else {
        [self outputString:@"Result = F"];
    }

    [self outputString:nil];
}

- (BOOL)runVerify:(TestFileData*)testData
            withCounter:(NSInteger)counter
{
    struct cavs_op_ec25519 request;
    [self makeRequest:&request withTestData:testData];

    size_t len = sizeof(uint32_t);
    uint8_t *wksp = NULL;
    int ret = cavs_dispatch(testData.testTarget, request.vector, &request, &wksp, &len);
    if (ret != CAVS_STATUS_OK) {
        errorf("failed cavs_dispatch");
        return NO;
    }

    [self printVerify:testData result:*(uint32_t *)wksp];

    return YES;
}

- (void)printKeyVerify:(TestFileData *)testData
           publicKey:(ccec25519pubkey *)key
                result:(int)valid
{
    [self outputFormat:@"Static-PublicKey = %@",DataToHexString(testData.classBStaticPubKey)];
    [self outputFormat:@"Static-PrivateKey = %@", DataToHexString(testData.classBStaticPrivKey)];
    [self outputFormat:@"Ephemeral-PublicKey = %@", BufToHexString((uint8_t *)key, sizeof(ccec25519pubkey))];

    if (valid) {
        [self outputString:@"Result = P"];
    } else {
        [self outputString:@"Result = F"];
    }
    [self outputString:nil];
}

- (BOOL)runKeyVerify:(TestFileData *)testData
               withCounter:(NSInteger)counter
{
    struct cavs_op_ec25519 request;
    [self makeRequest:&request withTestData:testData];

    size_t len = sizeof(ccec25519pubkey) + sizeof(uint32_t);
    uint8_t *wksp = NULL;
    int ret = cavs_dispatch(testData.testTarget, request.vector, &request, &wksp, &len);
    if (ret != CAVS_STATUS_OK) {
        errorf("failed cavs_dispatch");
        return NO;
    }

    [self printKeyVerify:testData publicKey:(ccec25519pubkey *)wksp
            result:*(uint32_t *)((ccec25519pubkey *)wksp + 1)];

    return YES;
}

- (BOOL)runKeyGenerate:(TestFileData *)testData
                 withCounter:(NSInteger)counter
{
    for (int i = 0; i < [testData.numKeys intValue]; i++) {
        struct cavs_op_ec25519 request;
        [self makeRequest:&request withTestData:testData];

        size_t len = sizeof(ccec25519pubkey) + sizeof(ccec25519secretkey);
        uint8_t *wksp = NULL;
        int ret = cavs_dispatch(testData.testTarget, request.vector, &request, &wksp, &len);
        if (ret != CAVS_STATUS_OK) {
            errorf("failed cavs_dispatch");
            return NO;
        }

        ccec25519pubkey *pub_key = (ccec25519pubkey *)wksp;
        ccec25519secretkey *secret_key = (ccec25519secretkey *)(pub_key + 1);

        [self outputFormat:@"Static-PublicKey = %@", BufToHexString((uint8_t *)pub_key, sizeof(ccec25519pubkey))];
        [self outputFormat:@"Static-PrivateKey = %@", BufToHexString((uint8_t *)secret_key, sizeof(ccec25519secretkey))];
        [self outputString:nil];
    }

    return YES;
}

- (BOOL)runTest:(TestFileData *)testData withCounter:(NSInteger)counter
{
    switch(testData.testType) {
    case TTECDHCurve25519GenerateShared: 	return [self runGenerateShared:testData withCounter:counter];
    case TTECDHCurve25519VerifyShared: 		return [self runVerify:testData withCounter:counter];
    case TTECDHCurve25519KeyGenerate: 		return [self runKeyGenerate:testData withCounter:counter];
    case TTECDHCurve25519KeyVerify: 		return [self runKeyVerify:testData withCounter:counter];
    default:
        break;
    }

    errorf("unsupported vector");

    return NO;
}

@end

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

#import "CavsECTests.h"
#import "CavsTestDispatcher.h"

#include "cavs_op_ec_pkv.h"
#include "cavs_op_ec_key_gen.h"
#include "cavs_op_ec_sig_gen.h"
#include "cavs_op_ec_sig_gen_comp.h"
#include "cavs_op_ec_sig_verify.h"
#include "cavs_op_ec_val_init.h"
#include "cavs_op_ec_val_resp.h"
#include "cavs_op_ec_func.h"

/* Utility functions for determing result lengths. */
#include "cavs_vector_ec.h"

/* ==========================================================================
    Private Methods for the CavsECTests class
   ========================================================================== */
@interface CavsECTests  (PrivateMethods)

- (void)printOnePassTest:(TestFileData *)testData
                initiate:(BOOL)initiate
                     ret:(int)ret
        computed_key_len:(size_t)computed_key_len
            computed_key:(uint8_t *)computed_key
               out_x_len:(size_t)out_x_len
                   out_x:(uint8_t *)out_x
                out_y_len:(size_t)out_y_len
                   out_y:(uint8_t *)out_y;

- (BOOL)runOnePassTest:(TestFileData *)testData
          withCounter:(NSInteger)counter
             initiate:(BOOL)initiate;

- (void) printValidityResults:(TestFileData *)testData
                      counter:(NSInteger)counter
                     initiate:(BOOL)initiate
                          ret:(int)ret
             computed_key_len:(size_t)computed_key_len
                 computed_key:(uint8_t *)computed_key;

- (BOOL) runValidityTest:(TestFileData *)testData
             withCounter:(NSInteger)counter
                initiate:initiate;

- (BOOL)runKeyGenTest:(TestFileData *)testData
          withCounter:(NSInteger)counter;

- (BOOL)runPKVerifyTest:(TestFileData *)testData
            withCounter:(NSInteger)counter;

- (BOOL)runSigGenTest:(TestFileData *)testData
          withCounter:(NSInteger)counter;

- (BOOL)runSigVerTest:(TestFileData *)testData
          withCounter:(NSInteger)counter;

@end


@implementation CavsECTests

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
    return [super initWithFileParser:fileParser withTestDictionary:testsToRun];
}

- (BOOL)runTest:(TestFileData *)testData withCounter:(NSInteger)counter
{
    BOOL result = NO;
    BOOL initiate;

    if (testData == nil) return result;

    if ([testData.fileName rangeOfString:@"resp.req"].length > 0) {
        initiate = NO;
    } else {
        initiate = YES;
    }

    TFTestType testType = testData.testType;
    switch(testType) {
    case TTECKeyGeneration:
        result = [self runKeyGenTest:testData withCounter:counter];
        break;

    case TTECPublicKeyVerification:
        result = [self runPKVerifyTest:testData withCounter:counter];
        break;

    case TTECSignatureGeneration:
    case TTECSignatureGenerationComponent:
        result = [self runSigGenTest:testData withCounter:counter];
        break;

    case TTECSignatureVerification:
        result = [self runSigVerTest:testData withCounter:counter];
        break;

    case TTECDHPrimFuncOnePassDH:
        result = [self runOnePassTest:testData withCounter:counter initiate:initiate];
        break;

    case TTECDHPrimValOnePassDH:
        result = [self runValidityTest:testData withCounter:counter initiate:initiate];
        break;

    default:
        errorf("Unknown EC Test Type");
        break;
    }

    return result;
}

- (void)printOnePassTest:(TestFileData *)testData
                initiate:(BOOL)initiate
                     ret:(int)ret
        computed_key_len:(size_t)computed_key_len
            computed_key:(uint8_t *)computed_key
               out_x_len:(size_t)out_x_len
                   out_x:(uint8_t *)out_x
               out_y_len:(size_t)out_y_len
                   out_y:(uint8_t *)out_y
{
    NSData *qx = initiate ? testData.QsX : testData.QeX;
    NSData *qy = initiate ? testData.QsY : testData.QeY;

    char mod = initiate ? 's' : 'e';
    char alt = initiate ? 'e' : 's';

    [self outputFormat:@"Q%cCAVSx = %@", mod, DataToHexString(qx)];
    [self outputFormat:@"Q%cCAVSy = %@", mod, DataToHexString(qy)];

    if (ret == CAVS_STATUS_OK) {
        [self outputFormat:@"Q%cIUTx = %@", alt, BufToHexString(out_x, out_x_len)];
        [self outputFormat:@"Q%cIUTy = %@", alt, BufToHexString(out_y, out_y_len)];
    }
    [self outputFormat:@"HashZZ = %@", BufToHexString(computed_key, computed_key_len)];

    [self outputString:nil];
}

- (BOOL) runOnePassTest:(TestFileData *)testData
            withCounter:(NSInteger)counter
               initiate:(BOOL)initiate
{
    NSData *qx = initiate ? testData.QsX : testData.QeX;
    NSData *qy = initiate ? testData.QsY : testData.QeY;

    struct cavs_op_ec_func request;
    memset(&request, 0, sizeof(request));
    request.vector = CAVS_VECTOR_EC_FUNC;
    request.key_sz = (uint32_t)[testData.curve integerValue];
    request.pub_x_len = (uint32_t)[qx length];
    request.pub_x = (uint8_t *)[qx bytes];
    request.pub_y_len = (uint32_t)[qy length];
    request.pub_y = (uint8_t *)[qy bytes];

    size_t exp_key_len = cavs_vector_ec_get_key_len(request.key_sz);
    size_t exp_result_len = cavs_vector_ec_get_prime_len(request.key_sz);

    size_t len = sizeof(uint8_t) +                      /* ret */
        sizeof(uint32_t) +                              /* out_key_len */
        exp_key_len +                                   /* out_key */
        sizeof(uint32_t) +                              /* out_x_len */
        exp_result_len +                                /* out_x */
        sizeof(uint32_t) +                              /* out_y_len */
        exp_result_len;                                 /* out_y */
    uint8_t *wksp = NULL;
    uint8_t ret = cavs_dispatch(testData.testTarget, request.vector, &request, &wksp, &len);
    if (ret != CAVS_STATUS_OK) {
        errorf("failed cavs_dispatch");
        return NO;
    }

    /* Unpack the results from the returned buffer. */
    ret = *(uint8_t *)wksp;
    uint32_t *key_len = (uint32_t *)(wksp + 1);
    uint8_t *key = (uint8_t *)(key_len + 1);
    uint32_t *out_x_len = (uint32_t *)(key + *key_len);
    uint8_t *out_x = (uint8_t *)(out_x_len + 1);
    uint32_t *out_y_len = (uint32_t *)(out_x + *out_x_len);
    uint8_t *out_y = (uint8_t *)(out_y_len + 1);

    if (*key_len != exp_key_len) {
        errorf("key expectations not matched, expected %zu, got %d", exp_key_len, *key_len);
        return NO;
    }

    if (*out_x_len != exp_result_len || *out_y_len != exp_result_len) {
        errorf("key expectations not matched, expected %zu, got %d, %d",
                exp_result_len, *out_x_len, *out_y_len);
        return NO;
    }

    /* Output the results. */
    [self printOnePassTest:testData initiate:initiate ret:ret
        computed_key_len:*key_len computed_key:key
            out_x_len:*out_x_len out_x:out_x out_y_len:*out_y_len out_y:out_y];

    return YES;
}

- (void) printValidityResults:(TestFileData *)testData
                      counter:(NSInteger)counter
                     initiate:(BOOL)initiate
                          ret:(int)ret
             computed_key_len:(size_t)computed_key_len
                 computed_key:(uint8_t *)computed_key
{
    char mod;
    char alt;
    NSData *qx;
    NSData *qy;
    NSData *dIUT;
    NSData *qIUTx;
    NSData *qIUTy;

    if (initiate) {
        mod = 's';
        alt = 'e';
        qx = testData.QsX;
        qy = testData.QsY;
        dIUT = testData.deIUT;
        qIUTx = testData.QeIUTx;
        qIUTy = testData.QeIUTy;
    } else {
        mod = 'e';
        alt = 's';
        qx = testData.QeX;
        qy = testData.QeY;
        dIUT = testData.dsIUT;
        qIUTx = testData.QsIUTx;
        qIUTy = testData.QsIUTy;
    }

    [self outputFormat:@"COUNT = %@",   @(counter).stringValue];
    [self outputFormat:@"Q%cCAVSx = %@", mod, DataToHexString(qx)];
    [self outputFormat:@"Q%cCAVSy = %@", mod, DataToHexString(qy)];
    [self outputFormat:@"d%cIUT = %@",   alt, DataToHexString(dIUT)];
    [self outputFormat:@"Q%cIUTx = %@",  alt, DataToHexString(qIUTx)];
    [self outputFormat:@"Q%cIUTy = %@",  alt, DataToHexString(qIUTy)];
    [self outputFormat:@"CAVSHashZZ = %@", DataToHexString(testData.HashZZ)];
    [self outputFormat:@"IUTHashZZ = %@", BufToHexString(computed_key, computed_key_len)];
    if (ret != CAVS_STATUS_OK || computed_key_len != [testData.HashZZ length] ||
            memcmp([testData.HashZZ bytes], computed_key, computed_key_len)) {
        [self outputString:@"Result = F"];
    } else {
        [self outputString:@"Result = P"];
    }

    [self outputString:nil];
}

- (BOOL) runValidityTest:(TestFileData *)testData
             withCounter:(NSInteger)counter
                initiate:initiate
{
    uint32_t key_sz = (uint32_t)[testData.curve integerValue];
    size_t exp_key_len = cavs_vector_ec_get_key_len(key_sz);

    /* Result, key_len, and key. */
    size_t len = sizeof(uint8_t) + sizeof(uint32_t) + exp_key_len;
    uint8_t *wksp = NULL;
    uint8_t ret;

    if (initiate) {
        struct cavs_op_ec_val_init request;
        memset(&request, 0, sizeof(request));
        request.key_sz = key_sz;
        request.vector = CAVS_VECTOR_EC_VAL_INIT;
        request.rng_len = (uint32_t)[testData.deIUT length];
        request.rng = (uint8_t *)[testData.deIUT bytes];
        request.pub_x_len = (uint32_t)[testData.QsX length];
        request.pub_x = (uint8_t *)[testData.QsX bytes];
        request.pub_y_len = (uint32_t)[testData.QsY length];
        request.pub_y = (uint8_t *)[testData.QsY bytes];
        ret = cavs_dispatch(testData.testTarget, request.vector, &request, &wksp, &len);
    } else {
        struct cavs_op_ec_val_resp request;
        memset(&request, 0, sizeof(request));
        request.key_sz = key_sz;
        request.vector = CAVS_VECTOR_EC_VAL_RESP;
        request.rng_len = (uint32_t)[testData.dsIUT length];
        request.rng = (uint8_t *)[testData.dsIUT bytes];
        request.pub_x_len = (uint32_t)[testData.QeX length];
        request.pub_x = (uint8_t *)[testData.QeX bytes];
        request.pub_y_len = (uint32_t)[testData.QeY length];
        request.pub_y = (uint8_t *)[testData.QeY bytes];
        request.priv_x_len = (uint32_t)[testData.QsIUTx length];
        request.priv_x = (uint8_t *)[testData.QsIUTx bytes];
        request.priv_y_len = (uint32_t)[testData.QsIUTy length];
        request.priv_y = (uint8_t *)[testData.QsIUTy bytes];
        request.priv_k_len = (uint32_t)[testData.dsIUT length];
        request.priv_k = (uint8_t *)[testData.dsIUT bytes];
        ret = cavs_dispatch(testData.testTarget, request.vector, &request, &wksp, &len);
    }
    if (ret != CAVS_STATUS_OK) {
        errorf("failed cavs_dispatch");
        return NO;
    }

    /* Unpack the results from the returned buffer. */
    ret = *(uint8_t *)wksp;
    uint32_t *key_len = (uint32_t *)(wksp + 1);
    uint8_t *key = (uint8_t *)(key_len+ 1);

    if (*key_len != exp_key_len) {
        errorf("expectations not matched");
        return NO;
    }

    /* Output the results. */
    [self printValidityResults:testData counter:counter initiate:initiate ret:ret
        computed_key_len:(size_t)*key_len computed_key:key];

    return YES;
}

- (BOOL)runKeyGenTest:(TestFileData *)testData
          withCounter:(NSInteger)counter
{
    int gen_count = (int)[testData.nValue integerValue];

    for (int i = 0; i < gen_count; i++) {
        struct cavs_op_ec_key_gen request;
        memset(&request, 0, sizeof(request));
        request.vector = CAVS_VECTOR_EC_KEY_GEN;
        request.digest = CipherTypeToDigest(testData.ecDigestType);
        request.key_sz = (uint32_t)[testData.curve integerValue];

        size_t len = sizeof(uint32_t) * 3 + CAVS_OP_EC_KEY_GEN_LEN * 3;
        uint8_t *wksp = NULL;
        int ret = cavs_dispatch(testData.testTarget, request.vector, &request, &wksp, &len);
        if (ret != CAVS_STATUS_OK) {
            errorf("failed cavs_dispatch");
            return NO;
        }

        uint32_t *x, *y, *d;
        uint8_t *xp, *yp, *dp;

        x = (uint32_t *)wksp;
        y = x + 1;
        d = y + 1;
        xp = (uint8_t *)(d + 1);
        yp = xp + CAVS_OP_EC_KEY_GEN_LEN;
        dp = yp + CAVS_OP_EC_KEY_GEN_LEN;

        /* Output results. */
        [self outputFormat:@"d = %@", BufToHexString(dp, *d)];
        [self outputFormat:@"Qx = %@", BufToHexString(xp, *x)];
        [self outputFormat:@"Qy = %@", BufToHexString(yp, *y)];
        [self outputString:nil];
    }

    return YES;
}

- (BOOL)runPKVerifyTest:(TestFileData *)testData
            withCounter:(NSInteger)counter
{
    struct cavs_op_ec_pkv request;
    memset(&request, 0, sizeof(request));
    request.vector = CAVS_VECTOR_EC_PKV;
    request.key_sz = (uint32_t)[testData.curve integerValue];
    request.qx_len = (uint32_t)[testData.qX length];
    request.qx = (uint8_t *)[testData.qX bytes];
    request.qy_len = (uint32_t)[testData.qY length];
    request.qy = (uint8_t *)[testData.qY bytes];

    size_t len = sizeof(int32_t);
    uint8_t *wksp = NULL;
    int ret = cavs_dispatch(testData.testTarget, request.vector, &request, &wksp, &len);
    if (ret != CAVS_STATUS_OK) {
        errorf("failed cavs_dispatch");
        return NO;
    }

    [self outputFormat:@"Qx = %@", DataToHexString(testData.qX)];
    [self outputFormat:@"Qy = %@", DataToHexString(testData.qY)];
    [self outputFormat:@"Result = %@", *((int32_t *)wksp) ? @"Passed" : @"Failed"];
    [self outputString:nil];

    return YES;
}

- (BOOL)runSigGenTest:(TestFileData *)testData withCounter:(NSInteger)counter
{
    size_t len = 0;
    uint8_t *wksp = NULL;
    int ret;

    if (testData.testType == TTECSignatureGeneration) {
        struct cavs_op_ec_sig_gen request;
        memset(&request, 0, sizeof(request));
        request.vector = CAVS_VECTOR_EC_SIG_GEN;
        request.digest = CipherTypeToDigest(testData.ecDigestType);
        request.key_sz = (uint32_t)[testData.curve integerValue];
        request.message_len = (uint32_t)[testData.msg length];
        request.message = (uint8_t *)[testData.msg bytes];
        ret = cavs_dispatch(testData.testTarget, request.vector, &request, &wksp, &len);
    } else {
        struct cavs_op_ec_sig_gen_comp request;
        memset(&request, 0, sizeof(request));
        request.vector = CAVS_VECTOR_EC_SIG_GEN_COMP;
        request.digest = CipherTypeToDigest(testData.ecDigestType);
        request.key_sz = (uint32_t)[testData.curve integerValue];
        request.qx_len = (uint32_t)[testData.qX length];
        request.qx = (uint8_t *)[testData.qX bytes];
        request.qy_len = (uint32_t)[testData.qY length];
        request.qy = (uint8_t *)[testData.qY bytes];
        request.message_len = (uint32_t)[testData.msg length];
        request.message = (uint8_t *)[testData.msg bytes];
        ret = cavs_dispatch(testData.testTarget, request.vector, &request, &wksp, &len);
    }
    if (ret != CAVS_STATUS_OK) {
        errorf("failed cavs_dispatch");
        return NO;
    }

    /* This format of len:buf is inconsistently followed elsewhere, alas. */
#define CAVS_EC_PRINT_BUFFER(KEY)                                           \
    len = *(uint32_t *)wksp;                                                \
    wksp += sizeof(uint32_t);                                               \
    [self outputFormat:@"%s = %@", KEY, BufToHexString(wksp, len)];         \
    wksp += len;

    [self outputFormat:@"Msg = %@", DataToHexString(testData.msg)];
    CAVS_EC_PRINT_BUFFER("Qx");
    CAVS_EC_PRINT_BUFFER("Qy");
    CAVS_EC_PRINT_BUFFER("R");
    CAVS_EC_PRINT_BUFFER("S");
#undef CAVS_EC_PRINT_BUFFER

    [self outputString:nil];

    return YES;
}

- (BOOL)runSigVerTest:(TestFileData *)testData
          withCounter:(NSInteger)counter
{
    struct cavs_op_ec_sig_verify request;
    memset(&request, 0, sizeof(request));
    request.vector = CAVS_VECTOR_EC_SIG_VERIFY;
    request.digest = CipherTypeToDigest(testData.ecDigestType);
    request.key_sz = (uint32_t)[testData.curve integerValue];
    request.qx_len = (uint32_t)[testData.qX length];
    request.qx = (uint8_t *)[testData.qX bytes];
    request.qy_len = (uint32_t)[testData.qY length];
    request.qy = (uint8_t *)[testData.qY bytes];
    request.r_len = (uint32_t)[testData.capitalRData length];
    request.r = (uint8_t *)[testData.capitalRData bytes];
    request.s_len = (uint32_t)[testData.sData length];
    request.s = (uint8_t *)[testData.sData bytes];
    request.message_len = (uint32_t)[testData.msg length];
    request.message = (uint8_t *)[testData.msg bytes];

    size_t len = sizeof(uint8_t);
    uint8_t *wksp = NULL;
    int ret = cavs_dispatch(testData.testTarget, request.vector, &request, &wksp, &len);
    if (ret != CAVS_STATUS_OK) {
        errorf("failed cavs_dispatch");
        return NO;
    }

    // Time to print out the results;
    [self outputFormat:@"Msg = %@", DataToHexString(testData.msg)];
    [self outputFormat:@"Qx = %@", DataToHexString(testData.qX)];
    [self outputFormat:@"Qy = %@", DataToHexString(testData.qY)];
    [self outputFormat:@"R = %@", DataToHexString(testData.capitalRData)];
    [self outputFormat:@"S = %@", DataToHexString(testData.sData)];
    [self outputFormat:@"Result = %@", *(uint8_t *)wksp ? @"Passed" : @"Failed"];

    [self outputString:nil];

    return YES;
}

@end

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

#include <stdlib.h>
#include <corecrypto/cc_config.h>
#include "cavs_common.h"

#import "CavsUtil.h"
#import "CavsTestFileParser.h"
#import "CavsTest.h"

/* --------------------------------------------------------------------------
    Externally supplied prototypes
 -------------------------------------------------------------------------- */
NSString* DataToHexString(NSData* data);
NSString* BufToHexString(uint8_t* data, size_t len);

/* --------------------------------------------------------------------------
    Local Function prototypes
 -------------------------------------------------------------------------- */
static NSString* escapeString(NSString* str);
static NSString* testToJson(TestFileData* data, BOOL includeData);
static NSString* jsonKeyValue(NSString* key, NSString* value);
static NSString* jsonArray(NSArray* array);

/* --------------------------------------------------------------------------
    Method:         escapeString
    Description:    Perform some minimal escaping for " characters.
 -------------------------------------------------------------------------- */
NSString* escapeString(NSString* str)
{
    return [NSString stringWithFormat:@"\"%@\"", [str stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""]];
}

/* --------------------------------------------------------------------------
    Method:         jsonKeyValue
    Description:    Convert a supplied pair of strings into JSON key-values.
 -------------------------------------------------------------------------- */
NSString* jsonKeyValue(NSString* key, NSString* value)
{
    return [NSString stringWithFormat:@"%@: %@", escapeString(key), value];
}

/* --------------------------------------------------------------------------
    Method:         jsonArray
    Description:    Return a string, including surrounding [], of the array in
                    JSON format.
 -------------------------------------------------------------------------- */
NSString* jsonArray(NSArray* array)
{
    NSMutableArray* result = [[NSMutableArray alloc] init];
    for (id entry in array) {
        if ([entry isKindOfClass:[NSString class]]) {
            if ([entry length] > 0) {
                [result addObject:[NSString stringWithFormat:@"%@", escapeString(entry)]];
            }
        } else if ([entry isKindOfClass:[NSData class]]) {
            if ([entry length] > 0) {
                [result addObject:[NSString stringWithFormat:@"%@", escapeString(DataToHexString(entry))]];
            }
        } else {
            assert(false);
        }
    }
    NSString* retval = [NSString stringWithFormat:@"[%@]", [result componentsJoinedByString:@","]];
    [result release];

    return retval;
}

/* --------------------------------------------------------------------------
    Method:         testToJson
    Description:    Print current TestFileData to a NSString in JSON.
 -------------------------------------------------------------------------- */
NSString* testToJson(TestFileData* data, BOOL includeData)
{
    // Declare a set of utility macros specific to this function to help construct
    // the desired string.
#define ADD_STR(K) if (nil != data->K) {[result addObject:jsonKeyValue(@#K, escapeString(data->K))]; }
#define ADD_ENUM(K) if (0 != data->K) { [result addObject:jsonKeyValue(@#K, [NSString stringWithFormat:@"%ld", (long)data->K])]; }
#define ADD_BOOL(K)     [result addObject:jsonKeyValue(@#K, [NSString stringWithFormat:@"%ld", (long)data->K])]
#define ADD_NUM(K)  if (nil != data->K) {[result addObject:jsonKeyValue(@#K, [NSString stringWithFormat:@"%@", data->K])];}
#define ADD_ARRAY(K) if (nil != data->K && [data->K count] > 0) { [result addObject:jsonKeyValue(@#K, jsonArray(data->K))]; }
#define ADD_DATA(K) if (nil != data->K) {[result addObject:jsonKeyValue(@#K, includeData ? escapeString(DataToHexString(data->K)) : @"\"_\"")];}

    // Place the contents in a mutable array, for collapsing into a single string at the end
    NSMutableArray* result = [[NSMutableArray alloc] init];

    // Add the contents of each variable in the TestFileData structure
    ADD_ENUM(_testType);
    ADD_ENUM(_modeType);
    ADD_ENUM(_cipherType);
    ADD_ENUM(_ecDigestType);
    ADD_BOOL(_encryption);
    ADD_BOOL(_monteCarlo);
    ADD_BOOL(_predictionResistance);
    ADD_BOOL(_singleTDESKey);
    ADD_ARRAY(_testEnvironmentData);
    ADD_DATA(_key);
    ADD_NUM(_numKeys);
    ADD_DATA(_key2);
    ADD_DATA(_key3);
    ADD_DATA(_tDESKey);
    ADD_DATA(_iv);
    ADD_DATA(_plainText);
    ADD_NUM(_length);
    ADD_DATA(_entropyInput);
    ADD_DATA(_nonce);
    ADD_DATA(_personalizationString);

    ADD_ARRAY(_additionalInput);
    ADD_ARRAY(_additionalEntropyInput);

    ADD_NUM(_klen);
    ADD_NUM(_tlen);
    ADD_NUM(_plen);
    ADD_NUM(_nlen);
    ADD_NUM(_alen);
    ADD_DATA(_msg);
    ADD_ENUM(_shaAlgo);
    ADD_NUM(_groupLen);
    ADD_DATA(_groupSeed);
    ADD_DATA(_nData);
    ADD_DATA(_eData);
    ADD_DATA(_sData);
    ADD_NUM(_modulus);

    ADD_DATA(_dtData);
    ADD_DATA(_vData);
    ADD_DATA(_capitalNData);
    ADD_DATA(_capitalPData);
    ADD_DATA(_capitalQData);
    ADD_DATA(_capitalGData);
    ADD_DATA(_capitalYData);
    ADD_DATA(_capitalRData);
    ADD_DATA(_xp1);
    ADD_DATA(_xp2);
    ADD_DATA(_xp);
    ADD_DATA(_xq1);
    ADD_DATA(_xq2);
    ADD_DATA(_xq);
    ADD_DATA(_prnd);
    ADD_DATA(_qrnd);

    ADD_DATA(_QeX);
    ADD_DATA(_QeY);
    ADD_DATA(_QsX);
    ADD_DATA(_QsY);
    ADD_DATA(_deIUT);
    ADD_DATA(_QeIUTx);
    ADD_DATA(_QeIUTy);
    ADD_DATA(_dsIUT);
    ADD_DATA(_QsIUTx);
    ADD_DATA(_QsIUTy);
    ADD_DATA(_HashZZ);
    ADD_DATA(_OI);
    ADD_DATA(_CAVSTag);

    ADD_STR(_resultFieldName);
    ADD_DATA(_result);
    ADD_NUM(_rsaKeySize);
    ADD_NUM(_ecDigestSize);
    ADD_BOOL(_rsaKeySizeChanged);

    ADD_DATA(_aData);
    ADD_NUM(_ivLen);
    ADD_NUM(_tagLength);
    ADD_DATA(_tag);
    ADD_STR(_fileName);
    ADD_NUM(_nValue);
    ADD_DATA(_qX);
    ADD_DATA(_qY);
    ADD_NUM(_curve);
    ADD_DATA(_rData);
    ADD_BOOL(_printNData);
    ADD_ENUM(_aesImplType);
    ADD_ENUM(_rsaSigType);
    ADD_ENUM(_rsaKeyGenType);
    ADD_ENUM(_ecKeyGenType);
    ADD_NUM(_dataUnitSeqNumber);
    ADD_NUM(_dataUnitLen);

    ADD_DATA(_classBStaticPrivKey);
    ADD_DATA(_classBStaticPubKey);
    ADD_DATA(_classBEphemPrivKey);
    ADD_DATA(_classBEphemPubKey);
    ADD_DATA(_classBSharedSecret);

    ADD_STR(_keyString);
    ADD_ENUM(_testTarget);

    NSString* retval = [result componentsJoinedByString:@","];

    [result release];

    return retval;
#undef ADD_STR
#undef ADD_ENUM
#undef ADD_BOOL
#undef ADD_NUM
#undef ADD_ARRAY
#undef ADD_DATA
}

/* --------------------------------------------------------------------------
    Method:         logTests
    Description:    Iterate over the supplied dictionary, outputting the
                    contents in JSON format.

                    Call by adding these lines to the top of runTests:
                      void logTests(NSString* path, NSDictionary* testsToRun);
                      logTests(@"/tmp/test_dump.json", self.testsToRun);
 -------------------------------------------------------------------------- */

void logTests(NSString* path, NSDictionary* testsToRun)
{
    NSArray* fileNames = [testsToRun allKeys];
    BOOL fnFirst = YES;
    BOOL grFirst = YES;
    BOOL first = YES;

    // Open the file and place the initial opening bracket
    FILE* tgt = fopen([path UTF8String], "w");
    fprintf(tgt, "{");

    // Over each filename, create the appropriate objects for the tests
    // contained in that file.
    //
    // Example output:
    //
    //   {
    //     "somefile.req" : {
    //       "hdr": [ .. header lines .. ],                     // Primarily the # lines at the top of the file.
    //       "tests": [
    //         {                                                // One object for each TestGroup
    //           "env": [ .. environment variable lines .. ],   // Whatever [] variables were specified for this test
    //           "test": [                                      // Each TestFileData object for this TestGroup
    //             { .. contents of the TestFileData .. },
    //             { .. contents of the TestFileData .. },
    //             ...
    //           ]
    //         }, ...
    //       ]
    //     },
    //     "otherfile.req" : { ... },
    //     ...
    //   }
    for (NSString* fileName in fileNames) {
        fprintf(tgt, "%s\n%s: { \"hdr\": [", fnFirst ? "" : ",", [escapeString(fileName) UTF8String]);
        NSDictionary* fileDictionary = [testsToRun objectForKey:fileName];

        first = YES;
        for (NSString* hdr in [fileDictionary objectForKey:TFFileHeaderKey]) {
            if ([hdr length] > 0) {
                fprintf(tgt, "%s%s", first ? "" : ",", [escapeString(hdr) UTF8String]);
                first = NO;
            }
        }

        fprintf(tgt, "], \"tests\": [");

        grFirst = YES;
        for (NSDictionary* group in [fileDictionary objectForKey:TFTestGroupKey]) {
            fprintf(tgt, "%s{\"env\": [", grFirst ? "" : ",");

            first = YES;
            for (NSString* env in [group objectForKey:TFEnvironmentDataKey]) {
                if ([env length] > 0) {
                    fprintf(tgt, "%s%s", first ? "" : ",", [escapeString(env) UTF8String]);
                    first = NO;
                }
            }
            fprintf(tgt, "], \"test\": [");

            first = YES;
            for (TestFileData* data in [group objectForKey:TFTestKey]) {
                fprintf(tgt, "%s{%s}", first ? "" : ",", [testToJson(data, YES) UTF8String]);
                first = NO;
            }
            fprintf(tgt, "]}");
            grFirst = NO;
        }
        fprintf(tgt, "]}");
        fnFirst = NO;
    }
    fprintf(tgt, "\n}");
    fclose(tgt);
}

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

#import <IOKit/IOKitLib.h>
#import <mach/vm_map.h>

#include "cavs_common.h"

#import "CavsTest.h"
#import "CavsTestDispatcher.h"

/* ==========================================================================
    Private Methods for the CavsTest class
   ========================================================================== */
@interface CavsTest (PrivateMethods)

- (BOOL)initializeOutput:(NSString *)testOutputFile
                forTests:(NSDictionary *)fileDirectory;

- (BOOL)closeOutput;

- (BOOL)runTests:(NSDictionary *)fileDirectory;

@end

@implementation CavsTest

@synthesize testDirectory       = _testDirectory;
@synthesize outputDirectory     = _outputDirectory;
@synthesize outputFileExtension = _outputFileExtension;
@synthesize testsToRun          = _testsToRun;
@synthesize keyString           = _keyString;
@synthesize testTarget          = _testTarget;

+ (void)setupTest
{
    return;
}

+ (void)cleanUpTest
{
    return;
}

/* --------------------------------------------------------------------------
    Method:         initWithFileParser:(TestFileParser *)fileParser
                        withTestDictioanry:(NSDictionary *)testsToRun

    Description:    Initialize this object with the file parser and the list
                    of tests to run
   -------------------------------------------------------------------------- */
- (id)initWithFileParser:(TestFileParser *)fileParser
      withTestDictionary:(NSDictionary *)testsToRun
{
    if ((self = [super init])) {
        _fileParser             = [fileParser retain];
        _testsToRun             = [testsToRun retain];
        _outputFileExtension    = [@"rsp" copy];
        _outputFile             = nil;
        _outputDirectory        = [[NSTemporaryDirectory() stringByAppendingPathComponent:@"CAVSResults"] copy];
    }
    return self;
}

/* --------------------------------------------------------------------------
    Method:         dealloc
    Description:    Standard object memory deallocator
   -------------------------------------------------------------------------- */
- (void)dealloc
{
    [_fileParser            release];
    [_testDirectory         release];
    [_outputDirectory       release];
    [_outputFileExtension   release];
    [self closeOutput];
    [super dealloc];
}

/* --------------------------------------------------------------------------
    Method:         outputData:(NSData *)data
    Description:    write data to the output file
   -------------------------------------------------------------------------- */
- (void)outputData:(NSData *)data
{
    if (nil != data) {
        [_outputFile writeData:data];
    }

    [_outputFile writeData:[@"\n" dataUsingEncoding:NSUTF8StringEncoding]];

}

/* --------------------------------------------------------------------------
    Method:         outputString:(NSString *)string
    Description:    write a string to the output file
   -------------------------------------------------------------------------- */
- (void)outputFormat:(NSString *)format, ...
{
    va_list args;
    va_start(args, format);
    NSString *s = [[NSString alloc] initWithFormat:format locale:nil arguments:args];
    va_end(args);

    [self outputString:s];
}

- (void)outputString:(NSString *)string
{

    if (nil == string) {
        [self outputData:nil];
    }
    else {
        NSData*     tempData = [string dataUsingEncoding:NSUTF8StringEncoding];
        if (nil == tempData) {
            errorf("outputString:toTestFile: has a nil tempData");
        }

        [self outputData:tempData];
    }
}

/* --------------------------------------------------------------------------
    Method:         initializeOutput
    Description:    Private method to set up the output file
   -------------------------------------------------------------------------- */
- (BOOL)initializeOutput:(NSString      *)testOutputFile
                forTests:(NSDictionary  *)fileDirectory
{
    if (nil == _outputDirectory ||  nil == testOutputFile ||
        nil == _fileParser      ||  nil == fileDirectory)   {
        return NO;
    }

    BOOL isDir = NO;
    if (![[NSFileManager defaultManager] fileExistsAtPath:self.outputDirectory isDirectory:&isDir] ||
        !isDir) {
        return NO;
    }

    NSFileManager* fileManager = [NSFileManager defaultManager];

    NSString* outputFilePath = [[self.outputDirectory stringByAppendingPathComponent:testOutputFile]
            stringByAppendingPathExtension:_outputFileExtension];

    NSError* error = nil;

    if ([fileManager fileExistsAtPath:outputFilePath]){
        [fileManager removeItemAtPath:outputFilePath error:&error];
    }

    if (![fileManager createFileAtPath:outputFilePath contents:nil  attributes:nil]) {
        return NO;
    }

    _outputFile = [[NSFileHandle fileHandleForWritingAtPath:outputFilePath] retain];
    if (nil == _outputFile) {
        return NO;
    }

    NSArray* headerStrings = [fileDirectory objectForKey:TFFileHeaderKey];
    if (nil == headerStrings) {
        return NO;
    }

    NSString* crStr = @"\n";

    for (NSString* headerStr in headerStrings) {
        [_outputFile writeData:[headerStr dataUsingEncoding:NSUTF8StringEncoding]];
        [_outputFile writeData:[crStr     dataUsingEncoding:NSUTF8StringEncoding]];
    }

    return YES;
}

- (BOOL)closeOutput
{
    if (nil != _outputFile) {
        [_outputFile synchronizeFile];
        [_outputFile closeFile];
        [_outputFile release];
        _outputFile = nil;
    }
    return YES;
}

- (BOOL)runTest:(TestFileData *)testData withCounter:(NSInteger)counter
{
    return NO;
}

- (BOOL)runTests
{
    BOOL logTests(NSString* path, NSDictionary* testsToRun);
    logTests([NSString stringWithFormat:@"%@/parsed.json", self.outputDirectory], self.testsToRun);

    NSArray* fileNames = [self.testsToRun allKeys];

    for (NSString* fileName in fileNames) {
        errorf("%s", [fileName UTF8String]);
        if (![CAVSTestDispatcher currentTestDispatcher].silent) {
            debug("Processing test: %s", [fileName UTF8String]);
            fflush(stdout);
        }
        NSDictionary* fileDictionary = [self.testsToRun objectForKey:fileName];
        NSString* baseFileName = [fileName stringByDeletingPathExtension];
        if (![self initializeOutput:baseFileName forTests:fileDictionary]) {
            errorf("Processing test: %s  Failed to initialize test", [fileName UTF8String]);
            return NO;
        }

        [self outputString:nil];

        NSUInteger testIdx = 0;

        // Get the TestGroup Array
        NSArray* testGroups = [fileDictionary objectForKey:TFTestGroupKey];
        for (NSDictionary* testGroup in testGroups) {
            NSArray* environmentStrings = [testGroup objectForKey:TFEnvironmentDataKey];
            for (NSString* environStr in environmentStrings)
                [self outputString:environStr];

            NSArray* tests = [testGroup objectForKey:TFTestKey];
            [self processNumberOfItems:[tests count]];

            if ([[fileDictionary objectForKey:TFGroupCountReset] boolValue]) {
                testIdx = 0;
            }

            for (TestFileData* fileData in tests) {
                if (0 == testIdx) {
                    [self outputString:nil];
                }

                [self processItemNumber:(testIdx + 1)];
                if (![self runTest:fileData withCounter:testIdx]) {
                    errorf("runTest failed: %s", [fileName UTF8String]);
                    goto next;
                }
                testIdx++;
            }
        }
next:
        [self closeOutput];
    }
    return YES;
}

- (void)processNumberOfItems:(NSUInteger)numTests
{
    return;
}

- (void)processItemNumber:(NSUInteger)testNumber
{
    return;
}

@end

NSString* CipherTypeToString(TFCipherType cipherType)
{
    NSString* result = nil;

    switch (cipherType)
    {
        default:
        case TFCipherUnknown:   result = @"Unknown";    break;
        case TFCipherSHA1:      result = @"SHA1";       break;
        case TFCipherSHA224:    result = @"SHA224";     break;
        case TFCipherSHA256:    result = @"SHA256";     break;
        case TFCipherSHA384:    result = @"SHA384";     break;
        case TFCipherSHA512:    result = @"SHA512";     break;
        case TFCipherSHA3_224:  result = @"SHASHA3-224";break;
        case TFCipherSHA3_256:  result = @"SHASHA3-256";break;
        case TFCipherSHA3_384:  result = @"SHASHA3-384";break;
        case TFCipherSHA3_512:  result = @"SHASHA3-512";break;
        case TFCipherRC4:       result = @"RC4";        break;
        case TFCipherAES:       result = @"AES";        break;
        case TFCipher3DES:      result = @"3DES";       break;
        case TFCipherDRBG:      result = @"DRBG";       break;
        case TFCipherHMAC:      result = @"HMAC";       break;
    }
    return result;
}

TFCipherType StringToCipherType(NSString* cipher)
{
    if ([cipher isMatchedByRegex:@"SHA-1"])    return TFCipherSHA1;
    if ([cipher isMatchedByRegex:@"SHA-224"])  return TFCipherSHA224;
    if ([cipher isMatchedByRegex:@"SHA-256"])  return TFCipherSHA256;
    if ([cipher isMatchedByRegex:@"SHA-384"])  return TFCipherSHA384;
    if ([cipher isMatchedByRegex:@"SHA-512"])  return TFCipherSHA512;
    if ([cipher isMatchedByRegex:@"SHA3-224"]) return TFCipherSHA3_224;
    if ([cipher isMatchedByRegex:@"SHA3-256"]) return TFCipherSHA3_256;
    if ([cipher isMatchedByRegex:@"SHA3-384"]) return TFCipherSHA3_384;
    if ([cipher isMatchedByRegex:@"SHA3-512"]) return TFCipherSHA3_512;
    if ([cipher isMatchedByRegex:@"SHA1"])     return TFCipherSHA1;
    if ([cipher isMatchedByRegex:@"SHA224"])   return TFCipherSHA224;
    if ([cipher isMatchedByRegex:@"SHA256"])   return TFCipherSHA256;
    if ([cipher isMatchedByRegex:@"SHA384"])   return TFCipherSHA384;
    if ([cipher isMatchedByRegex:@"SHA512"])   return TFCipherSHA512;

    return TFCipherUnknown;
}

cavs_digest CipherTypeToDigest(TFCipherType cipherType)
{
    switch(cipherType)
    {
        case TFCipherSHA1:      return CAVS_DIGEST_SHA1;
        case TFCipherSHA224:    return CAVS_DIGEST_SHA224;
        case TFCipherSHA256:    return CAVS_DIGEST_SHA256;
        case TFCipherSHA384:    return CAVS_DIGEST_SHA384;
        case TFCipherSHA512:    return CAVS_DIGEST_SHA512;
        case TFCipherSHA3_224:  return CAVS_DIGEST_SHA3_224;
        case TFCipherSHA3_256:  return CAVS_DIGEST_SHA3_256;
        case TFCipherSHA3_384:  return CAVS_DIGEST_SHA3_384;
        case TFCipherSHA3_512:  return CAVS_DIGEST_SHA3_512;
        default:                return CAVS_DIGEST_UNKNOWN;
    }
}

cavs_cipher_mode ModeTypeToMode(TFModeType modeType)
{
    switch (modeType)
    {
        case TFModeCBC:         return CAVS_CIPHER_MODE_CBC;
        case TFModeECB:         return CAVS_CIPHER_MODE_ECB;
        case TFModeOFB:         return CAVS_CIPHER_MODE_OFB;
        case TFModeCFB:         return CAVS_CIPHER_MODE_CFB;
        case TFModeCFB8:        return CAVS_CIPHER_MODE_CFB8;
        default:                return CAVS_CIPHER_MODE_UNKNOWN;
    }
}

cavs_cipher_curve CipherTypeToCurve(TFCipherType cipherType)
{
    switch (cipherType)
    {
        case TFCipherCurve25519: return CAVS_CIPHER_CURVE_25519;
        case TFCiphered25519:    return CAVS_CIPHER_CURVE_ED25519;
        default:                 return CAVS_CIPHER_CURVE_UNKNOWN;
    }
}

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

#import <TargetConditionals.h>
#import <dispatch/dispatch.h>

#include <corecrypto/cc_config.h>

#include "cavs_common.h"

#import "CavsTestDispatcher.h"
#import "CavsAESTest.h"
#import "CavsTDESTest.h"
#import "CavsDigestTest.h"
#import "CavsHMACTest.h"
#import "CavsDRBGTest.h"
#import "CavsECTests.h"
#import "CavsRSATests.h"
#import "CavsAESGCMTest.h"
#import "CavsAESCCMTest.h"
#import "CavsAESXTSTest.h"
#import "CavsAESKWTest.h"
#import "CavsCurve25519Test.h"
#import "CavsPOSTTest.h"
#import "CavsHKDFTest.h"
#import "CavsFFDHKeyGenerateTest.h"
#import "CavsFFDHSecretTest.h"
#import "CavsMemoryHelpers.h"

#define VERBOSE 1

const NSString* kReqDirectoryName   = @"req";
const NSString* kRespDirectoryName  = @"resp";
static NSString* kMatchString       = @"(\\w+)-(\\w+)-(\\w+)-(\\w+)";
static CAVSTestDispatcher* gCurrentTestDispatcher = nil;

@interface CAVSTestDispatcher (PrivateMethods)
- (void)processReqDirectory:(NSString *)reqDirPath
          toOutputDirectory:(NSString *)reqOutputDirPath
                    keyPath:(NSString *)keyPath
                 testTarget:(cavs_target)testTarget;

- (NSString*)parseDirectory:(NSString *)dirName
                 testTarget:(cavs_target *)outTarget;
@end


@implementation CAVSTestDispatcher

@synthesize testDirectory       = _testDirectory;
@synthesize testOutputDirectory = _testOutputDirectory;
@synthesize knownAnswerTesting  = _knownAnswerTesting;
@synthesize skipTests           = _skipTests;
@synthesize verbose             = _verbose;
@synthesize silent              = _silent;
@synthesize noaction            = _noaction;
@synthesize testRootDirName     = _testRootDirName;
@synthesize fipsKextIsInstalled = _fipsKextIsInstalled;


+ (CAVSTestDispatcher *)currentTestDispatcher
{
    return gCurrentTestDispatcher;
}

- (BOOL)fipsKextIsInstalled
{
    static dispatch_once_t kCheckKextInitialized = 0;
    dispatch_once(&kCheckKextInitialized,
    ^()
    {
#if !TARGET_OS_IPHONE   // Meaning we are running on OS X
        NSLog(@"Checking for the existance of the IOFIPS Kext");
        NSTask*         aTask   = [NSTask new];
        [aTask setLaunchPath:@"/usr/sbin/kextstat"];
        NSPipe*         pipe    = [NSPipe pipe];
        [aTask setStandardOutput:pipe];
        NSFileHandle*   file    = [pipe fileHandleForReading];

        [aTask launch];
        [aTask waitUntilExit];

        NSData*         data   = [file readDataToEndOfFile];
        NSString*       string = [[NSString alloc] initWithData: data
                                                       encoding: NSUTF8StringEncoding];

        NSRange aRange = [string rangeOfString:@"fips"];

        _fipsKextIsInstalled = aRange.length > 0;

        [string release];

#else   // Meaning we are running on iOS
        _fipsKextIsInstalled = false;

        FILE* fp;
        char path[2048];
        fp = popen("/usr/sbin/kextstat", "r");
        if (NULL != fp)
        {
            memset(path, 0, 2048);
            while (fgets(path, sizeof(path)-1, fp) != NULL)
            {
                if (NULL != strstr(path, "fips"))
                {
                    _fipsKextIsInstalled = true;
                    break;
                }
                memset(path, 0, 2048);
            }
            pclose(fp);
        }
        else
        {
            NSLog(@"/usr/sbin/kextstat was NULL");
        }

#endif
        if (_fipsKextIsInstalled)   NSLog(@"The IOFIPS Kext was found");
        else                        NSLog(@"The IOFIPS Kext was not found");

    });

    return _fipsKextIsInstalled;
}

/* --------------------------------------------------------------------------
    Method:         initWithTestDirectory:(NSString*)testDirectory
                        withOutputTestDirectory:(NSString *)testOutputDirectory

    Description:    Initialize this test dispatcher with the top level
                    test directory and the output directory
   -------------------------------------------------------------------------- */
- (id)initWithTestDirectory:(NSString*)testDirectory
    withOutputTestDirectory:(NSString *)testOutputDirectory
{
    if ((self = [super init]))
    {
        _testDirectory          = [[NSString alloc] initWithString:testDirectory];
        _testOutputDirectory    = [[NSString alloc] initWithString:testOutputDirectory];
        _knownAnswerTesting     = NO;
        _skipTests              = nil;
        gCurrentTestDispatcher  = self;
        _verbose                = YES;
        _silent                 = NO;
        _noaction               = NO;
    }
    return self;
}

/* --------------------------------------------------------------------------
    Method:         processReqDirectory:(NSString *)reqDirPath toOutputDirectory:(NSString *)reqOutputDirPath
    Description:    Deal with a single test directory
   -------------------------------------------------------------------------- */
- (void)processReqDirectory:(NSString *)reqDirPath
          toOutputDirectory:(NSString *)reqOutputDirPath
                    keyPath:(NSString *)keyPath
                 testTarget:(cavs_target)testTarget
{
    NSAutoreleasePool* pool = [NSAutoreleasePool new];

    if (!self.silent)
    {
        errorf("%s", [reqDirPath UTF8String]);
        fflush(stdout);
    }

    TestFileParser* fileParser = [[TestFileParser alloc] initWithDirectoryPath:reqDirPath];

    fileParser.keyString    = keyPath;
    fileParser.testTarget   = testTarget;

    NSDictionary* testsToRun = [[NSDictionary alloc] initWithDictionary:[fileParser parse]];

    if (nil == testsToRun || 0 == [testsToRun count])
    {
        errorf("%s: fileParser parse did not return any tests", [reqDirPath UTF8String]);
        [pool drain];
        if (!self.noaction) exit(-1); else return;
    }

    // Get the type of test that will be run
    NSArray* fileNames = [testsToRun allKeys];
    if (nil == fileNames || 0 == [fileNames count])
    {
        errorf("%s: There are no file names", [reqDirPath UTF8String]);
        [pool drain];
        if (!self.noaction) exit(-1); else return;
    }

    NSString* fileName = [fileNames objectAtIndex:0];
    NSDictionary* fileDictionary = [testsToRun objectForKey:fileName];
    if (nil == fileDictionary || 0 == [fileDictionary count])
    {
        errorf("%s: There is no fileDictionary", [reqDirPath UTF8String]);
        [pool drain];
        if (!self.noaction) exit(-1); else return;
    }

    NSArray* testGroups = [fileDictionary objectForKey:TFTestGroupKey];
    if (nil == testGroups || 0 == [testGroups count])
    {
        errorf("%s: There are no test groups", [reqDirPath UTF8String]);
        [pool drain];
        if (!self.noaction) exit(-1); else return;
    }


    NSDictionary* testGroup = [testGroups objectAtIndex:0];
    NSArray* tests = [testGroup objectForKey:TFTestKey];
    if (nil == tests || 0 == [tests count])
    {
        errorf("%s: There are no tests", [reqDirPath UTF8String]);
        [pool drain];
        if (!self.noaction) exit(-1); else return;
    }

    TestFileData*   fileData = [tests objectAtIndex:0];
    TFCipherType  cipherType = fileData.cipherType;

    Class           testClass   = nil;
    NSMutableSet*   classSet    = [NSMutableSet set];
    CavsTest*       result      = nil;

    switch (cipherType)
    {
        case TFCipherSHA1:
        case TFCipherSHA224:
        case TFCipherSHA256:
        case TFCipherSHA384:
        case TFCipherSHA512:
            {
                if (TTHMACDRBG == fileData.testType) {
                    if (![classSet containsObject:(testClass = [CavsDRBGTest class])])
                    {
                        [testClass setupTest];
                        [classSet addObject:testClass];

                        printf("Creating a CavsDRBGTest object\n");

                        result = [[CavsDRBGTest alloc] initWithFileParser:fileParser
                                                         withTestDictionary:testsToRun];
                    }
                } else if (TTHKDF == fileData.testType) {
                    if (![classSet containsObject:(testClass = [CavsHKDFTest class])]) {
                        [testClass setupTest];
                        [classSet addObject:testClass];
                    }

                    printf("Creating a CavsHKDFTest object\n");
                    result = [[CavsHKDFTest alloc] initWithFileParser:fileParser
                                                     withTestDictionary:testsToRun];
                } else {
                    if (![classSet containsObject:(testClass = [CavsDigestTest class])])
                    {
                        [testClass setupTest];
                        [classSet addObject:testClass];
                    }

                    printf("Creating a CavsDigestTest object\n");
                    result = [[CavsDigestTest alloc] initWithFileParser:fileParser
                                                     withTestDictionary:testsToRun];
                }
            }
            break;
        case TFCipherAES:
            {
                if      (TTGCM == fileData.testType)
                {
                    if (![classSet containsObject:(testClass = [CavsAESGCMTest class])])
                    {
                        [testClass setupTest];
                        [classSet addObject:testClass];
                    }

                    printf("Creating a CavsAESGCMTest object\n");
                    result = [[CavsAESGCMTest alloc] initWithFileParser:fileParser
                                                     withTestDictionary:testsToRun];
                }
                else if (TTCCMVADT == fileData.testType)
                {
                    if (![classSet containsObject:(testClass = [CavsAESCCMTest class])]) {
                        [testClass setupTest];
                        [classSet addObject:testClass];
                    }

                    printf("Creating a CavsAESCCM-VADT-Test object\n");
                    result = [[CavsAESCCMTest alloc] initWithFileParser:fileParser
                                                     withTestDictionary:testsToRun];
                }
                else if (TTCCMDVPT == fileData.testType)
                {
                    if (![classSet containsObject:(testClass = [CavsAESCCMTest class])]) {
                        [testClass setupTest];
                        [classSet addObject:testClass];
                    }

                    printf("Creating a CavsAES-DVPT-CCMTest object\n");
                    result = [[CavsAESCCMTest alloc] initWithFileParser:fileParser
                                                     withTestDictionary:testsToRun];
                }
                else if (TTCCMVNT == fileData.testType)
                {
                    if (![classSet containsObject:(testClass = [CavsAESCCMTest class])]) {
                        [testClass setupTest];
                        [classSet addObject:testClass];
                    }

                    printf("Creating a CavsAESCCM-VNT-Test object\n");
                    result = [[CavsAESCCMTest alloc] initWithFileParser:fileParser
                                                     withTestDictionary:testsToRun];
                }
                else if (TTCCMVPT == fileData.testType)
                {
                    if (![classSet containsObject:(testClass = [CavsAESCCMTest class])]) {
                        [testClass setupTest];
                        [classSet addObject:testClass];
                    }

                    printf("Creating a CavsAESCCM-VPTTest object\n");
                    result = [[CavsAESCCMTest alloc] initWithFileParser:fileParser
                                                     withTestDictionary:testsToRun];
                }
                else if (TTCCMVTT == fileData.testType)
                {
                    if (![classSet containsObject:(testClass = [CavsAESCCMTest class])]) {
                        [testClass setupTest];
                        [classSet addObject:testClass];
                    }

                    printf("Creating a CavsAESCCM-VTT-Test object\n");
                    result = [[CavsAESCCMTest alloc] initWithFileParser:fileParser
                                                     withTestDictionary:testsToRun];
                }
                else if (TTXTS == fileData.testType)
                {
                    if (![classSet containsObject:(testClass = [CavsAESXTSTest class])])
                    {
                        [testClass setupTest];
                        [classSet addObject:testClass];
                    }

                    printf("Creating a CavsAESXTSTest object\n");
                    result = [[CavsAESXTSTest alloc] initWithFileParser:fileParser
                                                     withTestDictionary:testsToRun];
                }
                else if (TTAESKeyWrap == fileData.testType)
                {
                    if (![classSet containsObject:(testClass = [CavsAESKWTest class])])
                    {
                        [testClass setupTest];
                        [classSet addObject:testClass];
                    }

                    printf("Creating a CavsAESKWTest object\n");
                    result = [[CavsAESKWTest alloc] initWithFileParser:fileParser
                                                     withTestDictionary:testsToRun];
                }
                else
                {
                    if (![classSet containsObject:(testClass = [CavsAESTest class])])
                    {
                        [testClass setupTest];
                        [classSet addObject:testClass];
                    }

                    printf("Creating a CavsAESTest object\n");
                    result = [[CavsAESTest alloc] initWithFileParser:fileParser
                                                  withTestDictionary:testsToRun];
                }
            }
            break;

        case TFCipher3DES:
            {
                if (![classSet containsObject:(testClass = [CAVTDESTest class])])
                {
                    [testClass setupTest];
                    [classSet addObject:testClass];
                }

                printf("Creating a CAVTDESTest object\n");
                result = [[CAVTDESTest alloc] initWithFileParser:fileParser
                                              withTestDictionary:testsToRun];
            }
            break;

        case TFCipherDRBG:
            {
                if (![classSet containsObject:(testClass = [CavsDRBGTest class])])
                {
                    [testClass setupTest];
                    [classSet addObject:testClass];
                }

                printf("Creating a CavsDRBGTest object\n");
                result = [[CavsDRBGTest alloc] initWithFileParser:fileParser
                                               withTestDictionary:testsToRun];
            }
            break;

        case TFCipherHMAC:
            {
                if (![classSet containsObject:(testClass = [CavsHMACTest class])])
                {
                    [testClass setupTest];
                    [classSet addObject:testClass];
                }

                printf("Creating a CavsHMACTest object\n");
                result = [[CavsHMACTest alloc] initWithFileParser:fileParser
                                               withTestDictionary:testsToRun];
            }
            break;

        case TFCipherRSA:
            {
                if (![classSet containsObject:(testClass = [CavsRSATests class])])
                {
                    [testClass setupTest];
                    [classSet addObject:testClass];
                }

                printf("Creating a CavsRSATests object\n");
                result = [[CavsRSATests alloc] initWithFileParser:fileParser
                                               withTestDictionary:testsToRun];
            }
            break;

        case TFCipherECC:
            {
            if (![classSet containsObject:(testClass = [CavsECTests class])])
            {
                [testClass setupTest];
                [classSet addObject:testClass];
            }

            printf("Creating a CavsECTests object\n");
            result = [[CavsECTests alloc] initWithFileParser:fileParser
                                          withTestDictionary:testsToRun];
            }
            break;

        case TFCipherCurve25519:
            {
            if (![classSet containsObject:(testClass = [CavsCurve25519Tests class])])
            {
                [testClass setupTest];
                [classSet addObject:testClass];
            }

            printf("Creating a CavsCurve25519Tests object\n");
            result = [[CavsCurve25519Tests alloc] initWithFileParser:fileParser
                                                  withTestDictionary:testsToRun];
            }
            break;

        case TFCiphered25519:
            {
            if (![classSet containsObject:(testClass = [CavsCurve25519Tests class])])
            {
                [testClass setupTest];
                [classSet addObject:testClass];
            }

            printf("Creating a Cavsed25519Tests object\n");
            result = [[CavsCurve25519Tests alloc] initWithFileParser:fileParser
                                                  withTestDictionary:testsToRun];
        }
            break;
        default:
            if (TTFIPSPOST == fileData.testType)
            {
                if (![classSet containsObject:(testClass = [CavsPOSTTest class])]) {
                    [testClass setupTest];
                    [classSet addObject:testClass];
                }

                printf("Creating a CavsPOSTTest object\n");
                result = [[CavsPOSTTest alloc] initWithFileParser:fileParser
                                               withTestDictionary:testsToRun];
            }
            else if (TTFFDHKeyGenerate == fileData.testType)
            {
                if (![classSet containsObject:(testClass = [CavsFFDHKeyGenerateTest class])]) {
                    [testClass setupTest];
                    [classSet addObject:testClass];
                }

                printf("Creating a CavsFFDHKeyGenerateTest object\n");
                result = [[CavsFFDHKeyGenerateTest alloc] initWithFileParser:fileParser
                                                          withTestDictionary:testsToRun];
            }
            else if (TTFFDHValidity == fileData.testType || TTFFDHFunction == fileData.testType)
            {
                if (![classSet containsObject:(testClass = [CavsFFDHSecretTest class])]) {
                    [testClass setupTest];
                    [classSet addObject:testClass];
                }

                printf("Creating a CavsFFDHSecretTest object\n");
                result = [[CavsFFDHSecretTest alloc] initWithFileParser:fileParser
                                                     withTestDictionary:testsToRun];
            }
            else
            {
                errorf("%s: Unknown cipher type %d\n", [reqDirPath UTF8String], (int)cipherType);
                if (!self.noaction) exit(-1);
                break;
            }
    }

    if (nil != result) {
        result.outputDirectory  = reqOutputDirPath;
        result.keyString        = keyPath;
        result.testTarget       = testTarget;

        if (self.verbose) {
            printf("About to run tests\n");
            fflush(stdout);
        }

        if (!self.noaction) {
            [result runTests];
        }

        if (!self.silent) {
            printf("\nDone processing directory: %s\n\n", [reqDirPath UTF8String]);
            fflush(stdout);
        }
    }

    [result release];
    result = nil;

    [pool drain];
    return;
}

/* --------------------------------------------------------------------------
    Method:         parseDirectory:(NSString *)dirPath
                        testTarget:(cavs_target *)outTarget

    Description:    parse the directory name to see if it is in the form
                    (\w+)-(\w+)-(\w+)-(\w+)
   -------------------------------------------------------------------------- */
- (NSString*)parseDirectory:(NSString *)dirName
                 testTarget:(cavs_target *)outTarget
{
    NSString* result = nil;

    if (nil == dirName) return result;

    NSError*
    error = nil;

    NSRegularExpression*
    path_name_match = [NSRegularExpression regularExpressionWithPattern:kMatchString
                                                                options:0
                                                                  error:&error];
    if (nil != error)   return result;

    NSArray*
    matches = [path_name_match matchesInString:dirName
                                       options:0
                                         range:NSMakeRange(0, [dirName length])];

    if (nil != matches && [matches count] > 0) {

        NSTextCheckingResult*   tcResult    = [matches objectAtIndex:0];
        NSUInteger              numRanges   = tcResult.numberOfRanges;

        if (numRanges >= 4) {
            result = [dirName retain];
            if (NULL != outTarget) {
                if ([result hasSuffix:@"us"]) {
                    *outTarget = CAVS_TARGET_USER;
                } else if ([result hasSuffix:@"ks"]) {
                    *outTarget = CAVS_TARGET_KERNEL;
                } else if ([result hasSuffix:@"l4"]) {
                    *outTarget = CAVS_TARGET_L4;
                } else if ([result hasSuffix:@"tr"]) {
                    *outTarget = CAVS_TARGET_TRNG;
                }
            }
        }
    }

    return result;
}


/* --------------------------------------------------------------------------
    Method:         dealloc
    Description:    Standard memory reclimation method
   -------------------------------------------------------------------------- */
- (void)dealloc
{
    [_testDirectory release];
    [_testOutputDirectory release];
    [_skipTests release];
    gCurrentTestDispatcher = nil;
    [super dealloc];
}

/* --------------------------------------------------------------------------
    Method:         processTests
    Description:    process all of the tests that can be found from the root
                    test directory
   -------------------------------------------------------------------------- */
- (void)processTests
{
    NSAutoreleasePool*      pool = [NSAutoreleasePool new];
    NSString*       testTypePath = nil;
    cavs_target       testTarget = CAVS_TARGET_UNKNOWN;

    if (self.verbose)   printf("[FIPSTool][CAVSTestDispatcher.processTests] \n");

    if (nil == self.testDirectory || nil == self.testOutputDirectory) {
        // If we were not given a directory either for input or output then we
        // have nothing to do
        errorf("Either the input test directory or the output directory were not specified:  Aborting test.");
        [pool drain];
        return;
    }

    if (!self.silent)
    {
        printf("[FIPSTool][REQUEST  Directory]   = [%s]\n", [self.testDirectory UTF8String]);
        printf("[FIPSTool][RESPONSE Directory]   = [%s]\n", [self.testOutputDirectory UTF8String]);
        fflush(stdout);
    }

    NSFileManager* fileManager = [NSFileManager defaultManager];
    BOOL isDir = NO;

    // Check the validity of the input test directory
    if (![fileManager fileExistsAtPath:self.testDirectory isDirectory:&isDir] || !isDir)
    {
        errorf("Either the input test directory does not exist or it is not a directory. Aborting test.");
        [pool drain];
        return;
    }

    // Check the validity of the output test directory
    BOOL outputExists = [fileManager fileExistsAtPath:self.testOutputDirectory isDirectory:&isDir];
    if (outputExists && !isDir)
    {
        errorf("The output test directory path exists but it is not a directory.  Aborting test.");
        [pool drain];
        return;
    }

    NSError* error = nil;
    if (!outputExists)
    {
        // ensure the output directory
        if (![fileManager createDirectoryAtPath:self.testOutputDirectory
            withIntermediateDirectories:YES attributes:nil error:&error] || nil != error)
        {
            errorf("Unable to create the output test path. Aborting test.");
            [pool drain];
            return;
        }
    }

    // Now that the validity of the directories has been sorted out, determine if the
    // input directory is a req directory with *.req files
    if ([[self.testDirectory lastPathComponent] isEqualToString:(NSString *)kReqDirectoryName])
    {
        if (self.verbose)
            printf("[FIPSTool][CAVSTestDispatcher.processTests] : The top directory just contains req files.\n");

        // This is a single req directory so process accordingly
        [self processReqDirectory:(NSString *)self.testDirectory
                toOutputDirectory:(NSString *)self.testOutputDirectory
                          keyPath:testTypePath
                       testTarget:CAVS_TARGET_USER];

        [pool drain];
        return;
    }

    // This is not a .req directory so we need to iterate the directories


    NSMutableArray* dirArray = [NSMutableArray new];

    NSDirectoryEnumerator* dirEnum = [fileManager enumeratorAtPath:self.testDirectory];
    BOOL skip_test = NO;
    for (NSString* partialPath in dirEnum) {
        skip_test = NO;
        for (NSString* skip_item in _skipTests) {
            if ([partialPath rangeOfString:skip_item].length > 0) {
                skip_test = YES;
                break;
            }
        }

        if (skip_test)  continue;
        // loop until a .req file is found

        NSString*       file_path = [self.testDirectory stringByAppendingPathComponent:partialPath];
        if ([[file_path pathExtension] isEqualToString:@"req"])
        {
            // Bingo!
            //Back up to the directory
            NSString*   dir_path = [file_path stringByDeletingLastPathComponent];
            NSString*   dir_name = [dir_path lastPathComponent];
            // check to see if this directory has been processed.  Lame but works
            if ([dirArray containsObject:dir_path]) continue;

            [dirArray addObject:dir_path];

            // we have a directory of tests to process
            // ensure the output directory
            if ([dir_name isEqualToString:@"req"])
            {
                NSString* temp_dir_path         = [dir_path stringByDeletingLastPathComponent];
                NSString* temp_parent_name      = [temp_dir_path lastPathComponent];
                NSString* temp_grandparent_name = [[[dir_path stringByDeletingLastPathComponent]
                                                              stringByDeletingLastPathComponent]
                                                              lastPathComponent];

                testTypePath = [self parseDirectory:temp_grandparent_name testTarget:&testTarget];

                if (nil != testTypePath)
                    dir_name = [[testTypePath stringByAppendingPathComponent:temp_parent_name]
                                              stringByAppendingPathComponent:(NSString *)kRespDirectoryName];
                else
                    dir_name = [temp_parent_name stringByAppendingPathComponent:(NSString *)kRespDirectoryName];
            }
            NSString* outputDir = [self.testOutputDirectory stringByAppendingPathComponent:dir_name];

            BOOL isDir      = NO;
            BOOL dir_exists = NO;
            if ((dir_exists = [fileManager fileExistsAtPath:outputDir isDirectory:&isDir]) && !isDir)
            {
                errorf("The output directory %s exists but it is not a directory!\n", [outputDir UTF8String]);
                [pool drain];
                return;
            }

            if (!dir_exists)
            {
                // If the output directory does not exist then make the directory
                if (![fileManager createDirectoryAtPath:outputDir withIntermediateDirectories:YES
                    attributes:nil error:&error] || nil != error)
                {
                    errorf("Unable to create the output directory: %s\n", [outputDir UTF8String]);
                    [pool drain];
                    return;
                }
            }

            // At this point we have an output directory run the tests
            if (self.verbose) {
                errorf("[FIPSTool][CAVSTestDispatcher.processTests]");
                errorf("  REQUEST:[%s]", [dir_path UTF8String]);
                errorf(" RESPONSE:[%s]", [outputDir UTF8String]);
            }

            [self processReqDirectory:dir_path
                    toOutputDirectory:outputDir
                              keyPath:testTypePath
                           testTarget:testTarget];

            if (self.verbose)
                errorf("Completed: %s",[dir_path UTF8String]);
        }
    }

    [pool drain];
}

@end

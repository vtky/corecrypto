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

/* ==========================================================================
    Discussion:

    This program is designed to work through a single directory of CAVS tests.
    Typically the tests are organized by cipher for example, the test
    directories we received from @Sec were as follows:
        AES
        AES_GCM
        DRBG800-90
        ECDSA2
        HMAC
        HMAC-DRBG
        KeyWrap38F
        RSA2
        SHA
        TDES
        XTS

    The tool is designed to take a single directory and process all of the
    tests in that single directory.  For example to run all of the AES test
    one would do the following:

    CAVS -i $CAVSDIR/AES -o $OUTPUTDIS/AESResults

    Assuming $CAVSDIR points to the directory containing the AES directory
    and $OUTPUTDIR is the directory where the AESResults directory should be
    created.
   ========================================================================== */

#import <Foundation/Foundation.h>
#import <AvailabilityMacros.h>

#include <corecrypto/cc_config.h>

#include "cavs_common.h"

#import "CavsTestFileParser.h"
#import "CavsMemoryHelpers.h"
#import "CavsTestDispatcher.h"

static void usage(const char* programName)
{
    printf("%s usage:\n", programName);
    printf(" [-h, --help]          \tPrint out this help message\n");
    printf(" [-v, --verbose]       \tPrint verbose logging\n");
    printf(" [-s, --slient]        \tDo not print out any logging\n");
    printf(" [-i, --input]         \tSpecify the input directory that contains the test files\n");
    printf(" [-o, --output]        \tSpecify the output directory for the test results\n");
    printf(" [-k, --known_tests]   \tRun a set of known tests and compare the results with a set of known answers\n");
    printf(" [-x, --skip_tests]    \tSpecify a list of Tests to skip.  This needs to be a comma delimited string. i.e. 'AES,TDES'\n");
    printf(" [-n, --noaction]      \tOnly parse the input files, do not execute tests themselves\n");
    printf("\n");
}

static BOOL StringStartsWithDash(NSString *tempStr)
{
    const char* cStr  = [tempStr UTF8String];
    return (*cStr == '-');
}

static BOOL EnsureDirectory(NSString* dir_path)
{
    BOOL result                 = NO;               // guilty until proven
    BOOL isDir                  = NO;
    NSError* error              = nil;
    NSFileManager* fileManager  = [NSFileManager defaultManager];
    if (![fileManager fileExistsAtPath:dir_path isDirectory:&isDir])
    {
        // create the directory
        if (![fileManager createDirectoryAtPath:dir_path
                    withIntermediateDirectories:YES attributes:nil error:&error])
        {
            fprintf(stderr, "Unable to create the %s directory\n", [dir_path UTF8String]);
            return result;
        }
    }
    else if (!isDir)
        return result;

    return YES;
}

/* ==========================================================================
    Compare the results of running a set of CAVS tests with a set of known
    answers.  Output the results into a single file at
    ~/Known_CAVS_Results/CAVS_KnownAnswerTest_Results.txt
   ========================================================================== */
static BOOL DoKnownAnswerComparison(BOOL verbose)
{
    BOOL iResult = YES;

    if (verbose)
        fprintf(stderr, "In DoKnownAnswerComparision\n");

    @autoreleasepool
    {
        NSFileManager* fileManager = [NSFileManager defaultManager];
        BOOL isDir;

        /* ------------------------------------------------------------------
            Create a single output file to show the results of comparing the
            CAVS results to the known answers results
           ------------------------------------------------------------------ */
        NSString* known_answer_test_file_path = [[@"~/Known_CAVS_Results" stringByExpandingTildeInPath]
                                       stringByAppendingPathComponent:@"CAVS_KnownAnswerTest_Results.txt"];

        if ([fileManager fileExistsAtPath:known_answer_test_file_path isDirectory:&isDir])
        {
            if (isDir)
            {
                fprintf(stderr, "Unable to proceed the test output file %s is a directory!\n",
                        [known_answer_test_file_path UTF8String]);
                return NO;
            }
        }
        else    // create the file
            [[NSData data] writeToFile:known_answer_test_file_path atomically:NO];


        // The file exist so open it and truncate it to the beginning of the file
        NSFileHandle*
        knownTestOutputFile = [NSFileHandle fileHandleForWritingAtPath:known_answer_test_file_path];
        [knownTestOutputFile truncateFileAtOffset:0LL];

        // Get the path for the known answer directory and results
        NSString* server_known_answers_path = @"~crypto/CAVS_VECTORING/Responses";
        NSString* cavs_results_path = [@"~/CAVS_VECTOR_RESULTS" stringByExpandingTildeInPath];

        /* ------------------------------------------------------------------
            The following code assumes that the ~crypto server has the
            follow directory structure

            ~crypto/CAVS_VECTORING/Responses/[OSX|iOS]/[Kernel|User]/...
           ------------------------------------------------------------------ */

        NSArray* platforms  = [NSArray arrayWithObjects:@"OSX", @"iOS", @"tvOS", @"watchOS", nil];
        NSArray* boundaries = [NSArray arrayWithObjects:@"Kernel", @"User", @"SEP",nil];

        // Loop through the top level directory
        for (NSString* top_dir_patform_name in platforms)
        {
            // check to see if the results path has a cooresponding dir
            NSString* full_result_platform_path = [cavs_results_path         stringByAppendingPathComponent:top_dir_patform_name];
            NSString* full_server_platform_path = [server_known_answers_path stringByAppendingPathComponent:top_dir_patform_name];

            if ([fileManager fileExistsAtPath:full_result_platform_path isDirectory:&isDir] && isDir)
            {
                // The result directory exists so now find out what boundaries directories are in the results
                for (NSString* top_boundary_name in boundaries)
                {
                    NSString* full_results_boundary_path = [full_result_platform_path stringByAppendingPathComponent:top_boundary_name];
                    NSString* full_server_bounndary_path = [full_server_platform_path stringByAppendingPathComponent:top_boundary_name];

                    if ([fileManager fileExistsAtPath:full_results_boundary_path isDirectory:&isDir] && isDir)
                    {
                        // The result boundary directory exists so enumerate the response directories
                        // within the result boundary directory and compare the files
                        NSDirectoryEnumerator* test_type_dir_enumerator = [fileManager enumeratorAtPath:full_server_platform_path];
                        [test_type_dir_enumerator skipDescendents];
                        for(NSString* test_dir_name in test_type_dir_enumerator)
                        {
                            NSString* partial_path = [[top_dir_patform_name stringByAppendingPathComponent:top_boundary_name]
                                            stringByAppendingPathComponent:test_dir_name];

                            [knownTestOutputFile writeData:[[NSString stringWithFormat:@"Results for %@\n", partial_path]
                                dataUsingEncoding:NSUTF8StringEncoding]];
                            [knownTestOutputFile synchronizeFile];

                            NSString* full_results_reponse_path = [[full_results_boundary_path stringByAppendingPathComponent:test_dir_name]
                                                                    stringByAppendingPathComponent:@"resp"];
                            NSString* full_server_reponse_path = [[full_server_bounndary_path stringByAppendingPathComponent:test_dir_name]
                                                                    stringByAppendingPathComponent:@"resp"];
                            if ([fileManager fileExistsAtPath:full_results_reponse_path isDirectory:&isDir] && isDir)
                            {
                                // There is a cooresponding results directory.  Time to enumerate the files and do a comparision
                                NSDirectoryEnumerator* test_response_dir_enumerator = [fileManager enumeratorAtPath:full_server_reponse_path];
                                [test_response_dir_enumerator skipDescendents];
                                for (NSString* response_file_name in test_response_dir_enumerator)
                                {
                                    // Weed out some undesireable results like .DS_Store files etx
                                    if ([response_file_name rangeOfString:@".DS_Store"].length > 0)
                                    {
                                        continue;
                                    }

                                    // Check to see if this an RSA set of tests
                                    if ([test_dir_name isEqualToString:@"RSA"])
                                    {
                                        // Check to see if this is a signature generation test
                                        if ([response_file_name rangeOfString:@"SigGen"].length > 0)
                                        {
                                            // RSA SigGen test requires that a random RSA key be
                                            // generated and used to create a RSA signature.  This
                                            // means there can be NO 'known' answers to compare

                                            [knownTestOutputFile writeData:[[NSString stringWithFormat:
                                                @"%@ is an RSA signature generation test and therefore cannot have a known answer.  Ignoring\n", response_file_name]
                                                dataUsingEncoding:NSUTF8StringEncoding]];
                                            [knownTestOutputFile synchronizeFile];
                                            continue;
                                        }
                                    }
                                    else if ([test_dir_name isEqualToString:@"ECDSA"])
                                    {
                                        // Check to see if this is a signature generation test
                                        if ([response_file_name rangeOfString:@"KeyPair"].length > 0)
                                        {
                                            // ECDSA KeyPair generation test requires that a random ECDSA key be
                                            // generated.  This means that there can be NO 'known' answers to compare

                                            [knownTestOutputFile writeData:[[NSString stringWithFormat:
                                                @"%@ is an ECDSA key generation test and therefore cannot have a known answer.  Ignoring\n", response_file_name]
                                                dataUsingEncoding:NSUTF8StringEncoding]];
                                            [knownTestOutputFile synchronizeFile];
                                            continue;
                                        }
                                        else if ([response_file_name rangeOfString:@"SigGen"].length > 0)
                                        {
                                            // ECDSA signature generation test requires that a random ECDSA key be
                                            // generated and used to create an ECDSA signature  This means that there
                                            // can be NO 'known' answers to compare

                                            [knownTestOutputFile writeData:[[NSString stringWithFormat:
                                                @"%@ is an ECDSA signature generation test and therefore cannot have a known answer.  Ignoring\n", response_file_name]
                                                dataUsingEncoding:NSUTF8StringEncoding]];
                                            [knownTestOutputFile synchronizeFile];
                                            continue;
                                        }
                                    }

                                    NSString* full_result_response_file_path = [full_results_reponse_path stringByAppendingPathComponent:response_file_name];
                                    NSString* full_server_reponse_file_path = [full_server_reponse_path stringByAppendingPathComponent:response_file_name];

                                    if ([fileManager fileExistsAtPath:full_result_response_file_path isDirectory:&isDir] && !isDir)
                                    {
                                        // There is a matching results file. Do the diff
                                        // Create a temp file to hold the contents of a diff
                                        NSString* tempDirStr = NSTemporaryDirectory();
                                        NSString* diff_temp_file = [tempDirStr stringByAppendingPathComponent:@"DiffTempFile.dif"];
                                        if ([fileManager fileExistsAtPath:diff_temp_file])
                                        {
                                            // Delete the old file
                                            [fileManager removeItemAtPath:diff_temp_file error:NULL];
                                        }

                                        // Now diff the known answer response with the response generated from the test.
                                        NSString* cmd_string = [NSString stringWithFormat:@"/usr/bin/diff -i -w %@ %@ > %@", full_server_reponse_file_path, full_result_response_file_path, diff_temp_file];
                                        (void)system([cmd_string UTF8String]);

                                        // If the test results match then the diff file should be empty
                                        NSData* fileData = [NSData dataWithContentsOfFile:diff_temp_file];
                                        BOOL passed = (0 == [fileData length]);

                                        if (passed)
                                        {
                                            [knownTestOutputFile writeData:[[NSString stringWithFormat:
                                                @"Test %@ passed\n",  response_file_name]
                                                dataUsingEncoding:NSUTF8StringEncoding]];
                                            [knownTestOutputFile synchronizeFile];
                                        }
                                        else
                                        {
                                            iResult = NO;
                                            NSString* fail_str = [[NSString alloc] initWithData:fileData encoding:NSUTF8StringEncoding];
                                            [knownTestOutputFile writeData:[[NSString stringWithFormat:
                                                @"Test %@ failed\nDiffs = \n%@\n\n",  response_file_name, fail_str]
                                                dataUsingEncoding:NSUTF8StringEncoding]];
                                            [knownTestOutputFile synchronizeFile];
                                            [fail_str release];
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if (nil != knownTestOutputFile)
        {
            [knownTestOutputFile synchronizeFile];
            [knownTestOutputFile closeFile];
        }

    }
    return iResult;
}


/* ==========================================================================
    The music goes round and rounds whoa o whoa o and comes out here
   ========================================================================== */
int main (int argc, const char * argv[])
{
    int iResult = 0;
    @autoreleasepool
    {
        const char* programName         = argv[0];

        // ==========================================================================
        //  Provide a way to test this program easily with XCode by hard coding the
        //  command line values.
        // ==========================================================================

#if defined(__x86_64__) || defined(__i386__)
        const char* hardcodedArgv[] =
        {
            argv[0],
            "-v",
            "--input",
            "~/Desktop/test_FIPS",
            "--output",
            "~/Desktop/test_CAVS_Results"
        };
#elif defined(__arm__) || defined(__arm64__)
        const char* hardcodedArgv[] =
        {
            argv[0],
            "-v",
            "--input",
            "/tmp/test_FIPS",
            "--output",
            "/tmp/test_CAVS_Results"
        };
#endif // TARGET_OS_EMBEDDED
        int hardcodedArgc = (sizeof(hardcodedArgv) / sizeof(const char*));


        if (argc < 2) {
            printf("WARNING: missing arguments, using hardcoded values. Use --help\n");
            argc = hardcodedArgc;
            argv = hardcodedArgv;
        }

        NSString* inputTestDirPath      = nil;
        NSString* outputResultsDirPath  = nil;
        NSArray* tests                  = nil;
        BOOL isDir                      = NO;
        NSError* error                  = nil;
        CAVSTestDispatcher* dispatcher  = nil;
        BOOL    doComparisons           = NO;
        NSMutableString*  skip_test_str = nil;
        NSString* skip_str              = nil;
        NSMutableArray* tests_to_skip   = nil;

        BOOL verbose                    = NO;
        BOOL silent                     = NO;
        BOOL noaction                   = NO;

        NSFileManager* fileManager      = [NSFileManager defaultManager];

// ==========================================================================
//  Provide a way to skip tests.  This is useful if a known issue is being
//  tracked for a particular test.  The tests array is check against the
//  the -x, --skip_tests argument.  If it is matched those test will be
//  skipped
// ==========================================================================

        tests = [NSArray arrayWithObjects:@"AES", @"ECDSA", @"RSA", @"TDES",
                                          @"DRBG800-90", @"HMAC", @"SHA", @"KAS", nil];

// ==========================================================================
//  Parse the command line arguments
// ==========================================================================
        for (int iCnt = 1; iCnt < argc; iCnt++)
        {
            const char* arg = argv[iCnt];

            if (!strcmp(arg, "-h") || !strcmp(arg, "--help"))
            {
                usage(programName);
               return iResult;
            }
            else if (!strcmp(arg, "-v") || !strcmp(arg, "--verbose"))
            {
                verbose = YES;
                silent = NO;
            }
            else if (!strcmp(arg, "-s") || !strcmp(arg, "--silent"))
            {
                silent = YES;
                verbose = NO;
            }
            else if (!strcmp(arg, "-i") || !strcmp(arg, "--input"))
            {
                if ((iCnt + 1) == argc)
                {
                    usage(programName);
                    return iResult;
                }

                inputTestDirPath = [NSString stringWithUTF8String:argv[iCnt + 1]];
                if (nil == inputTestDirPath || StringStartsWithDash(inputTestDirPath))
                {
                    usage(programName);
                    return iResult;
                }

                iCnt++;

                inputTestDirPath = [inputTestDirPath stringByExpandingTildeInPath];

                if (![fileManager fileExistsAtPath:inputTestDirPath isDirectory:&isDir] || !isDir)
                {
                    fprintf(stderr, "Input file does not exist!\n");
                    usage(programName);
                    return -1;
                }
            }
            else if (!strcmp(arg, "-o") || !strcmp(arg, "--output"))
            {
                if ((iCnt + 1) == argc)
                {
                    usage(programName);
                    return -1;
                }

                outputResultsDirPath = [NSString stringWithUTF8String:argv[iCnt + 1]];
                if (nil == outputResultsDirPath || StringStartsWithDash(outputResultsDirPath))
                {
                    usage(programName);
                    return -1;
                }

                iCnt++;

                outputResultsDirPath = [outputResultsDirPath stringByExpandingTildeInPath];

                if ([fileManager fileExistsAtPath:outputResultsDirPath isDirectory:&isDir] && isDir)
                {
                    if (![fileManager removeItemAtPath:outputResultsDirPath error:&error] || nil != error)
                    {
                        fprintf(stderr, "Unable to delete the exisiting directory!\n");
                        usage(programName);
                        return -1;
                    }
                }

                if (!EnsureDirectory(outputResultsDirPath))
                {
                    fprintf(stderr, "Unable to create the results directory!\n");
                    usage(programName);
                    return -1;
                }
            }
            else if (!strcmp(arg, "-k") || !strcmp(arg, "--known_tests"))
            {
                // Set the flag that will perform the post test run comparisions.
                doComparisons = YES;
            }
            else if (!strcmp(arg, "-n") || !strcmp(arg, "--noaction"))
            {
                noaction = YES;
            }
            else if (!strcmp(arg, "-x") || !strcmp(arg, "--skip_tests"))
            {
                // Get the path for the output directory
                if ((iCnt + 1) == argc)
                {
                    usage(programName);
                   return -1;
                }

                skip_test_str = [NSMutableString stringWithUTF8String:argv[iCnt + 1]];
                // Strip any whitespace
                [skip_test_str replaceOccurrencesOfString:@" " withString:@"" options:0
                                                    range:NSMakeRange(0,[skip_test_str length])];
                skip_str = [skip_test_str uppercaseString];
                NSArray* dirs = [skip_str componentsSeparatedByString:@","];

                for (NSString* test_str in dirs)
                {
                    if ([tests containsObject:test_str])
                    {
                        if (nil == tests_to_skip)
                        {
                            tests_to_skip = [NSMutableArray array];
                        }
                        [tests_to_skip addObject:test_str];
                    }
                }
            }
        }

// ==========================================================================
//  Do some parameter checking
// ==========================================================================

        if (nil == inputTestDirPath || nil == outputResultsDirPath)
        {
            printf("[FIPSTool] Missing %s directory\n",
                   (inputTestDirPath==nil)?"input":"output");
            usage(programName);
            return -1;
        }

        if (verbose)
        {
            printf("[FIPSTool] inputTestDirPath      = [%s]\n",[inputTestDirPath UTF8String]);
            printf("[FIPSTool] outputResultsDirPath  = [%s]\n",[outputResultsDirPath UTF8String]);
        }

// ==========================================================================
//  Create the test dispatcher
// =========================================================================

        dispatcher = [[[CAVSTestDispatcher alloc] initWithTestDirectory:inputTestDirPath
                                                withOutputTestDirectory:outputResultsDirPath] autorelease];

        [dispatcher setKnownAnswerTesting:doComparisons];
        [dispatcher setVerbose:verbose];
        [dispatcher setSilent:silent];
        [dispatcher setNoaction:noaction];

        if (nil != tests_to_skip)
            [dispatcher setSkipTests:tests_to_skip];

// ==========================================================================
// Run the tests
// ==========================================================================

        [dispatcher processTests];

        // Check to see if this was a known answer test run.  If so do the comparisions
        if (doComparisons) {
            if (verbose)
                printf("[FIPSTool] doComparisons is true!  Checking the results with known answers!\n");

            iResult =  (DoKnownAnswerComparison(verbose) ? 0 : -1);
        }
    }

    return iResult;
}


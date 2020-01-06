/*
 * Copyright (c) 2012,2015,2016,2017,2018 Apple Inc. All rights reserved.
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

#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <stdbool.h>
#if defined(_WIN32)
 static int optind = 1;
#else
#include <unistd.h>
#include <dlfcn.h>
#endif

#include "testmore.h"
#include "testenv.h"

#include <corecrypto/cc_macros.h>
#include <corecrypto/ccrng.h>
#include "../corecrypto_test/include/testbyteBuffer.h"

static int tests_printall(void);

static int
tests_summary(int verbose) {
    int failed_tests = 0;
    int todo_tests = 0;
    int actual_tests = 0;
    int planned_tests = 0;
    int warning_tests = 0;
    uint64_t duration_tests = 0;

    // First compute the totals to help decide if we need to print headers or not.
    for (int i = 0; testlist[i].name; ++i) {
        if (testlist[i].executed) {
            failed_tests += testlist[i].failed_tests;
            todo_tests += testlist[i].todo_tests;
            actual_tests += testlist[i].actual_tests;
            planned_tests += testlist[i].planned_tests;
            warning_tests += testlist[i].warning_tests;
            duration_tests += testlist[i].duration;
        }
    }

    fprintf(stdout, "\n[SUMMARY]\n");

    // -v makes the summary verbose as well.
    if (verbose || failed_tests || actual_tests != planned_tests || todo_tests || warning_tests) {
        fprintf(stdout, "Test name                                                failed  warning  todo  ran  planned\n");
        fprintf(stdout, "============================================================================================\n");
    }
    for (int i = 0; testlist[i].name; ++i) {
        if (testlist[i].executed) {
            const char *token = NULL;
            if (testlist[i].failed_tests) {
                token = "FAIL";
            } else if (testlist[i].actual_tests != testlist[i].planned_tests
                       || (testlist[i].todo_tests)
                       || (testlist[i].warning_tests)) {
                token = "WARN";
            } else if (verbose) {
                token = "PASS";
            }
            if (token) {
                fprintf(stdout, "[%s] %-49s %6d  %6d %6d %6d %6d\n", token,
                        testlist[i].name,
                        testlist[i].failed_tests, testlist[i].warning_tests,
                        testlist[i].todo_tests,
                        testlist[i].actual_tests, testlist[i].planned_tests);
            }
        }
    }
    if (verbose || failed_tests || warning_tests || todo_tests || actual_tests != planned_tests) {
        fprintf(stdout, "============================================================================================\n");
    }
    else {
        fprintf(stdout, "Test name                                                failed  warning  todo  ran  planned\n");
    }
    fprintf(stdout, "Totals (%6llus)                                         %6d  %6d %6d %6d %6d\n", duration_tests/1000, failed_tests, warning_tests, todo_tests, actual_tests, planned_tests);
    return failed_tests;
}

#if defined(_WIN32)
static int tests_run_index(int i, int argc, char * const *argv, byteBuffer seed)
{
    fprintf(stderr, "\n[BEGIN] %s\n", testlist[i].name);
    
    run_one_test(&testlist[i], argc, argv, seed->len, seed->bytes);
    if(testlist[i].failed_tests) {
        fprintf(stderr, "[FAIL] %s\n", testlist[i].name);
    } else {
        fprintf(stderr, "duration: %llu ms\n", testlist[i].duration);
        fprintf(stderr, "[PASS] %s\n", testlist[i].name);
    }
    
    return 0;
}
#else
static void usage(const char *progname)
{
    fprintf(stderr, "usage: %s [-L][-v][-s seed][-w][testname [-v] ...]\n", progname);
    fprintf(stderr, "\t-v verbose\n");
    fprintf(stderr, "\t-s <seed> to provide a specific seed (ex 8686b151ec2aa17c4ec41a59e496d2ff), reused for each sub-test.\n");
    fprintf(stderr, "\t-w sleep(100)\n");
    fprintf(stderr, "\t-L list supported tests by test names\n");
    fprintf(stderr, "Here is the list of supported tests:\n");
    tests_printall();
    exit(1);
}

static int tests_run_index(int i, int argc, char * const *argv, byteBuffer seed)
{
    int verbose = 0;
    int ch;

    while ((ch = getopt(argc, argv, "v")) != -1)
    {
        switch  (ch)
        {
            case 'v':
                verbose++;
                break;
            default:
                usage(argv[0]);
        }
    }

    fprintf(stderr, "\n[BEGIN] %s\n", testlist[i].name);

    run_one_test(&testlist[i], argc, argv, seed->len, seed->bytes);
    if(testlist[i].failed_tests) {
        fprintf(stderr, "[FAIL] %s\n", testlist[i].name);
    } else {
        fprintf(stderr, "duration: %llu ms\n", testlist[i].duration);
        fprintf(stderr, "[PASS] %s\n", testlist[i].name);
    }

    return 0;
}

static int tests_named_index(const char *testcase)
{
    int i;
    
    for (i = 0; testlist[i].name; ++i) {
        if (strcmp(testlist[i].name, testcase) == 0) {
            return i;
        }
    }
    
    return -1;
}

#endif

static int tests_printall(void)
{
    for (int i = 0; testlist[i].name; ++i) {
        fprintf(stdout, "%s\n", testlist[i].name);
    }

    return 0;
}

static int tests_run_all(int argc, char * const *argv, byteBuffer seed)
{
    int curroptind = optind;
    int i;

    for (i = 0; testlist[i].name; ++i) {
        tests_run_index(i, argc, argv,seed);
        optind = curroptind;
    }

    return 0;
}

static void print_tu_status(const char *dylib_path) {
#if CC_XNU_KERNEL_AVAILABLE
    void *lib = dlopen(dylib_path, RTLD_LAZY);
    int (*is_compiled_with_tu)()  = dlsym(lib, "cc_is_compiled_with_tu");

    if( is_compiled_with_tu != NULL){
        printf(is_compiled_with_tu()? "libcorecrypto.dylib is using headers with transparent unions\n" : "NO TU in libcorecrypto.dylib\n");
    } else {
        printf("this version of libcorecrypto.dylib does not support compilation without transparent unions\n");
    }
    dlclose(lib);
#else
    (void)dylib_path;
#endif

#if CORECRYPTO_USE_TRANSPARENT_UNION
    printf("corecrypto_test is using headers with transparent unions\n");
#else
    printf("NO TU in corecrypto_test\n");
#endif
}

#if CC_XNU_KERNEL_AVAILABLE
static off_t fsize(const char *fname)
{
    struct stat st;
    return (stat(fname, &st) == 0)? st.st_size:-1;
}

static void print_lib_path(void)
{
    Dl_info dl_info;
    if( dladdr((void *)cc_clear, &dl_info) != 0){
        fprintf(stderr, "corecrypto loaded: %s (%lld bytes)\n\n", dl_info.dli_fname, fsize(dl_info.dli_fname));
        print_tu_status(dl_info.dli_fname);
    }
}
#else
static void print_lib_path(void){
    print_tu_status("");
}
#endif

static int tests_init(byteBuffer *pSeedBuffer,const char *seedInput) {
    printf("[TEST] === corecrypto ===\n");
    print_lib_path();
    int status=-1;
    // Set a seed for reproducibility
    if (seedInput!=NULL) {
        *pSeedBuffer=hexStringToBytes(seedInput);
        if (*pSeedBuffer) {
            printByteBuffer(*pSeedBuffer,"\nInput seed value:");
            status=0;
        }
        else{
            printf("Error with input seed value: %s",seedInput);
        }
    } else {
        // If the seed is not in the argument, we generate one
        size_t entropy_size=16; // Default size of the seed
        cc_require((*pSeedBuffer=mallocByteBuffer(entropy_size))!=NULL,errOut);
        struct ccrng_state *rng = ccrng(&status);
        cc_require(rng!=NULL, errOut);
        cc_require((status=ccrng_generate(rng, (*pSeedBuffer)->len, (*pSeedBuffer)->bytes))==0, errOut);
        printByteBuffer(*pSeedBuffer,"\nRandom seed value:");
        printf("Seed used for every subtest. To reproduce a failure, you can run with '-s <seed> <subtest>'\n");
    }

errOut:
    return status;
}

#if defined(_WIN32)
int
tests_begin(int argc, char * const *argv)
{
    const char *seed=NULL;
    byteBuffer seedBuffer=NULL; //seed for test drbg
	int list = 0;
	int retval;
	int verbose = 0;

	printf("Command-line options are currently not supported on Windows.\n");
    
    if ((retval=tests_init(&seedBuffer, seed)) != 0) {
        printf("%08x unable to initialize tests", retval);
        return -1;
    }
	tests_run_all(argc, argv, seedBuffer);

	if (list) {
		tests_printall();
		retval = 0;
	}
	else {
		retval = tests_summary(verbose);
	}
	/* Cleanups */
    free(seedBuffer);
    
    retval = tests_summary(verbose);
	return retval;
}
#else

int
tests_begin(int argc, char * const *argv)
{
    const char *seed=NULL;
    byteBuffer seedBuffer=NULL; //seed for test drbg
	int retval;
	int verbose = 0;
    const char *testcase = NULL;
    bool initialized = false;
    int testix = -1;
    int ch;

	for (;;) {

        while (!testcase && (ch = getopt(argc, argv, "Lvws:")) != -1)
        {
            switch  (ch)
            {
            case 's': // seed provided
                // The same seed is reused for all of the tests
                seed = optarg;
                break;
            case 'w': // wait
                sleep(100);
                break;
            case 'v': // verbose
                verbose=1;
                break;
            case 'L': // List test for test discovery
                tests_printall();
                exit(0);
            case '?':
            default:
                printf("invalid option %c\n",ch);
                usage(argv[0]);
            }
        }

        if (optind < argc) {
            testix = tests_named_index(argv[optind]);
            if(testix<0) {
                printf("invalid test %s\n",argv[optind]);
                usage(argv[0]);
            }
            argc -= optind;
            argv += optind;
            optind=1;
        }

        if (testix < 0) {
            // Not test specified or reached end of list
            if (!initialized) {
                // Not test specified
                if (tests_init(&seedBuffer,seed)!=0) return -1;
                tests_run_all(argc, argv,seedBuffer);
            }
            break;
        } else {
            if (!initialized) {
                if (tests_init(&seedBuffer,seed)!=0) return -1;
                initialized = true;
            }
            tests_run_index(testix, argc, argv,seedBuffer);
            testix = -1;
        }
    }

    /* Cleanups */
    free(seedBuffer);

    retval=tests_summary(verbose);
    return retval;
}
#endif

/*
 * Copyright (c) 2012,2014,2015,2016,2017,2018 Apple Inc. All rights reserved.
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
#if defined(_WIN32)
 #include "cctime.h"
#else
 #include <sys/time.h>
 #include <unistd.h>
#endif

#include "testmore.h"

#include <corecrypto/cc_macros.h>
#include <corecrypto/ccrng_test.h>

//or, define like the following
//#definef printf_stderr(x...) fprintf(stderr, x)
//if cc_printf() is not available.
#define fprintf_stderr(x...) cc_printf(x)
#define fprintf_stdout(x...) cc_printf(x)

static int test_num = 0;
static int test_fails = 0;
static int test_cases = 0;
static int test_todo = 0;
static int test_warning = 0;
static const char *test_plan_file;
static int test_plan_line=0;

const char *test_directive = NULL;
const char *test_reason = NULL;

void test_skip(const char *reason, int how_many, int unless)
{
    if (unless)
        return;

    int done;
    for (done = 0; done < how_many; ++done)
        test_ok(1, NULL, "skip", reason, __FILE__, __LINE__, NULL);
}

void test_bail_out(const char *reason, const char *file, unsigned line)
{
    fprintf_stdout("BAIL OUT! (%s at line %u) %s\n", file, line, reason);
    fflush(stdout);
    exit(255);
}

void test_plan_skip_all(const char *reason)
{
    if (test_num > test_cases)
    {
	test_skip(reason, test_cases - test_num, 0);
	exit(test_fails > 255 ? 255 : test_fails);
    }
}

static void test_plan_reset(void) {
    test_fails = 0;
    test_num = 0;
    test_cases = 0;
    test_plan_file = NULL;
    test_plan_line = 0;
    test_warning = 0;
}

static void test_plan_exit(void)
{
    // int status = 0;
    fflush(stdout);

    if (!test_num)
    {
        if (test_cases)
        {
            fprintf_stderr("%s:%u: warning: No tests run!\n", test_plan_file, test_plan_line);
            // status = 255;
        }
        else
        {
            fprintf_stderr("%s:%u: error: Looks like your test died before it could "
                    "output anything.\n", test_plan_file, test_plan_line);
            // status = 255;
        }
    }
    else {
        if (test_fails)
        {
            fprintf_stderr("%s:%u: error: Looks like you failed %d tests of %d.\n",
                    test_plan_file, test_plan_line, test_fails, test_cases);
            // status = test_fails;
        }
        if (test_num < test_cases)
        {
            fprintf_stderr("%s:%u: warning: Looks like you planned %d tests but only ran %d.\n",
                   test_plan_file, test_plan_line, test_cases, test_num);
            // status = test_fails + test_cases - test_num;
        }
        else if (test_num > test_cases)
        {
            fprintf_stderr("%s:%u: warning: Looks like you planned %d tests but ran %d extra.\n",
                   test_plan_file, test_plan_line, test_cases, test_num - test_cases);
            // status = test_fails;
        }
    }

    fflush(stderr);
    test_plan_reset();
}

void test_plan_tests(int count, const char *file, unsigned line)
{
#if 0
    if (atexit(test_plan_exit) < 0)
    {
        fprintf_stderr("failed to setup atexit handler: %s\n",
                strerror(errno));
        fflush(stderr);
        exit(255);
    }
#endif

	if (test_cases)
    {
        fprintf_stderr(
                "%s:%u: error: You tried to plan twice!\n",
                file, line);
        
        fflush(stderr);
        exit(255);
    }
    else
	{
        if (!count)
        {
            fprintf_stderr("%s:%u: warning: You said to run 0 tests!  You've got to run "
                    "something.\n", file, line);
            fflush(stderr);
            exit(255);
        }

        test_plan_file=file;
        test_plan_line=line;
        
        test_cases = count;
		fprintf_stderr("%s:%u: note: 1..%d\n", file, line, test_cases);
		fflush(stdout);
	}
}

int
test_diag(const char *directive, TM_UNUSED const char *reason,
	TM_UNUSED const char *file, TM_UNUSED unsigned line, const char *fmt, ...)
{
	int is_todo = directive && !strcmp(directive, "TODO");
	va_list args;

	va_start(args, fmt);

    #define PRN_BUFF_SIZE 1024
    char buf[PRN_BUFF_SIZE];
    if(fmt!=NULL)
        vsnprintf(buf, PRN_BUFF_SIZE, fmt, args);
    else
        buf[0] = 0;
    
	if (is_todo)
	{
        fprintf_stdout("# %s \n", buf);
		fflush(stdout);
	}
	else
	{
		fflush(stdout);
        fprintf_stderr("# %s \n", buf);
        fflush(stderr);
	}

	va_end(args);

	return 1;
}

int
test_ok(int passed, const char *description, const char *directive,
	const char *reason, const char *file, unsigned line,
	const char *fmt, ...)
{
	int is_todo = !passed && directive && !strcmp(directive, "TODO");
    int is_warning = !passed && directive && !strcmp(directive, "WARNING");
	int is_setup = directive && !is_todo && !strcmp(directive, "SETUP");

	if (is_setup)
	{
		if (!passed)
		{
			fflush(stdout);
			fprintf_stderr("# SETUP not ok%s%s%s%s\n",
				   description ? " - " : "",
				   description ? description : "",
				   reason ? " - " : "",
				   reason ? reason : "");
		}
	}
	else
	{
		if (!test_cases)
		{
			atexit(test_plan_exit);
			fprintf_stderr("You tried to run a test without a plan!  "
					"Gotta have a plan. at %s line %u\n", file, line);
			fflush(stderr);
			exit(255);
		}

		++test_num;
		if (!passed && !is_todo && !is_warning) {
			++test_fails;
        }
/* We dont need to print this unless we want to */
#if 0
		fprintf_stderr("%s:%u: note: %sok %d%s%s%s%s%s%s\n", file, line, passed ? "" : "not ", test_num,
			   description ? " - " : "",
			   description ? description : "",
			   directive ? " # " : "",
			   directive ? directive : "",
			   reason ? " " : "",
			   reason ? reason : "");
#endif
 }

    if (passed)
		fflush(stdout);
	else
    {
		va_list args;

		va_start(args, fmt);

		if (is_todo)
		{
/* Enable this to output TODO as warning */
#if 0             
			fprintf_stdout("%s:%d: warning: Failed (TODO) test\n", file, line);
			if (fmt)
				vprintf(fmt, args);
#endif
            ++test_todo;
			fflush(stdout);
		}
        else if (is_warning)
        {
            /* Enable this to output warning */
            fprintf_stdout("%s:%d: warning: Failed test [%s]\n", file, line, description);
            if (fmt)
            vprintf(fmt, args);
            ++test_warning;
            fflush(stdout);
        }
        else
		{
			fflush(stdout);
            #define PRN_BUFF_SIZE 1024
            char buf[PRN_BUFF_SIZE];
            if(fmt!=NULL)
                vsnprintf(buf, PRN_BUFF_SIZE, fmt, args);
            else
                buf[0] = 0;
            
            if (description) {
                fprintf_stderr("%s:%d: error: Failed test [%s]\n", file, line, description);
                fprintf_stderr("%s", buf);
            } else {
                fprintf_stderr("%s:%d: error: Failed test [", file, line);
                fprintf_stderr("%s", buf);
                fprintf_stderr("]\n");
            }
			fflush(stderr);
		}

		va_end(args);
    }

    return passed;
}

static struct ccrng_test_state test_rng;
struct ccrng_state *global_test_rng=NULL;

static int test_rng_start(const char *test_name, size_t seed_nbytes, const unsigned char *seed) {
    int status=-1;
    // The seed is diversified with the test name
    // each test will use a different random sequence even provided the same seed
    cc_require(seed!=NULL && seed_nbytes>=1,errOut);
    cc_require((status=ccrng_test_init(&test_rng,
                                       seed_nbytes,seed,
                                       test_name))==0, errOut);
    uint64_t output_bytes;
    global_test_rng=(struct ccrng_state *)&test_rng;
    ccrng_generate(global_test_rng,sizeof(output_bytes),&output_bytes);
    return status;
errOut:
    printf("Error initializing test rng: %d\n",status);
    global_test_rng=NULL;
    return -1;
}

static int test_rng_end(void) {
    if (test_rng.drbg_state !=NULL) ccrng_test_done(&test_rng);
    global_test_rng=NULL;
    return 0;
}

/* run one test, described by test, return info in test struct */
int run_one_test(struct one_test_s *test, int argc, char * const *argv, size_t seed_nbytes, const unsigned char *seed)
{
    int rc=0;
    test->executed=1;
    rc=test_rng_start(test->name,seed_nbytes,seed);
    if(test->entry==NULL || rc!=0) {
        fprintf_stdout("%s:%d: error NULL test entry or RNG error (%d)\n", __FILE__, __LINE__,rc);
        return -1;
    }

#if defined(_WIN32)
    SYSTEMTIME st, end;
   
    GetSystemTime(&st);
    test->entry(argc, argv);
    GetSystemTime(&end);
	test->duration = (end.wMinute-st.wMinute)*60*1000 + (end.wSecond-st.wSecond)*1000 + (end.wMilliseconds-st.wMilliseconds);
#else
    struct timeval start, stop;
    gettimeofday(&start, NULL);
    test->entry(argc, argv);
    gettimeofday(&stop, NULL);
    /* this may overflow... */
    test->duration=(unsigned long long) (stop.tv_sec-start.tv_sec)*1000+(stop.tv_usec/1000)-(start.tv_usec/1000);
#endif

    test->failed_tests=test_fails;
    test->actual_tests=test_num;
    test->planned_tests=test_cases;
    test->plan_file=test_plan_file;
    test->plan_line=test_plan_line;
    test->todo_tests=test_todo;
    test->warning_tests=test_warning;

    test_rng_end();
    test_plan_exit();

    return test->failed_tests;
};




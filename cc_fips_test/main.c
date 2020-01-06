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
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/sysctl.h>
#include <stdlib.h>
#include <dlfcn.h>

#include <corecrypto/cc.h>

#include "fipspost.h"
#include "fipspost_get_hmac.h"
#include "fipspost_trace.h"
#include "fipspost_trace_priv.h"

static void usage(const char *argv[]);
static struct mach_header *fipspost_dylib_get_header(void);

static void usage(const char *argv[])
{
    fprintf(stderr, "Usage: %s [-vfFN] [-m mode] [-t trace.out]\n\n"
            "Execute the FIPS POST tests under a variety of conditions.\n"
            "\t-v,--verbose    \tIncrease logging.\n"
            "\t-f,--force      \tFull test set.\n"
            "\t-F,--fail       \tForce tests to fail, but continue testing.\n"
            "\t-N,--nointegrity\tBypass the integrity checks.\n"
            "\t-m,--mode mode  \tSpecify a discrete numerical fips_mode to test.\n"
            "\t-t,--trace file \tLog tracing output, if available, to the filename.\n"
            "\t                \tReturn an error if tracing is disabled.\n"
            , argv[0]);
    exit(-1);
}

static struct mach_header *fipspost_dylib_get_header(void)
{
    // Get information about the dylib
    Dl_info dylib_info;
    memset(&dylib_info, 0, sizeof(dylib_info));
    if (!dladdr(fipspost_post, &dylib_info)) {
        fprintf(stderr, "dladdr failed\n");
        return NULL;
    }

    return (struct mach_header *)dylib_info.dli_fbase;
}

static int fipspost_trace_writer(void *ctx, const uint8_t *buf, size_t len)
{
    FILE *f = (FILE *)ctx;
    size_t ret = fwrite(buf, 1, len, f);
    if (ret != len) {
        return -1;
    }
    return 0;
}

// The current Assumption is that FIPS will be on all of the time.
// If that assumption changes this code must change
int main (int argc, const char * argv[])
{
    int fFIPSResult = CCERR_GENERIC_FAILURE;
    int fips_mode = 0;              // Default to do-nothing; if fips_mode=0 is set on the boot-args.
    const char *fipstrace_fn = NULL;
    FILE *fipstrace_out = NULL;

    for (int iCnt = 1; iCnt < argc; iCnt++)
    {
        const char* arg = argv[iCnt];
        if (!strcmp(arg, "-v") || !strcmp(arg, "--verbose"))
        {
            fips_mode |= FIPS_MODE_FLAG_VERBOSE;
        }
        else if (!strcmp(arg, "-f") || !strcmp(arg, "--force"))
        {
            fips_mode |= FIPS_MODE_FLAG_FULL;
        }
        else if (!strcmp(arg, "-F") || !strcmp(arg, "--fail"))
        {
            fips_mode |= FIPS_MODE_FLAG_FORCEFAIL;
        }
        else if (!strcmp(arg, "-N") || !strcmp(arg, "--nointegrity"))
        {
            fips_mode |= FIPS_MODE_FLAG_NOINTEG;
        }
        else if (!strcmp(arg, "-m") || !strcmp(arg, "--mode"))
        {
            fips_mode = (int)strtoll(argv[++iCnt], NULL, 10);
        }
        else if (!strcmp(arg, "-t") || !strcmp(arg, "--trace"))
        {
            fipstrace_fn = argv[++iCnt];
        }
        else
        {
            usage(argv);
        }
    }

    if (fips_mode == 0) {
        const size_t boot_args_buffer_size = 1024;
        char boot_args_buffer[boot_args_buffer_size] = {};

        size_t boot_args_buffer_length = sizeof(boot_args_buffer);

        // Default to FIPS_MODE_FLAG_FULL which means to run the FIPS POST and
        // if an error happens log it but do not fail and allow
        // the system to boot
        int fips_mode_value = FIPS_MODE_FLAG_FULL;
        int iresult = sysctlbyname("kern.bootargs", boot_args_buffer, &boot_args_buffer_length, NULL, 0);
        boot_args_buffer[sizeof(boot_args_buffer)-1] = 0;

        if (!iresult)
        {
            char* fips_str = strcasestr(boot_args_buffer, "fips_mode");
            if (NULL != fips_str)
             {
                fprintf(stderr, "A fips_mode boot arg was set:  %s\n", fips_str);
                fflush(stderr);
                sscanf(fips_str, "fips_mode=%d",  &fips_mode_value);
            }
        }

        fips_mode |= FIPS_MODE_IS_VERBOSE(fips_mode_value);
        fips_mode |= FIPS_MODE_IS_FORCEFAIL(fips_mode_value);
        fips_mode |= FIPS_MODE_IS_NOINTEG(fips_mode_value);

        if (fips_mode_value == 0 && !FIPS_MODE_IS_FULL(fips_mode))
        {
            fprintf(stderr, "Bypassing FIPS mode for user space!\n");
            fflush(stderr);
            return 0;
        }

        fips_mode |= FIPS_MODE_IS_FULL(fips_mode_value);

        // Run the POST tests
        if (FIPS_MODE_IS_VERBOSE(fips_mode))
        {
            fprintf(stderr, "About to call the FIPS_POST function in the corecrypto.dylib\n");
            fflush(stderr);
        }
    }

    /* Only allow TRACE when a filename is supplied. */
    if (fipstrace_fn) {
        fips_mode |= FIPS_MODE_FLAG_TRACE;
    } else {
        fips_mode &= ~FIPS_MODE_FLAG_TRACE;
        fprintf(stderr, "Tracing: disabled%s\n",
                fipspost_trace_vtable.fipspost_trace_start == NULL ? "" : ", but available.");
    }

    if (FIPS_MODE_IS_TRACE(fips_mode)) {
        if (fipspost_trace_vtable.fipspost_trace_start == NULL) {
            fprintf(stderr, "Tracing: disabled, not available.\n");
            fprintf(stderr, "Tracing required by test parameters; exiting.\n");
            exit(-1);
        }
        fprintf(stderr, "Tracing: enabled\n");
        fipstrace_out = fopen(fipstrace_fn, "w");
        (*fipspost_trace_vtable.fipspost_trace_start)(fips_mode, fipspost_trace_writer, fipstrace_out);
    }

    fFIPSResult = fipspost_post(fips_mode, fipspost_dylib_get_header());

    if (FIPS_MODE_IS_VERBOSE(fips_mode))
    {
        fprintf(stderr, "Returned from calling the FIPS_POST function in the corecrypto.dylib: result = %s\n", (fFIPSResult==0) ? "true" : "false");
        fflush(stderr);
    }

    if ((fFIPSResult != 0) && FIPS_MODE_IS_FULL(fips_mode))
    {
        fprintf(stderr, "FIPS_POST failed!\n");
        fflush(stderr);
    }

    if (fipstrace_out) {
        int ret = (*fipspost_trace_vtable.fipspost_trace_end)(fFIPSResult);
        fprintf(stderr, "Tracing returned: %d\n", ret);
        fclose(fipstrace_out);
    }

    return fFIPSResult;
}

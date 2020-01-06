/*
 * Copyright (c) 2017,2018 Apple Inc. All rights reserved.
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
#include <corecrypto/cc_debug.h>
#include <corecrypto/ccsha2.h>

/* CC_KERNEL requires a corecrypto include to use. */
#if CC_KERNEL
#include <libkern/libkern.h>
#endif

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_get_hmac.h"
#include "fipspost_trace.h"
#include "fipspost_trace_priv.h"

#if CC_FIPSPOST_TRACE

fipspost_trace_vtable_t fipspost_trace_vtable = {
    .fipspost_trace_start = &fipspost_trace_start,
    .fipspost_trace_end = &fipspost_trace_end,
    .fipspost_trace_clear = &fipspost_trace_clear,
};

/* Expose the precalculated HMAC for output in the results buffer. */
FIPSPOST_EXTERN_PRECALC_HMAC;

/*
 * Record the specified mode and the current test.
 */
static uint32_t fipspost_trace_fips_mode = 0;

/*
 * Save a pointer to the caller-supplied writer for use when serializing
 * output, and a supplied ctx token used by the writer.
 */
static fipspost_trace_writer_t fipspost_trace_writer;
static void *fipspost_trace_writer_ctx;

/*
 * A couple of utility macro's for writing 'plain old data' types (really
 * anything with a valid 'sizeof()' operation) and buffers.
 */
#define TRACE_POD(pod)                                                  \
    if ((*fipspost_trace_writer)(fipspost_trace_writer_ctx,             \
                (const uint8_t *)&pod, sizeof(pod))) {                  \
        goto err;                                                       \
    }

#define TRACE_BUF(buf, len)                                             \
    if ((*fipspost_trace_writer)(fipspost_trace_writer_ctx,             \
                (const uint8_t *)buf, len)) {                           \
        goto err;                                                       \
    }

/*
 * There are many, many faster ways of doing this.  But there's not many
 * simpler ways.
 *
 * For each call, look in a list for the matching string.  The current length
 * of the formal set is ~32, which would matter if this code was remotely
 * performance sensitive.  Since it's not, a O(n) search is fine.
 *
 * More sophisticated versions of this might use hash map, for example.
 */
static const char *fipspost_trace_hooks[FIPSPOST_TRACE_MAX_HOOKS];
static fipspost_trace_id_t fipspost_trace_hook_cnt = 0;

/* Local utility functions. */
static fipspost_trace_id_t fipspost_trace_hook_idx(const char *fname);

/*
 * Initialize the environment and record the preamble.  The 'ctx' is passed in
 * to the 'trace_writer' to be used as context.
 *
 * Return non-zero when tracing is not enabled.
 */
int fipspost_trace_start(uint32_t fips_mode, fipspost_trace_writer_t trace_writer, void *ctx)
{
    struct fipspost_trace_hdr hdr;

    fipspost_trace_clear();

    fipspost_trace_fips_mode = fips_mode;
    fipspost_trace_writer = trace_writer;
    fipspost_trace_writer_ctx = ctx;

    if (!fipspost_trace_is_active()) {
        goto err;
    }

    /*
     * Write out a header containing some basic pieces of information to  help
     * avoid 'sea of files all alike' syndrome.
     *
     * Note: this must be changed in sync with the userland tool for reading
     * the tracing buffer.
     */
    hdr.magic = FIPSPOST_TRACE_MAGIC;
    hdr.version = FIPSPOST_TRACE_PROTOCOL_VERSION;
    hdr.fips_mode = fipspost_trace_fips_mode;
    memcpy(hdr.integ_hmac, fipspost_precalc_hmac, FIPSPOST_PRECALC_HMAC_SIZE);
    hdr.system_flags = 0;
#if TARGET_OS_IPHONE
    hdr.system_flags |= FIPSPOST_TRACE_SYSFLAG_IPHONE;
#endif
#if TARGET_OS_OSX
    hdr.system_flags |= FIPSPOST_TRACE_SYSFLAG_OSX;
#endif
#if CC_USE_L4
    hdr.system_flags |= FIPSPOST_TRACE_SYSFLAG_L4;
#endif
#if CC_KERNEL
    hdr.system_flags |= FIPSPOST_TRACE_SYSFLAG_KERNEL;
#endif
    TRACE_BUF(&hdr, sizeof(hdr));

    /* Add a '-' at the front to reserve '0'. */
    fipspost_trace_hook_idx("-");
    /* Use '?' to indicate the end of the test sets. */
    fipspost_trace_hook_idx(FIPSPOST_TRACE_TEST_STR);

    return 0;

err:
    /* Cleanly reset to a non-impactful state. */
    fipspost_trace_clear();

    return -1;
}

/*
 * Returns non-zero if tracing has been requested for this POST run.
 */
int fipspost_trace_is_active(void)
{
    return FIPS_MODE_IS_TRACE(fipspost_trace_fips_mode) && fipspost_trace_writer != NULL;
}

/*
 * Take the unique string supplied by the caller and record in the trace
 * buffer that the event was hit.  Expects that the string is a global
 * constant, and only takes a reference.
 *
 * On error, reset the environment, discard the tracing data, and stop tracing.
 */
void fipspost_trace_call(const char *test_name)
{
    fipspost_trace_id_t id;

    if (!fipspost_trace_is_active()) {
        goto err;
    }

    id = fipspost_trace_hook_idx(test_name);
    if (id < FIPSPOST_TRACE_MAX_HOOKS) {
        TRACE_POD(id);
        return;
    }

err:
    fipspost_trace_clear();
}

/*
 * Finish the tracing process by writing out the closing string buffers.
 *
 * Returns 0 if successful, or -1 if unsuccessful and the output should be
 * discarded.
 */
int fipspost_trace_end(uint32_t result)
{
    size_t len = 0;
    fipspost_trace_id_t n;

    /*
     * Must be enough space for 0xDEADBEEF + terminating null.
     */
    const size_t status_len = strlen(FIPSPOST_TRACE_FAILURE_STR) + 10 + 1;
    char status_str[status_len];

    if (!fipspost_trace_is_active()) {
        goto err;
    }

    /* Add one final event that encodes the exit code from the POST. */
    if (result == 0) {
        fipspost_trace_call(FIPSPOST_TRACE_SUCCESS_STR);
    } else {
        snprintf(status_str, status_len, FIPSPOST_TRACE_FAILURE_STR "%08X", result);
        fipspost_trace_call(status_str);
    }

    if (!fipspost_trace_is_active()) {
        goto err;
    }

    n = FIPSPOST_TRACE_TABLE_ID;
    TRACE_POD(n);                           /* Indicate the string table is coming next. */
    TRACE_POD(fipspost_trace_hook_cnt);     /* Record the number of table entries. */

    /* Write out the string table in pascal string format. */
    for (fipspost_trace_id_t i = 0; i < fipspost_trace_hook_cnt; i++) {
        len = strlen(fipspost_trace_hooks[i]) + 1;
        if (len > FIPSPOST_TRACE_MAX_EVENT_LEN) {
            goto err;
        }
        n = len;

        /* Write the pascal string out. */
        TRACE_POD(n);
        TRACE_BUF(fipspost_trace_hooks[i], len);
    }

    fipspost_trace_clear();
    return 0;

err:
    fipspost_trace_clear();
    return -1;
}

/*
 * Find the supplied string in the lookup table.  The table as a whole
 * gets serialized during the output phase.
 *
 * This is also used to register individual tests and provide an
 * id-to-string mapping for them.
 */
static fipspost_trace_id_t fipspost_trace_hook_idx(const char *fname)
{
    if (fname == NULL) {
        return FIPSPOST_TRACE_MAX_HOOKS;
    }

    for (int i = 0; i < fipspost_trace_hook_cnt; i++) {
        if (fipspost_trace_hooks[i] == NULL) {
            /* Shouldn't be any NULLs; somethings gone wrong. */
            return FIPSPOST_TRACE_MAX_HOOKS;
        }

        /*
         * Because the strings are required to be constant, we can cheat
         * and compare the address instead of comparing the entire string.
         */
        if (fname == fipspost_trace_hooks[i]) {
            return i;
        }
    }
    if (fipspost_trace_hook_cnt == FIPSPOST_TRACE_MAX_HOOKS) {
        return FIPSPOST_TRACE_MAX_HOOKS;
    }

    fipspost_trace_hooks[fipspost_trace_hook_cnt] = fname;
    return fipspost_trace_hook_cnt++;
}

/*
 * General utility function to reset the context back to empty.
 */
void fipspost_trace_clear(void)
{
    fipspost_trace_fips_mode = 0;
    fipspost_trace_writer = NULL;
    fipspost_trace_hook_cnt = 0;
}

#else

/*
 * Tracing is disabled in this binary.
 */
fipspost_trace_vtable_t fipspost_trace_vtable = {
    .fipspost_trace_start = NULL,
    .fipspost_trace_end = NULL,
    .fipspost_trace_clear = NULL,
};

#endif

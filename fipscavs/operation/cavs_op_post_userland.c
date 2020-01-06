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

#include "cavs_common.h"
#include "cavs_remote.h"
#include "cavs_op.h"
#include "cavs_io.h"

/* One of the rare tests that doesn't bother with a vector file. */

/* Included in cavs_io_struct.h as part of the IO declarations. */
#define CAVS_OP_HEADER "cavs_op_post.h"
#include "cavs_io_struct.h"

#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

#include "corecrypto/fipspost.h"
#include "corecrypto/fipspost_get_hmac.h"
#include "corecrypto/fipspost_trace_priv.h"

static uint8_t cavs_op_post_request(void *req);

CAVS_OP_REGISTER(CAVS_VECTOR_POST, cavs_op_post_request);
CAVS_IO_REGISTER_STRUCT(CAVS_VECTOR_POST, cavs_op_post);

static uint8_t cavs_op_post_request(void *req)
{
    struct cavs_op_post *request = (struct cavs_op_post *)req;

    char cmd[1024];
    struct stat st;
    memset(&st, 0, sizeof(st));

    /* Acquire some overrides from the environment. */
    const char *cc_bin = getenv("FIPS_CC_FIPS_TEST_PATH");
    if (!cc_bin) {
        cc_bin = "/usr/libexec/cc_fips_test";
    }
    const char *cc_raw = getenv("FIPS_CC_FIPS_RAW_OUT");
    if (!cc_raw) {
        cc_raw = "/var/tmp/cc_fips_trace_raw";
    }

    const char *dylib_path = getenv("FIPS_DYLIB_PATH");
    if (!dylib_path) {
        dylib_path = ".";
    }

    /*
     * Create the command to be executed; the DYLD_LIBRARY_PATH override is
     * useful for both testing locally as well as during an actual test run
     * when a pre-made dylib is placed in the current directory.
     */
    snprintf(cmd, 1024, "DYLD_LIBRARY_PATH=%s %s -t %s -m %d",
            dylib_path, cc_bin, cc_raw, request->fips_mode);
    if (system(cmd)) {
        errorf("command failed: %s", cmd);
        return CAVS_STATUS_FAIL;
    }

    /* Collect the output from the test for parsing. */
    if (stat(cc_raw, &st)) {
        errorf("failed to stat trace file");
        return CAVS_STATUS_FAIL;
    }

    size_t len = (size_t)st.st_size;
    if (len == 0 || len >= FIPSPOST_TRACE_MAX_BUFFER) {
        errorf("Result file exceeded maximum size");
        return CAVS_STATUS_FAIL;
    }

    FILE *f = fopen(cc_raw, "r");
    if (!f) {
        errorf("failed to open raw trace file");
        return CAVS_STATUS_FAIL;
    }
    if (fread(cavs_op_scratch_output, 1, len, f) != len) {
        errorf("Failed to read expected bytes; trying anyways");
    }
    fclose(f);

    /* Remove the raw file and indicate success. */
    unlink(cc_raw);

    return cavs_remote_write_buffer(cavs_op_scratch_output, (uint32_t)len);
}

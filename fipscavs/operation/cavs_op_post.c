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

#include "corecrypto/fipspost.h"
#include "corecrypto/fipspost_get_hmac.h"
#include "corecrypto/fipspost_trace_priv.h"

#if CC_USE_L4
#include <libSEPOS.h>
#elif CC_KERNEL
#else
#error Unsupported target - userland should use cavs_op_post_userland.c
#endif

static uint8_t cavs_op_post_request(void *req);
static int cavs_op_trace_writer(void *c, const uint8_t *buf, size_t len);

CAVS_OP_REGISTER(CAVS_VECTOR_POST, cavs_op_post_request);
CAVS_IO_REGISTER_STRUCT(CAVS_VECTOR_POST, cavs_op_post);

static int cavs_op_trace_writer(void *c, const uint8_t *buf, size_t len)
{
    int *used = (int *)c;

    /* Check for overflow. */
    if (*used + len > CAVS_OP_MAX_LEN) {
        errorf("trace exceeded buffer length");
        return -1;
    }

    /* Copy the data in. */
    memcpy(cavs_op_scratch_output + *used, buf, len);
    *used += len;

    return 0;
}

static uint8_t cavs_op_post_request(void *req)
{
    struct cavs_op_post *request = (struct cavs_op_post *)req;
    int ret;
    int used = 0;
    int fips_mode = request->fips_mode;

    if (fipspost_trace_vtable.fipspost_trace_start == NULL) {
        errorf("unsupported module");
        return CAVS_STATUS_FAIL;
    }

    if (FIPS_MODE_IS_TRACE(fips_mode)) {
        (*fipspost_trace_vtable.fipspost_trace_start)(fips_mode,
                cavs_op_trace_writer, &used);
    } else {
        /*
         * If tracing isn't enabled, write just the preamble and the postamble
         * for ease-of-parsing.
         */
        (*fipspost_trace_vtable.fipspost_trace_start)(
                fips_mode | FIPS_MODE_FLAG_TRACE,
                cavs_op_trace_writer, &used);
    }

#if CC_USE_L4
    ret = fipspost_post(fips_mode, &_mh_execute_header);
#elif CC_KERNEL
    ret = fipspost_post(fips_mode, NULL);
#else
#error Unsupported target - userland should use cavs_op_post_userland.c
#endif

    /* Close the trace. */
    (*fipspost_trace_vtable.fipspost_trace_end)(ret);

    return cavs_remote_write_buffer(cavs_op_scratch_output, used);
}

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

#include "cavs_dispatch.h"
#include "cavs_dispatch_priv.h"
#include "cavs_op.h"
#include "cavs_io.h"

#if CAVS_IO_ENABLE_CPRINT
#include <stdio.h>
#endif

/* Serialization target for requests. */
static uint8_t cavs_dispatch_request[CAVS_OP_MAX_LEN];

/* Statically allocated response buffer, valid until next request. */
static uint8_t cavs_dispatch_result[CAVS_OP_MAX_LEN];

/*
 * Dispatch each call to the appropriate target.
 *
 * For userland vectors, there's no point to serialize them so the dispatch
 * function takes the direct request pointer.  For the remote targets, the
 * request is serialized into the cavs_dispatch_request buffer for
 * transmission.  The two cavs_dispatch_* functions then record the results of
 * the vector - if any are received - in the cavs_dispatch_result buffer.  A
 * pointer to this buffer is returned to the caller.
 *
 * The caller is expected to make use of the contents of that buffer
 * immediately, as it will not be persisted after the next call to cavs_digest.
 */
int cavs_dispatch(cavs_target target, cavs_vector vector, void *request,
        uint8_t **result, size_t *result_len)
{
    int ret;
    size_t len = CAVS_OP_MAX_LEN;
    size_t request_len = cavs_io_serialize(vector, request, cavs_dispatch_request);
    if (request_len == 0) {
        errorf("failed to serialize request: %s", cavs_vector_to_string(vector));
        return CAVS_STATUS_FAIL;
    }

    *result = NULL;
    *result_len = 0;

    switch (target) {
    case CAVS_TARGET_USER:
        /* Follow this path so that the IO routines are always exercised. */
        ret = cavs_dispatch_user(vector, cavs_dispatch_request, request_len, cavs_dispatch_result, &len);
        break;
    case CAVS_TARGET_KERNEL:
        ret = cavs_dispatch_kernel(vector, cavs_dispatch_request, request_len, cavs_dispatch_result, &len);
        break;
    case CAVS_TARGET_L4:
    case CAVS_TARGET_TRNG:
        ret = cavs_dispatch_l4(vector, cavs_dispatch_request, request_len, cavs_dispatch_result, &len);
        break;
    default:
        errorf("unknown target");
        return CAVS_STATUS_FAIL;
    }

#if CAVS_IO_ENABLE_CPRINT
    /* Generate a /tmp/vector_log.c file suitable for unittests. */
    static int vector_hit_map[CAVS_VECTOR_LAST] = { 0 };
    if (ret != CAVS_STATUS_OK || vector_hit_map[vector] == 0) {
        cavs_io_log_dispatch(vector, request, *result_len, len, cavs_dispatch_result);
        vector_hit_map[vector] = 1;
    }
#endif

    /*
     * If the caller supplied a non-zero result_len, then require the returned
     * amount to be equal to it.
     */
    if (ret != CAVS_STATUS_OK) {
        errorf("%s/%s failed: dispatch error", cavs_target_to_string(target),
                cavs_vector_to_string(vector));
        ret = CAVS_STATUS_FAIL;
    } else {
        if (*result_len == 0 || len == *result_len) {
            *result = cavs_dispatch_result;
            *result_len = len;
        } else {
            errorf("%s/%s failed: invalid buffer length: expected %zu, got %zu",
                    cavs_target_to_string(target), cavs_vector_to_string(vector),
                    *result_len, len);
            ret = CAVS_STATUS_FAIL;
        }
    }

    return ret;
}



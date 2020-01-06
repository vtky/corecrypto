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

#include "cavs_vector_ec_prim_one_pass_dh.h"

#include "cavs_op_ec.h"

#include <corecrypto/ccrng_ecfips_test.h>

CAVS_OP_REGISTER(CAVS_VECTOR_EC_FUNC_DH_INIT, cavs_op_ec_dh_compute_request);
CAVS_OP_REGISTER(CAVS_VECTOR_EC_FUNC_DH_RESP, cavs_op_ec_dh_compute_request);
CAVS_OP_REGISTER(CAVS_VECTOR_EC_VAL_DH_INIT, cavs_op_ec_dh_compute_request);
CAVS_OP_REGISTER(CAVS_VECTOR_EC_VAL_DH_RESP, cavs_op_ec_dh_compute_request);

static uint8_t cavs_op_ec_dh_compute_request(void *req)
{
    struct cavs_op_ec *request = (struct cavs_op_ec *)req;

    /*
     * Place all of the expected result values directly into the scratch
     * buffer instead of copying them from intermediaries.
     */
    uint8_t *ret = cavs_op_scratch_output;
    uint32_t *computed_key_len = (uint32_t *)(ret + 1);
    uint32_t *result_len = (computed_key_len + 1);

    *computed_key_len = (uint32_t)cavs_vector_ec_dh_get_computed_key_sz(request->key_sz);
    *result_len = (uint32_t)cavs_vector_ec_dh_get_result_sz(request->key_sz);

    uint8_t *computed_key = (uint8_t *)(result_len + 1);
    uint8_t *out_x = computed_key + *computed_key_len;
    uint8_t *out_y = out_x + *result_len;

    /* Compute the EC-DH vector vector results. */
    switch(request->vector) {
    case CAVS_VECTOR_EC_FUNC_DH_INIT:
    case CAVS_VECTOR_EC_FUNC_DH_RESP: {
        struct ccrng_state *rng = ccrng(NULL);
        *ret = cavs_vector_ec_dh_compute(request->key_sz, rng,
                request->qx_len, request->qx, request->qy_len, request->qy,
                0, NULL, 0, NULL, 0, NULL, *computed_key_len, computed_key,
                *result_len, out_x, *result_len, out_y);
        break;
    }
    case CAVS_VECTOR_EC_VAL_DH_INIT:
    case CAVS_VECTOR_EC_VAL_DH_RESP: {
        struct ccrng_ecfips_test_state rng;
        ccrng_ecfips_test_init(&rng, request->d_len, request->d);
        *ret = cavs_vector_ec_dh_compute(request->key_sz, (struct ccrng_state *)&rng,
                request->qx_len, request->qx, request->qy_len, request->qy,
                request->d_len, request->d, request->r_len, request->r,
                request->s_len, request->s, *computed_key_len, computed_key,
                0, NULL, 0, NULL);
        *result_len = 0;
        break;
    }
    default:
        errorf("unknown EC DH Compute request: %s", cavs_vector_to_string(request->vector));
        return CAVS_STATUS_FAIL; 
    }

    uint32_t len = sizeof(uint8_t) +                /* ret */
        (sizeof(uint32_t) * 2) +                    /* computed_key_len and result_len */
        (*computed_key_len + (*result_len * 2));    /* computed_key, out_x, out_y */

    return cavs_remote_write_buffer(cavs_op_scratch_output, len);
}

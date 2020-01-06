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

#include "cavs_vector_montecarlo.h"

#include "cavs_op_cipher.h"

static uint8_t cavs_op_montecarlo_init_request(void *req);
static uint8_t cavs_op_montecarlo_op_request(void *req);
static uint8_t cavs_op_montecarlo_finish_request(void *req);

CAVS_OP_REGISTER(CAVS_VECTOR_MONTECARLO_ENC_INIT, cavs_op_montecarlo_init_request);
CAVS_OP_REGISTER(CAVS_VECTOR_MONTECARLO_DEC_INIT, cavs_op_montecarlo_init_request);
CAVS_OP_REGISTER(CAVS_VECTOR_MONTECARLO_ENC_OP, cavs_op_montecarlo_op_request);
CAVS_OP_REGISTER(CAVS_VECTOR_MONTECARLO_DEC_OP, cavs_op_montecarlo_op_request);
CAVS_OP_REGISTER(CAVS_VECTOR_MONTECARLO_FINISH, cavs_op_montecarlo_finish_request);
CAVS_OP_REGISTER(CAVS_VECTOR_XTS_ENC_INIT, cavs_op_montecarlo_init_request);
CAVS_OP_REGISTER(CAVS_VECTOR_XTS_DEC_INIT, cavs_op_montecarlo_init_request);
CAVS_OP_REGISTER(CAVS_VECTOR_XTS_OP, cavs_op_montecarlo_op_request);
CAVS_OP_REGISTER(CAVS_VECTOR_XTS_FINISH, cavs_op_montecarlo_finish_request);

static uint8_t cavs_op_montecarlo_init_request(void *req)
{
    struct cavs_op_cipher *request = (struct cavs_op_cipher *)req;

    size_t ctx_sz;
    int enc;
    struct cavs_vector_cipher_ctx *ctx = (struct cavs_vector_cipher_ctx *)cavs_op_scratch_extra;
    uint8_t result = CAVS_STATUS_FAIL;

    if (request->vector == CAVS_VECTOR_MONTECARLO_ENC_INIT ||
            request->vector == CAVS_VECTOR_XTS_ENC_INIT) {
        enc = 1;
    } else {
        enc = 0;
    }

    ctx_sz = cavs_vector_montecarlo_init(NULL, request->vector,
            request->cipher, request->aes_is, request->mode, enc, request->key_len,
            request->key, request->extra_len, request->extra);
    if (ctx_sz == CAVS_STATUS_FAIL) {
        errorf("unsupported cipher mode: %s", cavs_cipher_mode_to_string(request->mode));
        return CAVS_STATUS_FAIL;
    }

    if (ctx_sz > CAVS_OP_MAX_LEN) {
        errorf("montecarlo context too large: %zu", ctx_sz);
        return CAVS_STATUS_FAIL;
    }

    memset(cavs_op_scratch_extra, 0, CAVS_OP_MAX_LEN);
    if (cavs_vector_montecarlo_init(ctx, request->vector,
            request->cipher, request->aes_is, request->mode, enc, request->key_len,
            request->key, request->extra_len, request->extra) != CAVS_STATUS_OK) {
        errorf("failed to initialize");
        return CAVS_STATUS_FAIL;
    }

    result = CAVS_STATUS_OK;

    return cavs_remote_write_buffer(&result, sizeof(uint8_t));
}

static uint8_t cavs_op_montecarlo_op_request(void *req)
{
    struct cavs_op_cipher *request = (struct cavs_op_cipher *)req;
    struct cavs_vector_cipher_ctx *ctx = (struct cavs_vector_cipher_ctx *)cavs_op_scratch_extra;
    int result;

    result = cavs_vector_montecarlo_op(request->mode, ctx, request->input_len,
            request->input, cavs_op_scratch_output);
    if (result != CAVS_STATUS_OK) {
        errorf("failed cipher op");
        return CAVS_STATUS_FAIL;
    }

    return cavs_remote_write_buffer(cavs_op_scratch_output, request->input_len);
}

static uint8_t cavs_op_montecarlo_finish_request(void *req)
{
    uint8_t result = 1;

    req = req;

    memset(cavs_op_scratch_extra, 0, CAVS_OP_MAX_LEN);
    return cavs_remote_write_buffer(&result, sizeof(uint8_t));
}

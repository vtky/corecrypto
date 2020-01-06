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

#include "cavs_io.h"
#include "cavs_remote.h"
#include "cavs_op.h"

#include "cavs_driver_generic.h"

static uint8_t cavs_generic_request[CAVS_OP_MAX_LEN];         /* Where the parsed structure goes. */
static size_t *cavs_generic_out_len;                         /* Number of bytes to be sent. */
static uint8_t *cavs_generic_out_buf;                        /* Used to buffer up large responses. */

static uint8_t cavs_generic_parse_request(void **request, cavs_vector *vector, uint8_t *buf, size_t buf_len);

/*
 * Entrypoint for calls into the vectors from the control system. The output
 * parameters must come populated with the buffer and maximum allowed buffer
 * size for the vector result.
 *
 * This function accepts the request, parses, and dispatchs to the appropriate
 * operation implementation of that vector.
 */
uint8_t cavs_generic_cavs_request(uint8_t *buf, size_t buf_len, uint8_t *result, size_t *result_len)
{
    void *req = NULL;
    cavs_vector vector;
    uint8_t ret = cavs_generic_parse_request(&req, &vector, buf, buf_len);
    if (ret != CAVS_STATUS_OK) {
        errorf("vector read error: %d", ret);
        return ret;
    }

    /* Stash the output pointers for cavs_remote_write_buffer, called from the ops. */
    cavs_generic_out_len = result_len;
    cavs_generic_out_buf = result;

    /*
     * Dispatch to the appropriate operation; each operation calls back to
     * cavs_remote_write_buffer to return the result.
     */
    return cavs_op(vector, req);
}

/*
 * Once the cavs_remote_write_buffer has been called, the contents of the
 * request buffer is overwritten to prevent any lingering pointers from
 * refering to those memory regions - this can cause bugs when messages exceed
 * the sizing boundry.
 */
uint8_t cavs_remote_write_buffer(uint8_t *buf, uint32_t len)
{
    if (*cavs_generic_out_len < len) {
        errorf("attempted to write too much data, tried: %d, max: %zu", len, *cavs_generic_out_len);
        return CAVS_STATUS_FAIL;
    }

    /* Copy the result and len to the expecting buffers. */
    memcpy(cavs_generic_out_buf, buf, len);
    *cavs_generic_out_len = len;

    memset(cavs_generic_request, 0xFD, CAVS_OP_MAX_LEN);

    return CAVS_STATUS_OK;
}

/*
 * Parse the supplied buf into the cavs_remote_request buffer, which is used as
 * a staging ground for the construction of the appropriate request object.
 */
static uint8_t cavs_generic_parse_request(void **request, cavs_vector *vector, uint8_t *buf, size_t buf_len)
{
    uint32_t vector_len;

    if (buf_len < cavs_io_sizeof_header()) {
        /* Too little data is available to be useful; shouldn't ever be the first read. */
        errorf("data block too small");
        return CAVS_STATUS_FAIL;
    }

    /* See if the entire vector has been received. */
    cavs_io_read_header(buf, &vector_len, vector);
    if (vector_len > CAVS_OP_MAX_LEN) {
        /* Exceeds currently supported buffer size. */
        errorf("structure too large");
        return CAVS_STATUS_FAIL;
    }

    if (buf_len != vector_len) {
        errorf("structure size mismatch");
        return CAVS_STATUS_FAIL;
    }

    memset(cavs_generic_request, 0, CAVS_OP_MAX_LEN);

    *vector = cavs_io_deserialize(cavs_generic_request, buf);
    if (*vector == CAVS_VECTOR_UNKNOWN) {
        errorf("failed to parse vector.");
        return CAVS_STATUS_FAIL;
    }

    *request = cavs_generic_request;
    return CAVS_STATUS_OK;
}

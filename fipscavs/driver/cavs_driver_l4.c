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

#include <libSEPOS.h>
#include <if_Testing.h>

#include <stdio.h>

#include "cavs_common.h"

#include "cavs_io.h"
#include "cavs_remote.h"
#include "cavs_op.h"
#include "cavs_l4.h"
#include "cavs_driver_l4.h"

enum test_fips_error_codes {
    TEST_FAIL_IN_GT_OUT = TEST_FIRST_CUSTOM,        // 16
    TEST_FAIL_TEST_UNKNOWN,
    TEST_FAIL_DATA_READ_MISSING_HEADER,
    TEST_FAIL_DATA_READ_TOO_LARGE,
    TEST_FAIL_DATA_READ_ACTUAL,
    TEST_FAIL_DATA_READ_PARSE,
    TEST_FAIL_DATA_READ_MORE,
    TEST_FAIL_DATA_WRITE_ACTUAL,
    TEST_FAIL_TEST_FAILED,
    TEST_FAIL_TEST_INVALID_LEN,
    TEST_FAIL_TEST_OUTPUT_TOO_BIG,
};

static uint8_t cavs_l4_read_request(void **request, cavs_vector *vector);
static uint8_t cavs_l4_cont_write_buffer(void);

/* Reserve a bunch of space to handle inputs and outputs. */
static uint8_t cavs_l4_in_buf[CAVS_OP_MAX_LEN];      /* Used to receive large requests. */
static uint8_t *cavs_l4_in_wlk = cavs_l4_in_buf;    /* Tracks the location of new input bytes. */
static uint8_t cavs_l4_wksp[CAVS_OP_MAX_LEN];        /* Where the parsed structure goes. */
static uint32_t cavs_l4_out_len = 0;                /* Number of bytes remaining to be sent. */
static uint8_t cavs_l4_out_buf[CAVS_OP_MAX_LEN];     /* Used to buffer up large responses. */
static uint8_t *cavs_l4_out_wlk = cavs_l4_out_buf;  /* Tracks the already sent data. */

static uint8_t cavs_l4_read_request(void **request, cavs_vector *vector)
{
    uint32_t actual;
    uint32_t in_amount = test_data_in_size();

    uint32_t vector_len;

    if (in_amount < cavs_io_sizeof_header() && cavs_l4_in_wlk == cavs_l4_in_buf) {
        /* Too little data is available to be useful; shouldn't ever be the first read. */
        return TEST_FAIL_DATA_READ_MISSING_HEADER;
    }

    if (in_amount > CAVS_OP_MAX_LEN ||
            ((cavs_l4_in_wlk - cavs_l4_in_buf) + in_amount) > CAVS_OP_MAX_LEN) {
        /* Exceeds currently supported buffer size. */
        return TEST_FAIL_DATA_READ_TOO_LARGE;
    }

    if (cavs_l4_in_wlk == cavs_l4_in_buf) {
        /* Starting a new vector; zero the buffer. */
        memset(cavs_l4_in_buf, 0, CAVS_OP_MAX_LEN);
    }

    actual = test_data_read(cavs_l4_in_wlk, 0, in_amount);
    if (actual != in_amount) {
        cavs_l4_in_wlk = cavs_l4_in_buf;
        return TEST_FAIL_DATA_READ_ACTUAL;
    }
    cavs_l4_in_wlk += actual;

    /* See if the entire vector has been received. */
    cavs_io_read_header(cavs_l4_in_buf, &vector_len, vector);
    if (vector_len > CAVS_OP_MAX_LEN) {
        /* Exceeds currently supported buffer size. */
        return TEST_FAIL_DATA_READ_TOO_LARGE;
    }

    if ((cavs_l4_in_wlk - cavs_l4_in_buf) < vector_len) {
        return TEST_FAIL_DATA_READ_MORE;
    }

    /*
     * Early out the CAVS_VECTOR_META_CONTINUE; the cavs_io module doesn't need
     * to know about it and it's handled exclusively by the L4 components.
     */
    if (*vector == CAVS_VECTOR_META_CONTINUE) {
        return TEST_PASS;
    }

    memset(cavs_l4_wksp, 0, CAVS_OP_MAX_LEN);
    /* This fails via assertion, rather than via return. */
    *vector = cavs_io_deserialize(cavs_l4_wksp, cavs_l4_in_buf);
    if (*vector == CAVS_VECTOR_UNKNOWN) {
        return TEST_FAIL_DATA_READ_PARSE;
    }

    *request = cavs_l4_wksp;
    return TEST_PASS;
}

/*
 * Once the cavs_l4_write_buffer has been called, the contents of the
 * workspace and input buffers are overwritten to prevent any lingering
 * pointers from refering to those memory regions - this can cause bugs
 * when messages exceed the CAVS_L4_MAX_MSG_SZ boundry and require
 * META_CONTINUE messages to retrieve the full result.
 */
uint8_t cavs_remote_write_buffer(uint8_t *buf, uint32_t len)
{
    cavs_l4_out_wlk = cavs_l4_out_buf;

    /*
     * Lay down a buffer with [size],[buffer] so the receiving side knows how
     * many bytes to expect.
     */
    memcpy(cavs_l4_out_buf, &len, sizeof(len));
    memcpy(cavs_l4_out_buf + sizeof(len), buf, len);
    cavs_l4_out_len = sizeof(len) + len;

    memset(cavs_l4_in_buf, 0xFC, CAVS_OP_MAX_LEN);
    memset(cavs_l4_wksp, 0xFD, CAVS_OP_MAX_LEN);

    cavs_l4_cont_write_buffer();

    return TEST_PASS;
}

/* Continue sending output when indicated by the receiver. */
static uint8_t cavs_l4_cont_write_buffer(void)
{
    uint32_t actual;

    actual = CC_MIN(cavs_l4_out_len, CAVS_L4_MAX_MSG_SZ);
    actual = test_data_write(cavs_l4_out_wlk, 0, actual);
    cavs_l4_out_wlk += actual;
    cavs_l4_out_len -= actual;

    return TEST_PASS;
}

/*
 * Entrypoint for calls into the vectors from the seputil tool.
 */
uint8_t cavs_l4_cavs_request(void)
{
    void *req = NULL;
    cavs_vector vector;
    uint8_t ret = cavs_l4_read_request(&req, &vector);
    if (ret != TEST_PASS) {
        if (ret == TEST_FAIL_DATA_READ_MORE) {
            return TEST_PASS;
        }
        debugf("vector read error: %d", ret);

        /* Discard all of the currently supplied data and reset the system. */
        cavs_l4_in_wlk = cavs_l4_in_buf;
        cavs_l4_out_wlk = cavs_l4_out_buf;
        cavs_l4_out_len = 0;

        return ret;
    }

    /*
     * Reset the input walker pointer to the beginning of the buffer for
     * the next vector.
     */
    cavs_l4_in_wlk = cavs_l4_in_buf;

    if (vector == CAVS_VECTOR_META_CONTINUE) {
        return cavs_l4_cont_write_buffer();
    }
    return cavs_op(vector, req);
}

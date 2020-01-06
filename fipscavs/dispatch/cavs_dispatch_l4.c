/*
 * Copyright (c) 2016,2017,2018 Apple Inc. All rights reserved.
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

#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>
#include <spawn.h>
#include <unistd.h>
#include <fcntl.h>

#include "cavs_common.h"
#include "cavs_io.h"
#include "cavs_dispatch_priv.h"

#include "cavs_driver_l4.h"

/*
 * Communicating with the SEP utilizes the SEP unit test API to dispatch
 * vectors through the filesystem, and then into the SEP process defined in the
 * corecrypto/fipscavs/l4/main.c file.
 *
 * This process then acquires the information written in CAVS_TEST_IN_PATH and
 * executes the vector, leaving whatever appropriate artifacts (test specific) in
 * the supplied outbound buffer, which is then written to CAVS_TEST_OUT_PATH.
 *
 * The test writer would call cavs_l4_send() to write the necessary blobs to
 * disk and execute the seputil process.  Upon return from that method, a call
 * to cavs_l4_receive() returns the results of the vector operation.
 */

#define CAVS_TEST_IN_PATH "/tmp/test-in.bin"
#define CAVS_TEST_OUT_PATH "/tmp/test-out.out"

static int seputil_exec();
static size_t cavs_l4_receive_file(FILE **f);
static int cavs_l4_send(void *buf, size_t buf_len);
static size_t cavs_l4_receive(uint8_t *response);
static int cavs_l4_meta_continue(void);

static int seputil_exec()
{
    pid_t pid;
    int ret, status;
    posix_spawn_file_actions_t action;

    char *argv[] = {
        "/usr/libexec/seputil",
        "--test-run",
        "sks/cavs",
        "--test-input",
        CAVS_TEST_IN_PATH,
        "--test-output",
        CAVS_TEST_OUT_PATH,
        NULL};

    posix_spawn_file_actions_init(&action);
    posix_spawn_file_actions_addopen (&action, STDOUT_FILENO, "/dev/null", O_RDONLY, 0);

    ret = posix_spawn(&pid, argv[0], &action, NULL, argv, NULL);
    posix_spawn_file_actions_destroy(&action);
    if (ret != 0) {
        errorf("Failed to posix_spawn: %d", ret);
        return ret;
    }
    waitpid(pid, &status, 0);

    if (WIFEXITED(status)) {
        status = WEXITSTATUS(status);
        if (status != 0) {
            errorf("Exit Status: %d", status);
        }
        return status;
    }
    if (WIFSIGNALED(status)) {
        errorf("Termination Signal: %d", WTERMSIG(status));
        return WTERMSIG(status);
    }
    return 0;
}

static int cavs_l4_send(void *buf, size_t buf_len)
{
    uint8_t *buf_wlk;
    size_t ret;

    /* Use the walker to send the data in CAVS_L4_MAX_MSG_SZ chunks. */
    buf_wlk = buf;

    while (buf_len) {
        uint32_t len = CC_MIN((int)buf_len, CAVS_L4_MAX_MSG_SZ);
        FILE *f = fopen(CAVS_TEST_IN_PATH, "w");
        if (f == NULL) {
            errorf("failed to open '%s'", CAVS_TEST_IN_PATH);
            return CAVS_STATUS_FAIL;
        }

        ret = fwrite(buf_wlk, len, 1, f);
        fclose(f);
        if (ret != 1) {
            errorf("failed to write send buffer");
            return CAVS_STATUS_FAIL;
        }

        ret = seputil_exec();
        if (ret != 0) {
            errorf("SEPUtil call failed: %zu", ret);
            return CAVS_STATUS_FAIL;
        }
        buf_len -= len;
        buf_wlk += len;
    }

    return CAVS_STATUS_OK;
}

static size_t cavs_l4_receive_file(FILE **f)
{
    struct stat s;
    off_t buf_len;

    *f = NULL;

    if (stat(CAVS_TEST_OUT_PATH, &s) < 0) {
        errorf("stat call failed: %d", errno);
        return CAVS_STATUS_FAIL;
    }
    if ((size_t)s.st_size < sizeof(uint32_t)) {
        errorf("result file not large enough for length");
        return CAVS_STATUS_FAIL;
    }

    buf_len = s.st_size;
    *f = fopen(CAVS_TEST_OUT_PATH, "r");
    if (!*f) {
        errorf("fopen call failed: %d", errno);
        return CAVS_STATUS_FAIL;
    }

    return buf_len;
}

static int cavs_l4_meta_continue(void)
{
    static struct { uint32_t len; cavs_vector vector; } cavs_l4_meta_continue = {
        .len = 0,
        .vector = CAVS_VECTOR_META_CONTINUE
    };

    assert(sizeof(cavs_l4_meta_continue) == cavs_io_sizeof_header());

    return cavs_l4_send(&cavs_l4_meta_continue, cavs_io_sizeof_header());
}

/*
 * Returns the size of the resulting buffer and copies the contents into
 * response if supplied.
 */
static size_t cavs_l4_receive(uint8_t *response)
{
    int ret;
    uint32_t vector_len, len;
    off_t buf_len;
    FILE *f;
    uint8_t *wlk = response;

    buf_len = cavs_l4_receive_file(&f);
    if (!f) {
        errorf("fopen call failed: %d", errno);
        return CAVS_STATUS_FAIL;
    }

    /* Get the length of the result buffer. */
    ret = (int)fread(&len, sizeof(len), 1, f);
    if (ret != 1) {
        errorf("fread call failed");
        fclose(f);
        return CAVS_STATUS_FAIL;
    }

    if (!response) {
        fclose(f);
        return len;
    }

    /* Store for later, to report back the full response size. */
    vector_len = len;
    buf_len -= sizeof(len);

    /* Read until satisfied. */
    while (len) {
        if (!f) {
            if (cavs_l4_meta_continue() != CAVS_STATUS_OK) {
                errorf("meta continue failed");
                return CAVS_STATUS_FAIL;
            }

            buf_len = cavs_l4_receive_file(&f);
            if (!f) {
                errorf("fopen call failed: %d", errno);
                return CAVS_STATUS_FAIL;
            }
        }

        ret = (int)fread(wlk, (size_t)buf_len, 1, f);
        if (ret != 1) {
            errorf("fread call failed");
            fclose(f);
            return CAVS_STATUS_FAIL;
        }
        len -= buf_len;
        wlk += buf_len;

        /* Close the file so that it can be recreated on continue. */
        fclose(f);
        f = NULL;
    }

    if (f) {
        /* If only the size was sent, and the size was 0, will it fall through here. */
        fclose(f);
    }
    return vector_len;
}

int cavs_dispatch_l4(cavs_vector vector, uint8_t *request_buf,
        size_t request_len, void *result, size_t *result_len)
{
    size_t receive_len;

    if (cavs_l4_send(request_buf, request_len) != CAVS_STATUS_OK) {
        debugf("cavs_l4_send failed");
        return CAVS_STATUS_FAIL;
    }

    receive_len = cavs_l4_receive(NULL);

    if (receive_len == CAVS_STATUS_FAIL || receive_len > *result_len) {
        debugf("invalid size returned data: %zu", receive_len);
        return CAVS_STATUS_FAIL;
    }

    if (cavs_l4_receive(result) != receive_len) {
        debugf("failed to read data");
        return CAVS_STATUS_FAIL;
    }

    *result_len = receive_len;

    return CAVS_STATUS_OK;
}

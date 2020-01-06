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

extern enum DriverReturn driver_open_retry(DriverHandle handle, int32_t attempts);

struct ccaes_trng_encrypt_ctx
{
    uint8_t key[CCAES_KEY_SIZE_256];
};

static int ccaes_trng_ecb_encrypt_init(const struct ccmode_ecb *ecb CC_UNUSED, ccecb_ctx *ctx,
        size_t key_len, const void *key);
static uint8_t ccaes_trng_ecb_oneshot(const struct ccaes_trng_encrypt_ctx *ctx,
        const uint8_t *input, uint8_t *output);
static int ccaes_trng_ecb_encrypt(const ccecb_ctx *ecb_ctx,
        size_t num_blk, const void *in, void *out);

const struct ccmode_ecb ccaes_trng_ecb_encrypt_mode = {
    .size = sizeof(struct ccaes_trng_encrypt_ctx),
    .block_size = CCAES_BLOCK_SIZE,
    .init = ccaes_trng_ecb_encrypt_init,
    .ecb = ccaes_trng_ecb_encrypt,
};

static int ccaes_trng_ecb_encrypt_init(const struct ccmode_ecb *ecb CC_UNUSED, ccecb_ctx *ecb_ctx,
        size_t key_len, const void *key)
{
    struct ccaes_trng_encrypt_ctx *ctx =
            (struct ccaes_trng_encrypt_ctx *)ecb_ctx;

    cc_require(key_len == CCAES_KEY_SIZE_256, err);

    memcpy(ctx->key, key, key_len);

    return 0;

err:
    return -1;
}

static int ccaes_trng_ecb_encrypt(const ccecb_ctx *ecb_ctx,
        size_t num_blk, const void *input, void *output)
{
    const struct ccaes_trng_encrypt_ctx *ctx =
            (const struct ccaes_trng_encrypt_ctx *)ecb_ctx;

    uint8_t *output_wlkr = output;
    const uint8_t *input_wlkr = input;
    int len = 0;

    /* Process each block. */
    while (num_blk) {
        cc_require(ccaes_trng_ecb_oneshot(ctx, input_wlkr, output_wlkr) == 0, err);
        len += CCAES_BLOCK_SIZE;
        input_wlkr += CCAES_BLOCK_SIZE;
        output_wlkr += CCAES_BLOCK_SIZE;
        num_blk--;
    }

    return 0;
err:
    return -1;
}

static uint8_t ccaes_trng_ecb_oneshot(const struct ccaes_trng_encrypt_ctx *ctx,
        const uint8_t *input, uint8_t *output)
{
    DriverHandle trng_driver;
    int32_t ret;
    uint8_t workspace[CCAES_KEY_SIZE_256 + CCAES_BLOCK_SIZE];

    cc_require(input != NULL, fast_fail);
    cc_require(output != NULL, fast_fail);

    /* Place the required block after the key in the workspace. */
    memcpy(workspace, ctx->key, CCAES_KEY_SIZE_256);
    memcpy(workspace + CCAES_KEY_SIZE_256, input, CCAES_BLOCK_SIZE);

    /* Open the driver. */
    trng_driver = driver_lookup(DRIVER_TAG_TRNG, 0);
    cc_require(trng_driver != THREAD_INVALID, fast_fail);
    cc_require(driver_open_retry(trng_driver, 1000000) == SDRIVER_SUCCESS, fast_fail);

    /* Send the vector structure over the AES channel. */
    ret = (int32_t)driver_write(trng_driver, MTRNG_CHANNEL_FIPS_AES,
            workspace, CCAES_KEY_SIZE_256 + CCAES_BLOCK_SIZE);
    cc_require(ret == (CCAES_KEY_SIZE_256 + CCAES_BLOCK_SIZE), fail);

    /* Receive the response. */
    ret = (int32_t)driver_read(trng_driver, MTRNG_CHANNEL_FIPS_AES, output,
            CCAES_BLOCK_SIZE);
    cc_require(ret == CCAES_BLOCK_SIZE, fail);

    /* Check to see if support is needed for multiple-read/write operations. */
    driver_close(trng_driver);
    cc_clear(CCAES_KEY_SIZE_256 + CCAES_BLOCK_SIZE, workspace);

    return 0;

fail:
    driver_close(trng_driver);
fast_fail:
    cc_clear(CCAES_KEY_SIZE_256 + CCAES_BLOCK_SIZE, workspace);
    return -1;
}
#endif

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

struct ccaes_skg_ctx
{
    uint8_t key_len;
    uint8_t key[CCAES_KEY_SIZE_256];
};

static int ccaes_skg_cbc_init(const struct ccmode_cbc *cbc CC_UNUSED, cccbc_ctx *ctx,
        size_t key_len, const void *key);
static int ccaes_skg_ecb_init(const struct ccmode_ecb *ecb CC_UNUSED, ccecb_ctx *ctx,
        size_t key_len, const void *key);
static uint8_t ccaes_skg_cipher(bool cbc, bool enc,
        const struct ccaes_skg_ctx *ctx, cccbc_iv *iv,
        const uint8_t *input, size_t num_blk, uint8_t *output);

static int ccaes_skg_cbc_encrypt(const cccbc_ctx *cbc_ctx, cccbc_iv *iv,
        size_t num_blk, const void *in, void *out);
static int ccaes_skg_cbc_decrypt(const cccbc_ctx *cbc_ctx, cccbc_iv *iv,
        size_t num_blk, const void *in, void *out);
static int ccaes_skg_ecb_encrypt(const ccecb_ctx *ecb_ctx, size_t num_blk,
        const void *in, void *out);
static int ccaes_skg_ecb_decrypt(const ccecb_ctx *ecb_ctx, size_t num_blk,
        const void *in, void *out);

const struct ccmode_cbc ccaes_skg_cbc_encrypt_mode = {
    .size = sizeof(struct ccaes_skg_ctx),
    .block_size = CCAES_BLOCK_SIZE,
    .init = ccaes_skg_cbc_init,
    .cbc = ccaes_skg_cbc_encrypt,
    .custom = NULL,
};

const struct ccmode_cbc ccaes_skg_cbc_decrypt_mode = {
    .size = sizeof(struct ccaes_skg_ctx),
    .block_size = CCAES_BLOCK_SIZE,
    .init = ccaes_skg_cbc_init,
    .cbc = ccaes_skg_cbc_decrypt,
    .custom = NULL,
};

const struct ccmode_ecb ccaes_skg_ecb_encrypt_mode = {
    .size = sizeof(struct ccaes_skg_ctx),
    .block_size = CCAES_BLOCK_SIZE,
    .init = ccaes_skg_ecb_init,
    .ecb = ccaes_skg_ecb_encrypt,
};

const struct ccmode_ecb ccaes_skg_ecb_decrypt_mode = {
    .size = sizeof(struct ccaes_skg_ctx),
    .block_size = CCAES_BLOCK_SIZE,
    .init = ccaes_skg_ecb_init,
    .ecb = ccaes_skg_ecb_decrypt,
};

static int ccaes_skg_cbc_init(const struct ccmode_cbc *cbc CC_UNUSED, cccbc_ctx *cbc_ctx,
        size_t key_len, const void *key)
{
    struct ccaes_skg_ctx *ctx =
            (struct ccaes_skg_ctx *)cbc_ctx;

    cc_require(key_len <= CCAES_KEY_SIZE_256, err);

    memcpy(ctx->key, key, key_len);
    ctx->key_len = key_len;

    return 0;

err:
    return -1;
}

static int ccaes_skg_ecb_init(const struct ccmode_ecb *ecb CC_UNUSED, ccecb_ctx *ecb_ctx,
        size_t key_len, const void *key)
{
    struct ccaes_skg_ctx *ctx =
            (struct ccaes_skg_ctx *)ecb_ctx;

    cc_require(key_len <= CCAES_KEY_SIZE_256, err);

    memcpy(ctx->key, key, key_len);
    ctx->key_len = key_len;

    return 0;

err:
    return -1;
}

static int ccaes_skg_cbc_encrypt(const cccbc_ctx *cbc_ctx, cccbc_iv *iv,
        size_t num_blk, const void *in, void *out)
{
    return ccaes_skg_cipher(true, true, (const struct ccaes_skg_ctx *)cbc_ctx,
            iv, in, num_blk, out);
}

static int ccaes_skg_cbc_decrypt(const cccbc_ctx *cbc_ctx, cccbc_iv *iv,
        size_t num_blk, const void *in, void *out)
{
    return ccaes_skg_cipher(true, false, (const struct ccaes_skg_ctx *)cbc_ctx, 
            iv, in, num_blk, out);
}

static int ccaes_skg_ecb_encrypt(const ccecb_ctx *ecb_ctx, size_t num_blk,
        const void *in, void *out)
{
    return ccaes_skg_cipher(false, true, (const struct ccaes_skg_ctx *)ecb_ctx, 
            NULL, in, num_blk, out);
}

static int ccaes_skg_ecb_decrypt(const ccecb_ctx *ecb_ctx, size_t num_blk,
        const void *in, void *out)
{
    return ccaes_skg_cipher(false, false, (const struct ccaes_skg_ctx *)ecb_ctx, 
            NULL, in, num_blk, out);
}

static uint8_t ccaes_skg_cipher(bool cbc, bool enc,
        const struct ccaes_skg_ctx *ctx, cccbc_iv *iv,
        const uint8_t *input, size_t num_blk, uint8_t *output)
{
    enum ServiceReturn sret;
    ServiceHandle skg_handle;

    /*
     * Set an upper bound on the quantity of data that can be sent in a single
     * call.  Because arg_buf is allocated on the stack, it cannot grow
     * unbounded.
     */
    if (num_blk > CCAES_SKG_MAX_BLOCKS) {
        return -1;
    }

    if (num_blk == 0) {
        return 0;
    }

    skg_handle = service_lookup(SERVICE_TAG_SKG);
    if (skg_handle == THREAD_INVALID) {
        return -1;
    }

    size_t arg_len = sizeof(struct skg_oneshot_args) + ctx->key_len +
        CCAES_BLOCK_SIZE + num_blk * CCAES_BLOCK_SIZE;
    uint8_t arg_buf[arg_len];

    struct skg_oneshot_args *args = (struct skg_oneshot_args *)arg_buf;
    args->enc = enc;
    args->cbc = cbc;
    args->key_len = ctx->key_len;
    args->iv_len = iv ? CCAES_BLOCK_SIZE : 0;
    args->input_len = (uint32_t)(CCAES_BLOCK_SIZE * num_blk);

    uint8_t *key_arg = (uint8_t *)(args + 1);
    uint8_t *iv_arg = key_arg + args->key_len;
    uint8_t *input_arg = iv_arg + args->iv_len;
    memcpy(key_arg, ctx->key, args->key_len);
    if (iv) {
        memcpy(iv_arg, iv, args->iv_len);
    }
    memcpy(input_arg, input, args->input_len);

    sret = service_call_args(skg_handle, IF_SERVICE, MSERVICE_SKG_ONESHOT,
            SERVICE_ARGMODE_EXCHANGE, (unsigned int)arg_len, arg_buf);
    cc_require(sret == SSERVICE_SUCCESS, err);

    /* Copy the result into the supplied buffer. */
    memcpy(output, input_arg, args->input_len);

    /* Update the IV for subsequent calls. */
    if (iv) {
        if (enc) {
            /* Update the IV with the last cipher block from the output. */
            CC_MEMCPY(iv, output + (num_blk - 1) * CCAES_BLOCK_SIZE, CCAES_BLOCK_SIZE);
        } else {
            /* Update the IV with the last cipher block from the input. */
            CC_MEMCPY(iv, input + (num_blk - 1) * CCAES_BLOCK_SIZE, CCAES_BLOCK_SIZE);
        }
    }

    cc_clear(arg_len, arg_buf);
    return 0;

err:
    cc_clear(arg_len, arg_buf);
    return -1;
}
#endif

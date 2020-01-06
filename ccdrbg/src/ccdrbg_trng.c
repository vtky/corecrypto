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

struct ccdrbg_trng_msg
{
    uint8_t entropy[CCDRBG_TRNG_VECTOR_LEN];
    uint8_t pers[CCDRBG_TRNG_VECTOR_LEN];
    uint8_t reseed[2][CCDRBG_TRNG_VECTOR_LEN];
};
cc_static_assert(sizeof(struct ccdrbg_trng_msg) == (CCDRBG_TRNG_VECTOR_LEN * 4),
        "correct TRNG message size");

struct ccdrbg_trng_state
{
    struct ccdrbg_trng_msg msg;
    int reseed_idx;
};

static int ccdrbg_trng_init(const struct ccdrbg_info *info,
        struct ccdrbg_state *drbg, size_t entropy_len, const void *entropy,
        size_t nonce_len, const void *nonce,
        size_t ps_len, const void *ps);
static int ccdrbg_trng_generate(struct ccdrbg_state *rng,
        size_t out_len, void *out,
        size_t additional_len, const void *additional);
static int ccdrbg_trng_reseed(struct ccdrbg_state *rng,
        size_t entropy_len, const void *entropy,
        size_t additional_len, const void *additional);
static void ccdrbg_trng_done(struct ccdrbg_state *rng);

/*
 * Initializes an ccdrbg_info object to use the TRNG SP 800-90 test interface.
 */
void ccdrbg_factory_trng(struct ccdrbg_info *info)
{
    info->size = sizeof(struct ccdrbg_trng_state);
    info->init = ccdrbg_trng_init;
    info->generate = ccdrbg_trng_generate;
    info->reseed = ccdrbg_trng_reseed;
    info->done = ccdrbg_trng_done;
    info->custom = NULL;
}

static int ccdrbg_trng_init(const struct ccdrbg_info *info CC_UNUSED,
        struct ccdrbg_state *rng, size_t entropy_len, const void *entropy,
        size_t nonce_len, const void *nonce CC_UNUSED,
        size_t ps_len, const void *ps)
{
    struct ccdrbg_trng_state *state = (struct ccdrbg_trng_state *)rng;

    cc_require(entropy_len == CCDRBG_TRNG_VECTOR_LEN, err);
    cc_require(nonce_len == 0, err);
    cc_require(ps_len == CCDRBG_TRNG_VECTOR_LEN, err);

    /* Cache the passed in values. */
    memcpy(state->msg.entropy, entropy, CCDRBG_TRNG_VECTOR_LEN);
    memcpy(state->msg.pers, ps, CCDRBG_TRNG_VECTOR_LEN);

    state->reseed_idx = 0;

    return 0;

err:
    return -1;
}

static int ccdrbg_trng_reseed(struct ccdrbg_state *rng,
        size_t entropy_len, const void *entropy,
        size_t additional_len, const void *additional CC_UNUSED)
{
    struct ccdrbg_trng_state *state = (struct ccdrbg_trng_state *)rng;

    cc_require(entropy_len == CCDRBG_TRNG_VECTOR_LEN, err);
    cc_require(additional_len == 0, err);
    cc_require(state->reseed_idx < 2, err);

    memcpy(state->msg.reseed[state->reseed_idx++], entropy, CCDRBG_TRNG_VECTOR_LEN);

    return 0;

err:
    return -1;
}

static int ccdrbg_trng_generate(struct ccdrbg_state *drbg,
        size_t out_len, void *out,
        size_t additional_len, const void *additional CC_UNUSED)
{
    struct ccdrbg_trng_state *state = (struct ccdrbg_trng_state *)drbg;

    int32_t ret;
    DriverHandle trng_driver;
    enum DriverReturn dret;

    struct ccrng_state *rng;
    uint8_t byte;

    cc_require(out_len == CCAES_BLOCK_SIZE, fast_err);
    cc_require(additional_len == 0, fast_err);

    rng = ccrng(NULL);
    cc_require(rng != NULL, fast_err);

    /* Open the driver. */
    trng_driver = driver_lookup(DRIVER_TAG_TRNG, 0);
    cc_require(trng_driver != THREAD_INVALID, fast_err);

    dret = driver_open_retry(trng_driver, 1000000);
    cc_require(dret == SDRIVER_SUCCESS, fast_err);

    /* Send the vector structure. */
    ret = (int32_t)driver_write(trng_driver, MTRNG_CHANNEL_FIPS_DRBG, (void *)&state->msg,
            sizeof(struct ccdrbg_trng_msg));
    cc_require(ret == sizeof(struct ccdrbg_trng_msg), err);

    /* Receive the response. */
    ret = (int32_t)driver_read(trng_driver, MTRNG_CHANNEL_FIPS_DRBG, out,
            (unsigned)out_len);
    cc_require(ret == CCAES_BLOCK_SIZE, err);

    /*
     * Delay returning until a byte is read from the rng, indicating that the
     * device is operational again.
     *
     * This doesn't have a retry counter limit because failures here are
     * catastrophic no matter what.
     */
    ret = ccrng_generate(rng, 1, &byte);
    cc_require(ret == 0, err);

    /* Finish the operation by releasing the driver lock. */
    driver_close(trng_driver);

    return 0;

err:
    driver_close(trng_driver);
fast_err:
    return -1;
}

static void ccdrbg_trng_done(struct ccdrbg_state *rng)
{
    struct ccdrbg_trng_state *state = (struct ccdrbg_trng_state *)rng;

    cc_clear(sizeof(struct ccdrbg_trng_state), state);
}
#endif

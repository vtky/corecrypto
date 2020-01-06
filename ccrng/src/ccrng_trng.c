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

static int ccrng_trng_sep_generate(struct ccrng_state *rng,
        unsigned long entropy_size, void *entropy)
{
    enum DriverReturn result;
    unsigned long entropy_count = 0;
    struct ccrng_trng_state *trng = (struct ccrng_trng_state *)rng;
    uint32_t attempts = trng->attempts;

    if (rng == NULL) {
        return -1;
    }

    if (entropy == NULL) {
        return -1;
    }

    do {
        result = driver_read(trng->rng_driver, trng->channel,
                (uint8_t *)entropy + entropy_count,
                (uint32_t)(entropy_size - entropy_count));
        if (result == SDRIVER_NOT_OWNER && attempts > 0) {
            /* TRNG is open by another consumer; busy-poll until ready. */
            attempts--;
            ert_yield();
            continue;
        }
        if (result > 0) {
            entropy_count += result;
        } else {
            return result;
        }
    } while (entropy_count != entropy_size);

    return 0;
}

/*
 * Init a ccrng state struct that utilizes the SEP TRNG to generate entropy.
 */
int ccrng_trng_init(struct ccrng_trng_state *rng, unsigned channel,
        uint32_t attempts)
{
    rng->rng_driver = driver_lookup(DRIVER_TAG_TRNG, 0);

    if (rng->rng_driver == THREAD_INVALID) {
        sys_panic("Could not locate TRNG driver");
        return -1;
    }

    rng->generate = ccrng_trng_sep_generate;
    rng->channel = channel;
    rng->attempts = attempts;

    return 0;
}

/*
 * Provide a SEP/OS ccrng() method that leverages the TRNG.
 *
 * Certain routines need to use ccrng(NULL), specifically ccrsa_sign_pkcs1v15
 * and cavs_vector_ec_siggen.
 */
struct ccrng_state *ccrng(int *error)
{
    static struct ccrng_trng_state rng;
    static int init = 0;

    if (init == 0) {
        ccrng_trng_init(&rng, MTRNG_CHANNEL_DATA, 1000000);
        init = 1;
    }

    if (error) {
        *error = 0;
    }

    return (struct ccrng_state *)&rng;
}
#endif

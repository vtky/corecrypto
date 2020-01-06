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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include <stdint.h>

#define CORECRYPTO_DONOT_USE_TRANSPARENT_UNION 1

#include <corecrypto/cc_priv.h>

#ifndef CC_KERNEL
#error CC_KERNEL not defined; missing include?
#endif

#if CC_KERNEL
void kprintf(const char *fmt, ...) __printflike(1,2);
#define PRINTF kprintf
#else
#include <stdio.h>
#define PRINTF printf
#endif

/* Convienence logging macros. */
void print_preamble(const char *file, const char *function, uint32_t line);
#define errorf(fmt, args...) do {                                           \
    print_preamble(__FILE__, __FUNCTION__, __LINE__);                       \
    PRINTF(fmt "\n", ##args);                                               \
} while (0);
#define bufferf(b, l, fmt, args...) do {                                    \
    const uint8_t *_bptr = (const uint8_t *)b;                              \
    print_preamble(__FILE__, __FUNCTION__, __LINE__);                       \
    PRINTF(fmt ": ", ##args);                                               \
    for (int i = 0; i < l; i++) { PRINTF("%02X", _bptr[i]); }               \
    PRINTF("\n");                                                           \
} while (0);

/* Used for local or temporary debugging efforts. */
#define debugf errorf

/* Enable to increase verbosity universally. */
#define debug(fmt, args...) // errorf(fmt, ##args)
#define buffer_debug(b, l, fmt, args...) //bufferf(b, l, fmt, ##args)

/* Only support CPRINT IO functionality on userland builds. */
#if CC_KERNEL || CC_USE_L4
#define CAVS_IO_ENABLE_CPRINT 0
#else
#define CAVS_IO_ENABLE_CPRINT 1
#endif

/* Define some placeholders for IO structure definitions. */
#define CAVS_IO_STRUCT(STRUCT)
#define CAVS_IO_FIELD(TYPE, MBR)
#define CAVS_IO_BUFFER(BUF_LEN, BUF)
#define CAVS_IO_END_STRUCT

/* All of the test routines will return one of these results. */
#define CAVS_STATUS_FAIL      0
#define CAVS_STATUS_OK        1

/* Each of the different supported types. */
typedef enum {
    CAVS_VECTOR_UNKNOWN = 0,
    CAVS_VECTOR_META_CONTINUE,
    CAVS_VECTOR_CIPHER_ENC,
    CAVS_VECTOR_CIPHER_DEC,
    CAVS_VECTOR_MONTECARLO_ENC_INIT,
    CAVS_VECTOR_MONTECARLO_ENC_OP,
    CAVS_VECTOR_MONTECARLO_DEC_INIT,
    CAVS_VECTOR_MONTECARLO_DEC_OP,
    CAVS_VECTOR_MONTECARLO_FINISH,
    CAVS_VECTOR_XTS_ENC_INIT,
    CAVS_VECTOR_XTS_DEC_INIT,
    CAVS_VECTOR_XTS_OP,
    CAVS_VECTOR_XTS_FINISH,
    CAVS_VECTOR_DIGEST,
    CAVS_VECTOR_HMAC,
    CAVS_VECTOR_DRBG,
    CAVS_VECTOR_RSA_VERIFY,
    CAVS_VECTOR_HMAC_DRBG,
    CAVS_VECTOR_AES_KW_ENC,
    CAVS_VECTOR_AES_KW_DEC,
    CAVS_VECTOR_POST,
    CAVS_VECTOR_RSA_SIG_GEN,
    CAVS_VECTOR_RSA_KEY_GEN,
    CAVS_VECTOR_HKDF,
    CAVS_VECTOR_EC_KEY_GEN,
    CAVS_VECTOR_EC_PKV,
    CAVS_VECTOR_EC_SIG_GEN,
    CAVS_VECTOR_EC_SIG_GEN_COMP,
    CAVS_VECTOR_EC_SIG_VERIFY,
    CAVS_VECTOR_EC_FUNC,
    CAVS_VECTOR_EC_VAL_RESP,
    CAVS_VECTOR_EC_VAL_INIT,
    CAVS_VECTOR_EC25519_GENERATE_SHARED,
    CAVS_VECTOR_EC25519_VERIFY_SHARED,
    CAVS_VECTOR_EC25519_GENERATE_KEY,
    CAVS_VECTOR_EC25519_VERIFY_KEY,
    CAVS_VECTOR_DH_KEY_GEN,
    CAVS_VECTOR_DH_SECRET,

    CAVS_VECTOR_LAST
} cavs_vector;

typedef enum {
    CAVS_TARGET_UNKNOWN = 0,
    CAVS_TARGET_USER,
    CAVS_TARGET_KERNEL,
    CAVS_TARGET_L4,
    CAVS_TARGET_TRNG,

    CAVS_TARGET_LAST
} cavs_target;

/*
 * Various generally applicable enums specifying the various architectures,
 * instruction sets, cipher modes, and so forth used by the different vectors.
 */

/* Supported operating systems. */
typedef enum {
    CAVS_ARCH_UNKNOWN = 0,
    CAVS_ARCH_ARM,
    CAVS_ARCH_FIRST = CAVS_ARCH_ARM,
    CAVS_ARCH_INTEL,

    CAVS_ARCH_LAST
} cavs_arch;

/* Specify the current architecture compiled for. */
#if defined(__arm__) || defined (__arm64__)
#define CAVS_ARCH_CURRENT CAVS_ARCH_ARM
#endif

#if defined(__x86_64__) || defined(__i386__)
#if defined(CAVS_ARCH_CURRENT)
#error Duplicate architecture definition
#endif

#define CAVS_ARCH_CURRENT CAVS_ARCH_INTEL
#endif

/* Supported AES instruction sets. */
typedef enum cavs_aes_is {
    CAVS_AES_IS_UNKNOWN = 0,
    CAVS_AES_IS_GEN,
    CAVS_AES_IS_ASM,
    CAVS_AES_IS_GLAD,
    CAVS_AES_IS_NIGEN,
    CAVS_AES_IS_NI,
    CAVS_AES_IS_HW,
    CAVS_AES_IS_SKG,
    CAVS_AES_IS_SKS,
    CAVS_AES_IS_TRNG,

    CAVS_AES_IS_LAST
} cavs_aes_is;

typedef enum cavs_sha_is {
    CAVS_SHA_IS_UNKNOWN = 0,
    CAVS_SHA_IS_GEN,
    CAVS_SHA_IS_VNG,
    CAVS_SHA_IS_NOSSE,
    CAVS_SHA_IS_SSE,
    CAVS_SHA_IS_AVX1,
    CAVS_SHA_IS_AVX2,

    CAVS_SHA_IS_LAST
} cavs_sha_is;

/* Supported encryption ciphers. */
typedef enum {
    CAVS_CIPHER_ENC_UNKNOWN = 0,
    CAVS_CIPHER_ENC_AES,
    CAVS_CIPHER_ENC_TDES,

    CAVS_CIPHER_ENC_LAST
} cavs_cipher_enc;

/* Supported cipher modes. */
typedef enum {
    CAVS_CIPHER_MODE_UNKNOWN = 0,
    CAVS_CIPHER_MODE_ECB,
    CAVS_CIPHER_MODE_CBC,
    CAVS_CIPHER_MODE_CTR,
    CAVS_CIPHER_MODE_CFB,
    CAVS_CIPHER_MODE_CFB8,
    CAVS_CIPHER_MODE_OFB,
    CAVS_CIPHER_MODE_GCM,
    CAVS_CIPHER_MODE_CCM,
    CAVS_CIPHER_MODE_XTS,

    CAVS_CIPHER_MODE_LAST
} cavs_cipher_mode;

/* Supported Cipher Curves */
typedef enum {
    CAVS_CIPHER_CURVE_UNKNOWN = 0,
    CAVS_CIPHER_CURVE_25519,
    CAVS_CIPHER_CURVE_ED25519,

    CAVS_CIPHER_CURVE_LAST
} cavs_cipher_curve;

/* Supported Digest Types */
typedef enum {
    CAVS_DIGEST_UNKNOWN = 0,
    CAVS_DIGEST_SHA1,
    CAVS_DIGEST_SHA224,
    CAVS_DIGEST_SHA256,
    CAVS_DIGEST_SHA384,
    CAVS_DIGEST_SHA512,
    CAVS_DIGEST_SHA3_224,
    CAVS_DIGEST_SHA3_256,
    CAVS_DIGEST_SHA3_384,
    CAVS_DIGEST_SHA3_512,

    CAVS_DIGEST_LAST
} cavs_digest;

/*
 * Convienence utility functions to convert the various enums to
 * non-cannonical strings.
 *
 * Unfortunately, these are manually maintained.  All the usual tricks
 * break other useful things like ctags.  On the plus side, they rarely
 * change.
 */
const char *cavs_vector_to_string(cavs_vector vector);
const char *cavs_target_to_string(cavs_target target);
const char *cavs_arch_to_string(cavs_arch arch);
const char *cavs_aes_is_to_string(cavs_aes_is aes_is);
const char *cavs_sha_is_to_string(cavs_sha_is sha_is);
const char *cavs_cipher_enc_to_string(cavs_cipher_enc cipher);
const char *cavs_cipher_mode_to_string(cavs_cipher_mode cm);
const char *cavs_cipher_curve_to_string(cavs_cipher_curve curve);
const char *cavs_digest_to_string(cavs_digest digest);

/*
 * Convert key strings, usually the semi-top directory, into an apporpriate
 * instruction set identifier.
 */
cavs_aes_is cavs_key_to_aes_is(const char *key);
cavs_sha_is cavs_key_to_sha_is(const char *key);

/*
 * cavs_find_ccmode
 *
 * For a specified instruction set, encryption cipher, and cipher mode,
 * return a void pointer to a correctly set up object of that type.
 */
const void *cavs_find_ccmode(cavs_aes_is is, cavs_cipher_enc cipher,
        cavs_cipher_mode cm, int encryption);

/*
 * cavs_find_digest_info
 *
 * For a particular digest algo, return an appropriate ccdigest_info structure.
 */
const struct ccdigest_info *cavs_find_digest_info(cavs_sha_is is, cavs_digest digest);
const struct ccdigest_info *cavs_find_digest_info_by_len(cavs_sha_is is, int len);
cavs_digest cavs_find_digest_by_len(int len);

/*
 * cavs_digest_to_output
 *
 * Return the OUTPUT_SIZE of a particular digest.
 */
int cavs_digest_to_output(cavs_digest digest);

/*
 * Generally provided by the corecrypto ccrng library, on SEP there is
 * a local implementation.
 */
struct ccrng_state *ccrng(int *error);

#ifdef __cplusplus
}
#endif // __cplusplus

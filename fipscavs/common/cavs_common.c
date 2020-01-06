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

#include <string.h>
#include <corecrypto/cc_config.h>

#include "cavs_common.h"

#if CC_KERNEL || CC_USE_L4				// Non-boottime kernel kext's don't have strnstr.
/*
 * Substring find.
 *
 * Implementation pulled from: xnu/osfmk/device/subrs.c
 */
static const char *strnstr_kernel(const char *s, const char *find, size_t slen);
static const char *strnstr_kernel(const char *s, const char *find, size_t slen)
{
  char c, sc;
  size_t len;

  if ((c = *find++) != '\0') {
    len = strlen(find);
    do {
      do {
        if ((sc = *s++) == '\0' || slen-- < 1)
          return (NULL);
      } while (sc != c);
      if (len > slen)
        return (NULL);
    } while (strncmp(s, find, len) != 0);
    s--;
  }
  return (s);
}

#define strnstr strnstr_kernel
#endif

void print_preamble(const char *file, const char *function, uint32_t line)
{
    static int skip_path = -1;
    size_t len = strlen(file);

    if (skip_path == -1) {
        const char *l = strnstr(file, "fipscavs/", strlen(file));
        if (l) {
            skip_path = (int)(l - file);
        }
    }

    if (skip_path > 0 && skip_path < (int)len) {
        PRINTF("%s:%s:%d: ", file + skip_path, function, line);
    } else {
        PRINTF("%s:%s:%d: ", file, function, line);
    }
}

/*
 * Convert key strings, usually the semi-top directory, into an apporpriate
 * instruction set identifier for AES algorithms.
 */
cavs_aes_is cavs_key_to_aes_is(const char *key)
{
    size_t key_len;

    if (!key) {
        return CAVS_AES_IS_GEN;
    }

    key_len = strlen(key);
    if (strnstr(key, "gen", key_len)) {
        return CAVS_AES_IS_GEN;
    }

    if (strnstr(key, "aesasm", key_len)) {
        return CAVS_AES_IS_ASM;
    }

    if (strnstr(key, "aesglad", key_len)) {
        return CAVS_AES_IS_GLAD;
    }

    /* Must occur before 'aesni' check to avoid substring conflict. */
    if (strnstr(key, "aesnigen", key_len)) {
        return CAVS_AES_IS_NIGEN;
    }

    if (strnstr(key, "aesni", key_len)) {
        return CAVS_AES_IS_NI;
    }

    if (strnstr(key, "aeshw", key_len)) {
        return CAVS_AES_IS_HW;
    }

    if (strnstr(key, "skg", key_len)) {
        return CAVS_AES_IS_SKG;
    }

    if (strnstr(key, "trng", key_len)) {
        return CAVS_AES_IS_TRNG;
    }

    return CAVS_AES_IS_UNKNOWN;
}

/*
 * Convert key strings, usually the semi-top directory, into an apporpriate
 * instruction set identifier for SHA algorithms.
 */
cavs_sha_is cavs_key_to_sha_is(const char *key)
{
    size_t key_len;

    if (!key) {
        return CAVS_SHA_IS_GEN;
    }

    key_len = strlen(key);
    if (strnstr(key, "gen", key_len)) {
        return CAVS_SHA_IS_GEN;
    }

    if (strnstr(key, "shavng", key_len)) {
        return CAVS_SHA_IS_VNG;
    }

    if (strnstr(key, "shanosse", key_len)) {
        return CAVS_SHA_IS_NOSSE;
    }

    /* Must occur before 'shani' check to avoid substring conflict. */
    if (strnstr(key, "shasse", key_len)) {
        return CAVS_SHA_IS_SSE;
    }

    if (strnstr(key, "shaavx1", key_len)) {
        return CAVS_SHA_IS_AVX1;
    }

    if (strnstr(key, "shaavx2", key_len)) {
        return CAVS_SHA_IS_AVX2;
    }

    return CAVS_SHA_IS_UNKNOWN;
}

#define CASE_STRING(X) case X: return #X;

/*
 * Convienence utility functions to convert the various enums to
 * non-cannonical strings.
 *
 * Unfortunately, these are manually maintained.  All the usual tricks
 * break other useful things like ctags.  On the plus side, they rarely
 * change.
 */
const char *cavs_vector_to_string(cavs_vector vector)
{
    switch (vector) {
    CASE_STRING(CAVS_VECTOR_UNKNOWN);
    CASE_STRING(CAVS_VECTOR_META_CONTINUE);
    CASE_STRING(CAVS_VECTOR_CIPHER_ENC);
    CASE_STRING(CAVS_VECTOR_CIPHER_DEC);
    CASE_STRING(CAVS_VECTOR_MONTECARLO_ENC_INIT);
    CASE_STRING(CAVS_VECTOR_MONTECARLO_ENC_OP);
    CASE_STRING(CAVS_VECTOR_MONTECARLO_DEC_INIT);
    CASE_STRING(CAVS_VECTOR_MONTECARLO_DEC_OP);
    CASE_STRING(CAVS_VECTOR_MONTECARLO_FINISH);
    CASE_STRING(CAVS_VECTOR_XTS_ENC_INIT);
    CASE_STRING(CAVS_VECTOR_XTS_DEC_INIT);
    CASE_STRING(CAVS_VECTOR_XTS_OP);
    CASE_STRING(CAVS_VECTOR_XTS_FINISH);
    CASE_STRING(CAVS_VECTOR_DIGEST);
    CASE_STRING(CAVS_VECTOR_HMAC);
    CASE_STRING(CAVS_VECTOR_DRBG);
    CASE_STRING(CAVS_VECTOR_RSA_VERIFY);
    CASE_STRING(CAVS_VECTOR_HMAC_DRBG);
    CASE_STRING(CAVS_VECTOR_AES_KW_ENC);
    CASE_STRING(CAVS_VECTOR_AES_KW_DEC);
    CASE_STRING(CAVS_VECTOR_POST);
    CASE_STRING(CAVS_VECTOR_RSA_SIG_GEN);
    CASE_STRING(CAVS_VECTOR_RSA_KEY_GEN);
    CASE_STRING(CAVS_VECTOR_HKDF);
    CASE_STRING(CAVS_VECTOR_EC_KEY_GEN);
    CASE_STRING(CAVS_VECTOR_EC_PKV);
    CASE_STRING(CAVS_VECTOR_EC_SIG_GEN);
    CASE_STRING(CAVS_VECTOR_EC_SIG_GEN_COMP);
    CASE_STRING(CAVS_VECTOR_EC_SIG_VERIFY);
    CASE_STRING(CAVS_VECTOR_EC_FUNC);
    CASE_STRING(CAVS_VECTOR_EC_VAL_RESP);
    CASE_STRING(CAVS_VECTOR_EC_VAL_INIT);
    CASE_STRING(CAVS_VECTOR_EC25519_GENERATE_SHARED);
    CASE_STRING(CAVS_VECTOR_EC25519_VERIFY_SHARED);
    CASE_STRING(CAVS_VECTOR_EC25519_GENERATE_KEY);
    CASE_STRING(CAVS_VECTOR_EC25519_VERIFY_KEY);
    CASE_STRING(CAVS_VECTOR_DH_KEY_GEN);
    CASE_STRING(CAVS_VECTOR_DH_SECRET);
    CASE_STRING(CAVS_VECTOR_LAST);
    default:
        errorf("Unknown: %d", vector);
        return "Unknown";
    }
}

const char *cavs_target_to_string(cavs_target target)
{
    switch (target) {
    CASE_STRING(CAVS_TARGET_UNKNOWN);
    CASE_STRING(CAVS_TARGET_USER);
    CASE_STRING(CAVS_TARGET_KERNEL);
    CASE_STRING(CAVS_TARGET_L4);
    CASE_STRING(CAVS_TARGET_TRNG);
    CASE_STRING(CAVS_TARGET_LAST);
    default:
        errorf("Unknown: %d", target);
        return "Unknown";
    }
}

const char *cavs_arch_to_string(cavs_arch arch)
{
    switch (arch) {
    CASE_STRING(CAVS_ARCH_UNKNOWN);
    CASE_STRING(CAVS_ARCH_ARM);
    CASE_STRING(CAVS_ARCH_INTEL);
    CASE_STRING(CAVS_ARCH_LAST);
    default:
        errorf("Unknown: %d", arch);
        return "Unknown";
    }
}

const char *cavs_aes_is_to_string(cavs_aes_is aes_is)
{
    switch (aes_is) {
    CASE_STRING(CAVS_AES_IS_UNKNOWN);
    CASE_STRING(CAVS_AES_IS_GEN);
    CASE_STRING(CAVS_AES_IS_ASM);
    CASE_STRING(CAVS_AES_IS_GLAD);
    CASE_STRING(CAVS_AES_IS_NIGEN);
    CASE_STRING(CAVS_AES_IS_NI);
    CASE_STRING(CAVS_AES_IS_HW);
    CASE_STRING(CAVS_AES_IS_SKG);
    CASE_STRING(CAVS_AES_IS_TRNG);
    CASE_STRING(CAVS_AES_IS_LAST);
    default:
        errorf("Unknown: %d", aes_is);
        return "Unknown";
    }
}

const char *cavs_sha_is_to_string(cavs_sha_is sha_is)
{
    switch (sha_is) {
    CASE_STRING(CAVS_SHA_IS_UNKNOWN);
    CASE_STRING(CAVS_SHA_IS_GEN);
    CASE_STRING(CAVS_SHA_IS_VNG);
    CASE_STRING(CAVS_SHA_IS_NOSSE);
    CASE_STRING(CAVS_SHA_IS_SSE);
    CASE_STRING(CAVS_SHA_IS_AVX1);
    CASE_STRING(CAVS_SHA_IS_AVX2);
    CASE_STRING(CAVS_SHA_IS_LAST);
    default:
        errorf("Unknown: %d", sha_is);
        return "Unknown";
    }
}

const char *cavs_cipher_enc_to_string(cavs_cipher_enc cipher)
{
    switch (cipher) {
    CASE_STRING(CAVS_CIPHER_ENC_UNKNOWN);
    CASE_STRING(CAVS_CIPHER_ENC_AES);
    CASE_STRING(CAVS_CIPHER_ENC_TDES);
    CASE_STRING(CAVS_CIPHER_ENC_LAST);
    default:
        errorf("Unknown: %d", cipher);
        return "Unknown";
    }
}

const char *cavs_cipher_mode_to_string(cavs_cipher_mode cm)
{
    switch (cm) {
    CASE_STRING(CAVS_CIPHER_MODE_UNKNOWN);
    CASE_STRING(CAVS_CIPHER_MODE_ECB);
    CASE_STRING(CAVS_CIPHER_MODE_CBC);
    CASE_STRING(CAVS_CIPHER_MODE_CTR);
    CASE_STRING(CAVS_CIPHER_MODE_CFB);
    CASE_STRING(CAVS_CIPHER_MODE_CFB8);
    CASE_STRING(CAVS_CIPHER_MODE_OFB);
    CASE_STRING(CAVS_CIPHER_MODE_GCM);
    CASE_STRING(CAVS_CIPHER_MODE_CCM);
    CASE_STRING(CAVS_CIPHER_MODE_XTS);
    CASE_STRING(CAVS_CIPHER_MODE_LAST);
    default:
        errorf("Unknown: %d", cm);
        return "Unknown";
    }
}

const char *cavs_cipher_curve_to_string(cavs_cipher_curve curve)
{
    switch (curve) {
    CASE_STRING(CAVS_CIPHER_CURVE_UNKNOWN);
    CASE_STRING(CAVS_CIPHER_CURVE_25519);
    CASE_STRING(CAVS_CIPHER_CURVE_ED25519);
    CASE_STRING(CAVS_CIPHER_CURVE_LAST);
    default:
        errorf("Unknown: %d", curve);
        return "Unknown";
    }
}

const char *cavs_digest_to_string(cavs_digest digest)
{
    switch (digest) {
    CASE_STRING(CAVS_DIGEST_UNKNOWN);
    CASE_STRING(CAVS_DIGEST_SHA1);
    CASE_STRING(CAVS_DIGEST_SHA224);
    CASE_STRING(CAVS_DIGEST_SHA256);
    CASE_STRING(CAVS_DIGEST_SHA384);
    CASE_STRING(CAVS_DIGEST_SHA512);
    CASE_STRING(CAVS_DIGEST_SHA3_224);
    CASE_STRING(CAVS_DIGEST_SHA3_256);
    CASE_STRING(CAVS_DIGEST_SHA3_384);
    CASE_STRING(CAVS_DIGEST_SHA3_512);
    CASE_STRING(CAVS_DIGEST_LAST);
    default:
        errorf("Unknown: %d", digest);
        return "Unknown";
    }
}



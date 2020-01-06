/*
 * Copyright (c) 2015,2016,2018 Apple Inc. All rights reserved.
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

#include "ccsrp_priv.h"
#include "ccdh_priv.h"
#include <corecrypto/ccrsa_priv.h> // for MGF

/*!
 @function   ccsrp_sha_interleave_RFC2945
 @abstract   Hash Interleave per SHA_Interleave from RFC2945

 @param      di        Digest to use, if used per RFC it will be SHA1
 @param      s         Shared Secret in array of cc_unit
 @param      dest      Byte array for output of size at least 2*di->outputsize
 */

static int
ccsrp_sha_interleave_RFC2945(ccsrp_ctx_t srp, const cc_unit *s, uint8_t *dest) {
    uint8_t buf[ccsrp_ctx_sizeof_n(srp)];//vla
    uint8_t E[ccsrp_ctx_sizeof_n(srp)/2];//vla
    uint8_t F[ccsrp_ctx_sizeof_n(srp)/2];//vla
    uint8_t *T=buf;
    size_t digestlen=ccsrp_ctx_di(srp)->output_size;
    uint8_t G[digestlen];//vla
    uint8_t *H=((uint8_t *)dest) + digestlen;
    size_t T_len=ccn_write_uint_size(ccsrp_ctx_n(srp),s); // remove all leading zero bytes from the input.
    ccn_write_uint(ccsrp_ctx_n(srp),s,T_len,T);
    if (T_len & 1) {
        //  If the length of the resulting string is odd, also remove the first byte.
        T=&buf[1];
        T_len--;
    }
    // Extract the even-numbered bytes into a string E and the odd-numbered bytes into a string F
    for (size_t i=0;i<T_len/2;i++) {
        //E[i]=T[2*i];    // E = T[0] | T[2] | T[4] | ...
        //F[i]=T[2*i+1];  // F = T[1] | T[3] | T[5] | ...
        E[T_len/2-i-1]=T[2*i+1];    // E = T[0] | T[2] | T[4] | ...
        F[T_len/2-i-1]=T[2*i];      // F = T[1] | T[3] | T[5] | ...
    }
    ccdigest(ccsrp_ctx_di(srp), T_len/2, E, G); //  G = SHA(E)
    ccdigest(ccsrp_ctx_di(srp), T_len/2, F, H); //  H = SHA(F)

    // Interleave the two hashes back together to form the output, i.e.
    //  result = G[0] | H[0] | G[1] | H[1] | ... | G[19] | H[19]
    for (size_t i=0;i<digestlen;i++) {
        dest[2*i]  =G[i];
        dest[2*i+1]=H[i];
    }
    // With SHA1, the result will be 40 bytes (320 bits) long.
    return 0;
}

/*!
 @function   ccsrp_mgf
 @abstract   Derivation using MGF as defined in RSA PKCS1

 @param      di        Digest to use, if used per RFC it will be SHA1
 @param      s         Shared Secret in array of cc_unit
 @param      dest      Byte array for output of size at least 2*di->outputsize
 */
static int
ccsrp_mgf(ccsrp_ctx_t srp, const cc_unit *s, void *dest) {
    size_t offset;
    uint8_t buf[ccsrp_ctx_sizeof_n(srp)];//vla
    offset=ccsrp_export_ccn(srp, s, buf);
    /* leading zeroes are skipped */
    return ccmgf(ccsrp_ctx_di(srp),
          2*(ccsrp_ctx_di(srp)->output_size),dest,
          ccsrp_ctx_sizeof_n(srp)-offset, buf+offset);
}

/*!
 @function   ccsrp_generate_K_from_S
 @abstract   Generate the key K from the shared secret S

 @param      srp        SRP
 @param      S          Number represented as a cc_unit array of size ccsrp_ctx_sizeof_n(srp)

 @result SRP structure is update with value S
 */
int
ccsrp_generate_K_from_S(ccsrp_ctx_t srp, const cc_unit *S)
{
    int rc=CCSRP_ERROR_DEFAULT;
    if ((SRP_FLG(srp).variant & CCSRP_OPTION_KDF_MASK) == CCSRP_OPTION_KDF_HASH) {
        /* K = H(S) */
        ccsrp_digest_ccn(srp, S, ccsrp_ctx_K(srp),
                         (SRP_FLG(srp).variant & CCSRP_OPTION_PAD_SKIP_ZEROES_k_U_X));
        rc=0;
    }
    else if ((SRP_FLG(srp).variant & CCSRP_OPTION_KDF_MASK) == CCSRP_OPTION_KDF_INTERLEAVED) {
        /* K = SHA_Interleave(S) */
        /* specification is clear, leading zeroes are skipped */
        rc=ccsrp_sha_interleave_RFC2945(srp, S, ccsrp_ctx_K(srp));
    }
    else if ((SRP_FLG(srp).variant & CCSRP_OPTION_KDF_MASK) == CCSRP_OPTION_KDF_MGF1) {
        /* K = MGF1(S) */
        rc=ccsrp_mgf(srp, S, ccsrp_ctx_K(srp));
    }
    else {
        rc=CCSRP_NOT_SUPPORTED_CONFIGURATION;
    }
    if (rc == 0) SRP_FLG(srp).sessionkey=true;
    return rc; // No error
}

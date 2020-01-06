/*
 * Copyright (c) 2012,2014,2015,2016,2017,2018 Apple Inc. All rights reserved.
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

#include "testmore.h"
#include "testbyteBuffer.h"
#include <corecrypto/ccmode.h>
#include "ccsymmetric.h"
#include "crypto_test_modes.h"
#include "crypto_test_modes_vectors.h" // raw data is here
#include "cc_debug.h"

static int verbose = 0;

typedef struct duplex_cryptor_t {
    ciphermode_t encrypt_ciphermode;
    ciphermode_t decrypt_ciphermode;
    cc_cipher_select cipher;
    cc_mode_select mode;
} duplex_cryptor_s, *duplex_cryptor;

static void report_cipher_mode(duplex_cryptor cryptor) {
    char *cipherStr, *modeStr;
    
    switch(cryptor->cipher) {
        case cc_cipherAES: cipherStr = "AES-"; break;
        case cc_cipherDES: cipherStr = "DES-"; break;
        case cc_cipher3DES: cipherStr = "3DES-"; break;
        case cc_cipherCAST: cipherStr = "CAST-"; break;
        case cc_cipherRC2: cipherStr = "RC2-"; break;
        case cc_cipherBlowfish: cipherStr = "Blowfish-"; break;
        default: cipherStr = "UnknownCipher-"; break;
    }
    switch(cryptor->mode) {
        case cc_ModeECB:   modeStr = "ECB\n"; break;
        case cc_ModeCBC:   modeStr = "CBC\n"; break;
        case cc_ModeCFB:   modeStr = "CFB\n"; break;
        case cc_ModeCTR:   modeStr = "CTR\n"; break;
        case cc_ModeOFB:   modeStr = "OFB\n"; break;
        case cc_ModeXTS:   modeStr = "XTS\n"; break;
        case cc_ModeCFB8:  modeStr = "CFB8\n"; break;
        case cc_ModeGCM:   modeStr = "GCM\n"; break;
        case cc_ModeCCM:   modeStr = "CCM\n"; break;
        case cc_ModeSIV:   modeStr = "SIV\n"; break;
        default: modeStr = "UnknownMode\n"; break;
    }
    diag("%s%s", cipherStr, modeStr);
}

ccsymmetric_test_vector *vectors[cc_NCiphers][cc_NModes] = {
    { aes_ecb_vectors, aes_cbc_vectors, aes_cfb_vectors, NULL, aes_ofb_vectors, aes_xts_vectors, aes_cfb8_vectors, aes_gcm_vectors, aes_ccm_vectors,aes_siv_vectors}, // AES
    { des_ecb_vectors, des_cbc_vectors, des_cfb_vectors, des_ctr_vectors, des_ofb_vectors, NULL, des_cfb8_vectors, NULL, NULL }, // DES
    { des3_ecb_vectors, des3_cbc_vectors, des3_cfb_vectors, des3_ctr_vectors, des3_ofb_vectors, NULL, des3_cfb8_vectors, NULL, NULL }, // 3DES
    { cast_ecb_vectors, cast_cbc_vectors, cast_cfb_vectors, cast_ctr_vectors, cast_ofb_vectors, NULL, cast_cfb8_vectors, NULL, NULL }, // CAST
    { rc2_ecb_vectors, rc2_cbc_vectors, rc2_cfb_vectors, rc2_ctr_vectors, rc2_ofb_vectors, NULL, rc2_cfb8_vectors, NULL, NULL }, // RC2
    { blowfish_ecb_vectors, blowfish_cbc_vectors, blowfish_cfb_vectors, blowfish_ctr_vectors, blowfish_ofb_vectors, NULL, blowfish_cfb8_vectors, NULL, NULL }, // Blowfish
};


static cc_status
ccsymmetric_tests(duplex_cryptor cryptor, ccsymmetric_test_vector test) {
    byteBuffer key = hexStringToBytes(test.keyStr);
    byteBuffer twk = hexStringToBytes(test.twkStr);
    byteBuffer init_iv = hexStringToBytes(test.init_ivStr);
    byteBuffer block_iv = hexStringToBytes(test.block_ivStr);
    byteBuffer adata = hexStringToBytes(test.aDataStr);
    byteBuffer adata2 = hexStringToBytes(test.aData2Str);
    byteBuffer pt = hexStringToBytes(test.ptStr);
    byteBuffer ct = hexStringToBytes(test.ctStr);
    byteBuffer tag = hexStringToBytes(test.tagStr);
    size_t len_in = pt->len;
    size_t len_out = ct->len;
    cc_status status = 1;
    
    cc_ciphermode_descriptor_s encrypt_desc;
    cc_ciphermode_descriptor_s decrypt_desc;
    
    encrypt_desc.cipher = decrypt_desc.cipher = cryptor->cipher;
    encrypt_desc.mode = decrypt_desc.mode = cryptor->mode;
    encrypt_desc.direction = cc_Encrypt;
    decrypt_desc.direction = cc_Decrypt;
    encrypt_desc.ciphermode = cryptor->encrypt_ciphermode;
    decrypt_desc.ciphermode = cryptor->decrypt_ciphermode;
    
    MAKE_GENERIC_MODE_CONTEXT(encrypt_ctx, &encrypt_desc);
    MAKE_GENERIC_MODE_CONTEXT(decrypt_ctx, &decrypt_desc);

    if(verbose) report_cipher_mode(cryptor);

    //--------------------------------------------------------------------------
    // Known answer test
    //--------------------------------------------------------------------------
    switch(cryptor->mode) {
        case cc_ModeECB:
        case cc_ModeCBC:
        case cc_ModeCFB:
        case cc_ModeCTR:
        case cc_ModeOFB:
        case cc_ModeCFB8:
            ok_or_fail((cc_symmetric_setup(&encrypt_desc, key->bytes, key->len, init_iv->bytes, encrypt_ctx) == 0), "cipher-mode is initted");
            ok_or_fail((cc_symmetric_setup(&decrypt_desc, key->bytes, key->len, init_iv->bytes, decrypt_ctx) == 0), "cipher-mode is initted");
            break;
        case cc_ModeXTS:
            ok_or_fail((cc_symmetric_setup_tweaked(&encrypt_desc, key->bytes, key->len, twk->bytes, init_iv->bytes, encrypt_ctx) == 0), "cipher-mode is initted");
            ok_or_fail((cc_symmetric_setup_tweaked(&decrypt_desc, key->bytes, key->len, twk->bytes, init_iv->bytes, decrypt_ctx) == 0), "cipher-mode is initted");
            break;
        case cc_ModeCCM:
        case cc_ModeGCM:
        case cc_ModeSIV:
            ok_or_fail((cc_symmetric_setup_authenticated(&encrypt_desc, key->bytes, key->len, init_iv->bytes, init_iv->len,
                                                         adata->bytes, adata->len, adata2->bytes, adata2->len,
                                                         len_in, tag->len, encrypt_ctx) == 0), "cipher-mode is initted");
            ok_or_fail((cc_symmetric_setup_authenticated(&decrypt_desc, key->bytes, key->len, init_iv->bytes, init_iv->len,
                                                         adata->bytes, adata->len, adata2->bytes, adata2->len,
                                                         len_out, tag->len, decrypt_ctx) == 0), "cipher-mode is initted");
            break;
        default:
            break;
    }
    
    uint8_t in[len_in], out[len_out];
    ok_or_fail(cc_symmetric_crypt((cc_symmetric_context_p) encrypt_ctx, block_iv->bytes, pt->bytes, out, len_in) == 0,
               "cc_symmetric_crypt encrypt");

    if(test.ctStr) {
        ok_memcmp_or_fail(out, ct->bytes, len_out, "ciphertext as expected");
    } else if(verbose) {
        byteBuffer result = bytesToBytes(out, len_out);
        diag("Round Trip Results\n");
        printByteBufferAsCharAssignment(pt, "pt");
        printByteBufferAsCharAssignment(result, "ct");
        free(result);
        return 1;
    }
    
    ok_or_fail(cc_symmetric_crypt((cc_symmetric_context_p) decrypt_ctx, block_iv->bytes, out, in, len_out) == 0,
               "cc_symmetric_crypt decrypt");
    ok_memcmp_or_fail(in, pt->bytes, len_in, "plaintext as expected");
    
    if ((cryptor->mode == cc_ModeGCM)
        || (cryptor->mode == cc_ModeCCM)){
        size_t len = tag->len;
        char encrypt_returned_tag[len], decrypt_returned_tag[len];
        cc_zero(len,encrypt_returned_tag);
        cc_zero(len, decrypt_returned_tag);
        cc_symmetric_authenticated_finalize((cc_symmetric_context_p) encrypt_ctx, encrypt_returned_tag, len);
        cc_symmetric_authenticated_finalize((cc_symmetric_context_p) decrypt_ctx, decrypt_returned_tag, len);
        ok_memcmp_or_fail(encrypt_returned_tag, decrypt_returned_tag, len, "encrypt and decrypt tags match");
        if(test.tagStr) {
            ok_memcmp_or_fail(encrypt_returned_tag, tag->bytes, len, "computed and expected tags match");
        } else {
            byteBuffer result = bytesToBytes(encrypt_returned_tag, len);
            diag("Round Trip Tags\n");
            printByteBufferAsCharAssignment(result, "tagStr");
            free(result);
        }
    }

    //--------------------------------------------------------------------------
    // Usage test
    //--------------------------------------------------------------------------
    switch(cryptor->mode) {
        case cc_ModeECB:
        case cc_ModeCBC:
        case cc_ModeCFB:
        case cc_ModeCTR:
        case cc_ModeOFB:
        case cc_ModeCFB8:
        case cc_ModeGCM:
        case cc_ModeCCM:
            break;
        case cc_ModeSIV:
            memset(in,0,sizeof(in));
            memset(out,0,sizeof(out));

            // Encrypt again => expect failure with SIV
            ok_or_fail(cc_symmetric_crypt((cc_symmetric_context_p) encrypt_ctx, block_iv->bytes, pt->bytes, out, len_in) != 0,
                       "Negative test: cc_symmetric_crypt encrypt");
            ok_or_fail(cc_symmetric_crypt((cc_symmetric_context_p) decrypt_ctx, block_iv->bytes, out, in, len_out) != 0,
                       "Negative test: cc_symmetric_crypt decrypt");

            // Reset
            ok_or_fail(cc_symmetric_reset((cc_symmetric_context_p) encrypt_ctx) == 0,
                       "cc_symmetric_reset reset");
            ok_or_fail(cc_symmetric_reset((cc_symmetric_context_p) decrypt_ctx) == 0,
                       "cc_symmetric_reset reset");

            // Success after reset
            ok_or_fail(cc_symmetric_crypt((cc_symmetric_context_p) encrypt_ctx, block_iv->bytes, pt->bytes, out, len_in) == 0,
                       "After reset cc_symmetric_crypt encrypt");
            ok_or_fail(cc_symmetric_crypt((cc_symmetric_context_p) decrypt_ctx, block_iv->bytes, out, in, len_out) == 0,
                       "After reset cc_symmetric_crypt decrypt");

            if (adata->len==0 && adata2->len==0 && init_iv->len==0) {
                ok_memcmp_or_fail(out, ct->bytes, len_out, "ciphertext as expected");
                ok_memcmp_or_fail(in, pt->bytes, len_in, "plaintext as expected");
            }
            break;
        default:
            break;
    }


    //--------------------------------------------------------------------------
    free(key);
    free(twk);
    free(init_iv);
    free(block_iv);
    free(adata);
    free(adata2);
    free(pt);
    free(tag);
    free(ct);
    return status;
}

static int
run_symmetric_vectors(duplex_cryptor cryptor) {
    ccsymmetric_test_vector *run_vector = vectors[cryptor->cipher][cryptor->mode];
    for(int i=0; run_vector[i].keyStr != NULL; i++) {
        ccsymmetric_test_vector test = run_vector[i];
        ok_or_fail(ccsymmetric_tests(cryptor, test), "Test Vector %i",i);
    }
    return 1;
}

int test_mode(ciphermode_t encrypt_ciphermode, ciphermode_t decrypt_ciphermode, cc_cipher_select cipher, cc_mode_select mode) {
    duplex_cryptor_s cryptor;
    
    cryptor.cipher = cipher;
    cryptor.mode = mode;
    cryptor.encrypt_ciphermode = encrypt_ciphermode;
    cryptor.decrypt_ciphermode = decrypt_ciphermode;
    ok_or_fail(run_symmetric_vectors(&cryptor), "Cipher-Mode Test");
    return 1;
}


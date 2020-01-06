/*
 * Copyright (c) 2012,2013,2014,2015,2016,2018 Apple Inc. All rights reserved.
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

/******************************************************************************
 *  Component Test Interface
 *****************************************************************************/

CC_INLINE bool
ccsrp_ccn_component_equal(char *label, ccsrp_ctx_t srp, cc_unit *a, cc_unit *b) {
    bool retval = ccn_cmp(ccsrp_ctx_n(srp), a, b) == 0;
    if(!retval) {
        cc_printf("ccsrp_test_calculations: mismatch for %s:\n", label);
        ccn_lprint(ccsrp_ctx_n(srp),"", a);
        ccn_lprint(ccsrp_ctx_n(srp),"", b);
        cc_printf("\n\n");
    }
    return retval;
}

CC_INLINE bool
ccsrp_byte_component_equal(char *label, size_t len, const void *a, const void *b) {
    bool retval = memcmp(a, b, len) == 0;
    if(!retval) {
        cc_printf("ccsrp_test_calculations: mismatch for %s:\n", label);
        cc_print("", len, a);
        cc_print("", len, b);
        cc_printf("\n");
    }
    return retval;
}

int
ccsrp_test_calculations(const struct ccdigest_info *di, ccsrp_const_gp_t gp,
                        struct ccrng_state *blinding_rng,
                        const char *username, uint32_t options,
                        size_t password_len, const void *password,
                        size_t salt_len, const void *salt,
                        size_t k_len, const void *k,
                        size_t x_len, const void *x,
                        size_t v_len, const void *v,
                        size_t a_len, const void *a,
                        size_t b_len, const void *b,
                        size_t A_len, const void *A,
                        size_t B_len, const void *B,
                        size_t u_len, const void *u,
                        size_t S_len, const void *S,
                        size_t K_len, const void *K,
                        size_t M_len, const void *M,
                        size_t HAMK_len, const void *HAMK
                        )
{
    ccsrp_ctx_decl(di, gp, srp_c);
    ccsrp_ctx_decl(di, gp, srp_s);
    ccsrp_ctx_init_option(srp_c, di, gp, options, blinding_rng);
    ccsrp_ctx_init_option(srp_s, di, gp, options, blinding_rng);
    cc_size n = ccsrp_ctx_n(srp_c);
    cc_unit input_k[n];//vla
    cc_unit generated_k[n];//vla
    cc_unit input_x[n];//vla
    cc_unit generated_x[n];//vla
    cc_unit input_v[n]; //vla
    cc_unit input_A[n];//vla
    cc_unit input_B[n];//vla
    cc_unit input_u[n];//vla
    cc_unit generated_u[n];//vla
    cc_unit input_S[n];//vla
    cc_unit generated_server_S[n];//vla
    cc_unit generated_client_S[n];//vla

    ccsrp_import_ccn_with_len(srp_c, input_k, k_len, k);
    ccsrp_import_ccn_with_len(srp_c, input_x, x_len, x);
    ccsrp_import_ccn_with_len(srp_c, input_v, v_len, v);
    ccsrp_import_ccn_with_len(srp_c, ccsrp_ctx_private(srp_c), a_len, a);
    ccsrp_import_ccn_with_len(srp_c, ccsrp_ctx_private(srp_s), b_len, b);
    ccsrp_import_ccn_with_len(srp_c, input_A, A_len, A);
    ccsrp_import_ccn_with_len(srp_c, input_B, B_len, B);
    ccsrp_import_ccn_with_len(srp_c, input_u, u_len, u);
    ccsrp_import_ccn_with_len(srp_c, input_S, S_len, S);
    size_t session_key_len=0;
    int retval = 0;
    
    // This requires x to be generated the same as the spec
    ccsrp_generate_x(srp_c, generated_x, username, salt_len, salt, password_len, password);
    if(!ccsrp_ccn_component_equal("x", srp_c, generated_x, input_x)) retval = -1;
    
    // These need to work and are ready to try out.
    if (k_len) {
        ccsrp_generate_k(srp_c, generated_k);
        if(!ccsrp_ccn_component_equal("k", srp_c, generated_k, input_k)) retval = -1;
    }
    ccsrp_generate_client_pubkey(srp_c);
    if(!ccsrp_ccn_component_equal("A", srp_c, ccsrp_ctx_public(srp_c),input_A)) retval = -1;

    // since x might be whacked, we'll use the input x
    ccsrp_generate_v(srp_c, input_x);
    if(!ccsrp_ccn_component_equal("v", srp_c, ccsrp_ctx_v(srp_c),input_v)) retval = -1;

    // since v might be whacked, we'll use the input v
    ccsrp_import_ccn_with_len(srp_s, ccsrp_ctx_v(srp_s), v_len, v);
    ccsrp_generate_server_pubkey(srp_s, input_k);
    if(!ccsrp_ccn_component_equal("B", srp_s, ccsrp_ctx_public(srp_s),input_B)) retval = -1;

    // ccsrp_server_compute_session
    ccsrp_generate_u(srp_s, generated_u, input_A, input_B);
    if(!ccsrp_ccn_component_equal("u", srp_s, generated_u, input_u)) retval = -1;
    
    ccsrp_generate_server_S(srp_s, generated_server_S, input_u, input_A);
    if(!ccsrp_ccn_component_equal("ServerS", srp_s, generated_server_S, input_S)) retval = -1;

    ccsrp_generate_client_S(srp_c, generated_client_S, input_k, input_x, input_u, input_B);
    if(!ccsrp_ccn_component_equal("ClientS", srp_c, generated_client_S, input_S)) retval = -1;

    // Derivation of the key
    session_key_len=ccsrp_get_session_key_length(srp_s);
    if (!(ccsrp_generate_K_from_S(srp_s,input_S)==0
        && ccsrp_byte_component_equal("K", K_len,ccsrp_get_session_key(srp_s, &session_key_len),K)
        && K_len==session_key_len)) {
        retval = -1;
    }

    // Authentication token1 ccsrp_ctx_M
    ccsrp_generate_M(srp_s, username, salt_len, salt, input_A, input_B);
    if (!(M
        && ccsrp_byte_component_equal("M", M_len,ccsrp_ctx_M(srp_s),M))) {
        retval = -1;
    }

    // Authentication token2
    ccsrp_generate_H_AMK(srp_s, input_A);
    if (!(HAMK
        && ccsrp_byte_component_equal("HAMK", HAMK_len, ccsrp_ctx_HAMK(srp_s),HAMK))) {
        retval = -1;
    }
    ccsrp_ctx_clear(di, gp, srp_c);
    ccsrp_ctx_clear(di, gp, srp_s);
    return retval;
}

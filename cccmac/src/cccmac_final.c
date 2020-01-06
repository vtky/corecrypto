/*
 * Copyright (c) 2013,2015,2016,2018 Apple Inc. All rights reserved.
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

#include "cccmac_priv.h"

int cccmac_final_generate(cccmac_ctx_t ctx,
                  size_t mac_nbytes, void *mac) {
    int status=-1;
    size_t  final_nbytes = cccmac_block_nbytes(ctx);
    uint8_t *final_buf = cccmac_block(ctx);
    void *subkey = cccmac_k2(ctx);
    uint8_t full_mac[CMAC_BLOCKSIZE];
    const struct ccmode_cbc *cbc=cccmac_cbc(ctx);

    cccmac_cumulated_nbytes(ctx)+=final_nbytes;

    cc_require((final_nbytes <= CMAC_BLOCKSIZE)
               && ((final_nbytes > 0) || cccmac_cumulated_nbytes(ctx)==0),errOut); /* Invalid parameter: data */
    cc_require(mac_nbytes <= CMAC_BLOCKSIZE && mac_nbytes > 0,errOut); /* Invalid mac: data */

    // If Mn* is a complete block, let Mn = K1 ⊕ Mn*;
    if(final_nbytes == CMAC_BLOCKSIZE) {
        subkey = cccmac_k1(ctx);
    }
    // else, let Mn = K2 ⊕ (Mn*||10j), where j = nb-Mlen-1.
    else {
        cc_zero(CMAC_BLOCKSIZE-final_nbytes,final_buf+final_nbytes);
        final_buf[final_nbytes] = 0x80;
    }
    cc_xor(CMAC_BLOCKSIZE, final_buf, final_buf,subkey);
    cccbc_update(cbc,cccmac_mode_sym_ctx(cbc,ctx),cccmac_mode_iv(cbc, ctx),
                 1, final_buf, full_mac);
    CC_MEMCPY(mac,full_mac,mac_nbytes);
    status = 0;
errOut:
    cccmac_mode_clear(cccmac_cbc(ctx),CCCMAC_HDR(ctx));
    return status;
}

int cccmac_final_verify(cccmac_ctx_t ctx,
                     size_t expected_mac_nbytes, const void *expected_mac) {
    int status;
    uint8_t full_mac[CMAC_BLOCKSIZE];
    status=cccmac_final_generate(ctx,CMAC_BLOCKSIZE,full_mac);
    if (status != 0) {
        return status; // Computation error
    }
    if (cc_cmp_safe(expected_mac_nbytes, expected_mac, full_mac) == 0) {
        return 0;      // MAC matches
    }
    return -5;         // MAC mismatches
}

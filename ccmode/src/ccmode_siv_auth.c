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
#include "cccmac_priv.h"
#include <corecrypto/ccmode_siv.h>
#include <corecrypto/ccmode_siv_priv.h>
#include <corecrypto/ccmode_internal.h>
#include <corecrypto/cc_priv.h>

/*
 S2V for all vectors but the last S1..Sn-1
 D = AES-CMAC(K, <zero>)
 for i = 1 to n-1 do
 D = dbl(D) xor AES-CMAC(K, Si)
 done
 */
int ccmode_siv_auth(ccsiv_ctx *ctx,
                      size_t nbytes, const uint8_t *in) {

    uint8_t block[_CCMODE_SIV_CBC_MODE(ctx)->block_size];

    // If no data, nothing to do, return without changing state
    if (nbytes==0) return 0;

    // Process Si
    // D = dbl(D) xor AES-CMAC(K, Si)
    cccmac_sl_test_xor(_CCMODE_SIV_D(ctx),_CCMODE_SIV_D(ctx));
    cccmac_one_shot_generate(_CCMODE_SIV_CBC_MODE(ctx),
                             _CCMODE_SIV_KEYSIZE(ctx)/2,_CCMODE_SIV_K1(ctx),
                             nbytes,in,
                             _CCMODE_SIV_CBC_MODE(ctx)->block_size,block);
    cc_xor(_CCMODE_SIV_CBC_MODE(ctx)->block_size,
           _CCMODE_SIV_D(ctx),_CCMODE_SIV_D(ctx),block);

    // Done
    _CCMODE_SIV_STATE(ctx)=CCMODE_STATE_AAD;
    return 0;
}

int ccmode_siv_auth_last(ccsiv_ctx *ctx,
                         size_t nbytes, const uint8_t *in, uint8_t* V) {
    int rc=-1;
    size_t block_size=_CCMODE_SIV_CBC_MODE(ctx)->block_size;
    uint8_t block[2*block_size];
    const struct ccmode_cbc *cbc=_CCMODE_SIV_CBC_MODE(ctx);

    /* Sanity checks */
    if (block_size!=16) {
        rc=CCMODE_NOT_SUPPORTED;
        goto errOut;
    }
    if (   (_CCMODE_SIV_STATE(ctx)!=CCMODE_STATE_INIT)
        && (_CCMODE_SIV_STATE(ctx)!=CCMODE_STATE_AAD)) {
        rc=CCMODE_INVALID_CALL_SEQUENCE;
        goto errOut;
    }

    /* Special case, nothing to encrypt or authenticate:
     output is one block size */
    if ((nbytes==0) && _CCMODE_SIV_STATE(ctx)==CCMODE_STATE_INIT) {
        /*
         if n = 0 then
         return V = AES-CMAC(K, <one>)
         fi
         */
        cc_clear(block_size,block);
        block[block_size-1]=0x01;
        cccmac_one_shot_generate(_CCMODE_SIV_CBC_MODE(ctx),
                                 _CCMODE_SIV_KEYSIZE(ctx)/2,_CCMODE_SIV_K1(ctx),
                                 block_size,block,
                                 block_size,V);
        _CCMODE_SIV_STATE(ctx)=CCMODE_STATE_TEXT; // done
        return 0;
    }

    /* Something to encrypt */
    if (nbytes>=block_size) {
        /* if len(Sn) >= 128 then
         T = Sn xorend D */
        cccmac_mode_decl(cbc, cmac);
        cccmac_init(cbc, cmac, _CCMODE_SIV_KEYSIZE(ctx)/2, _CCMODE_SIV_K1(ctx));
        size_t head_nblocks=nbytes/block_size-1;
        size_t tail_nbytes=nbytes-(head_nblocks*block_size);

        // Will process all the entire block except the last
        // 1) Set the last full block and remaining bytes aside
        CC_MEMCPY(block,&in[(head_nblocks*block_size)],tail_nbytes-block_size);
        cc_xor(block_size,
               &block[tail_nbytes-block_size],
               &in[(head_nblocks*block_size)+tail_nbytes-block_size],
               _CCMODE_SIV_D(ctx));

        // 2) MAC the full blocks
        cccmac_update(cmac, head_nblocks*block_size, in);

        // 3) MAC the tailing bytes
        cccmac_update(cmac, tail_nbytes, block);
        cccmac_final_generate(cmac, block_size,V);
        cccmac_mode_clear(cbc, cmac);
    } else {
        /* else
         T = dbl(D) xor pad(Sn) */
        cccmac_sl_test_xor(_CCMODE_SIV_D(ctx),_CCMODE_SIV_D(ctx));
        CC_MEMCPY(block,in,nbytes);
        block[nbytes]=0x80;
        for (size_t i=1;i<(block_size-nbytes);i++) {
            block[nbytes+i]=0x00;
        }
        cc_xor(block_size,block,block,_CCMODE_SIV_D(ctx));
        cccmac_one_shot_generate(cbc, _CCMODE_SIV_KEYSIZE(ctx)/2,_CCMODE_SIV_K1(ctx),
                                 block_size,block,block_size,V);
    }
    _CCMODE_SIV_STATE(ctx)=CCMODE_STATE_TEXT; // done with S2V
    return 0;
errOut:
    _CCMODE_SIV_STATE(ctx)=-1; // done with S2V
    return rc;
}

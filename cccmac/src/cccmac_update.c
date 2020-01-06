/*
 * Copyright (c) 2016,2018 Apple Inc. All rights reserved.
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

#define CMAC_BUFFER_NB_BLOCKS ((size_t)16)

// CMAC compression. Always keep some data in cccmac_block for final
int cccmac_update(cccmac_ctx_t ctx,
                         size_t data_nbytes, const void *data) {
    if(!data_nbytes || !data) return 0; /* no data to process */

    const struct ccmode_cbc *cbc=cccmac_cbc(ctx);
    uint8_t tmp[CMAC_BUFFER_NB_BLOCKS*CMAC_BLOCKSIZE];
    size_t nblocks;
    size_t leftover_nbytes;
    size_t first_block_nbytes = CC_MIN(data_nbytes,CMAC_BLOCKSIZE-cccmac_block_nbytes(ctx));

    // Check for abnormality which would result in overflow
    if (cccmac_block_nbytes(ctx) > CMAC_BLOCKSIZE) return -1;

    // Skip for the following for first update (optimization)
    if (cccmac_block_nbytes(ctx) > 0) {
        CC_MEMCPY((uint8_t*)cccmac_block(ctx)+cccmac_block_nbytes(ctx), data, first_block_nbytes);
        cccmac_block_nbytes(ctx) += first_block_nbytes;
        data+=first_block_nbytes;
        data_nbytes-=first_block_nbytes;
        if (data_nbytes == 0) {
            return 0; /* done. Not enough to process yet. */
        }

        // Sanity / debug
        cc_assert(data_nbytes>0);
        cc_assert(cccmac_block_nbytes(ctx) <= CMAC_BLOCKSIZE);

        // Process the first block
        cccbc_update(cbc, cccmac_mode_sym_ctx(cbc, ctx),
                     cccmac_mode_iv(cbc, ctx),
                     1, cccmac_block(ctx), tmp);
        cccmac_cumulated_nbytes(ctx) += CMAC_BLOCKSIZE;
    }

    // Process the remaining blocks
    nblocks = ((data_nbytes-1) >> 4); //  divide by 16, keep at least one byte
    leftover_nbytes = data_nbytes-(CMAC_BLOCKSIZE*nblocks);
    cc_assert(leftover_nbytes>0);

    // Most blocks
    while(nblocks) {
        size_t process_nblocks=CC_MIN(CMAC_BUFFER_NB_BLOCKS,nblocks);
        cccbc_update(cbc, cccmac_mode_sym_ctx(cbc, ctx), cccmac_mode_iv(cbc, ctx), process_nblocks, data, tmp);
        data+=(CMAC_BLOCKSIZE*process_nblocks);
        nblocks-=process_nblocks;
    }

    // Keep the leftover bytes, at least one byte
    CC_MEMCPY(cccmac_block(ctx), data, leftover_nbytes);
    cccmac_block_nbytes(ctx) = leftover_nbytes;

    // Keep track of how much we processed
    cccmac_cumulated_nbytes(ctx) += (CMAC_BLOCKSIZE*(nblocks));
    return 0;
}




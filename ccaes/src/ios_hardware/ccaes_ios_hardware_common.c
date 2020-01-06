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

#include <corecrypto/cc_config.h>

#if CCAES_MUX

#include <unistd.h>

#include <IOKit/IOKitLib.h>
#include <Kernel/IOKit/crypto/IOAESTypes.h>
#include <sys/ioctl.h>

#include "cc_debug.h"
#include "ccaes_ios_hardware.h"
#include <corecrypto/ccmode_internal.h>

/*
 ccaes_hardware_threshold is being set to a constant of 1 so that hardware FIPS tests
 can directly call into this with a low threshold of bytes.  This shouldn't matter since
 iOS clients use this interface through the ccaes_ios_mux interface; which will use
 the 16K value.
 */

#include <errno.h>

static int ccaes_device = -1;
size_t ccaes_hardware_block_quantum = ((256*4096) / CCAES_BLOCK_SIZE);
size_t ccaes_hardware_block_threshold = 1;
uint32_t ccaes_hardware_support = 0;
uint64_t ccaes_hardware_perf = 0;

#define AES_HW_INIT_MAGIC 0xA5A5C5C5

#define WORKAROUND_32163348

static bool isHWfaster(void)
{
    cc_assert(ccaes_hardware_perf>0);
    // Only use HW if fast enough
    if (ccaes_hardware_perf>=(14*1024*1024)) {
        return true;
    }
    return false;
}

// Check HW support
static int ccaes_ios_hardware_support(int operation) {
    static dispatch_once_t	aesinit;
    __block int status=0;
    dispatch_once(&aesinit, ^{
        struct IOAESAcceleratorInfo aesInfo;

        ccaes_device = open("/dev/aes_0", O_RDWR | O_NONBLOCK, 0); // Non guarded
                        // Guarded open does not seem to support O_NONBLOCK
        if(ccaes_device < 0) {
            cc_printf("Failed open file descriptor to AES HW %d",errno);
            status = CCMODE_INTERNAL_ERROR;
        }
        if(ioctl(ccaes_device, IOAES_GET_INFO, &aesInfo) != -1) {
            ccaes_hardware_block_quantum =  aesInfo.maxBytesPerCall / CCAES_BLOCK_SIZE;
            // For right now we're going to set the minimum to 1 block - allowing this
            // to function like any other aes-cbc modeObj. It can be tested while in this
            // configuration with the normal tests, although the round trips through the
            // kernel boundary are painfully slow for small block counts.
            ccaes_hardware_block_threshold = 1; // aesInfo.minBytesPerCall / CCAES_BLOCK_SIZE;
            ccaes_hardware_support = aesInfo.options;
            ccaes_hardware_perf = aesInfo.encryptSpeed; // byte per seconds
#ifdef WORKAROUND_32163348
            if (!isHWfaster()) {
               ccaes_hardware_support &= ~kIOAESAcceleratorSupportCTR;
            }
#endif
        }
    });
    if (status) {
        return status;
    }
    else if (((operation&CCAES_HW_MODE) == CCAES_HW_CBC)
        && !(ccaes_hardware_support & kIOAESAcceleratorSupportCBC)) {
        return CCMODE_NOT_SUPPORTED;
    }
    else if (((operation&CCAES_HW_MODE) == CCAES_HW_CTR)
        && !(ccaes_hardware_support & kIOAESAcceleratorSupportCTR)) {
        return CCMODE_NOT_SUPPORTED;
    }
    return 0;
}

// Return true if the operation is supported by HW and if HW has some advantage
// over SW.
// Can be used as kill switch for corecrypto client without
// blocking function/performance testing within corecrypto
int ccaes_ios_hardware_enabled(int operation) {
    // First try to connect to the driver for operation support
    if (ccaes_ios_hardware_support(operation)==0) {
        // Then check if there is a performance benefit
        return isHWfaster()?1:0;
    }
    return 0;
}


int
ccaes_ios_hardware_common_init(int operation CC_UNUSED, ccaes_hardware_aes_ctx_t ctx, size_t rawkey_len, const void *rawkey)
{
    if (rawkey_len !=CCAES_KEY_SIZE_128
        && rawkey_len != CCAES_KEY_SIZE_192
        && rawkey_len != CCAES_KEY_SIZE_256) {
        return CCMODE_INVALID_INPUT;
    }

    CC_MEMCPY(&ctx->keyBytes[0], rawkey, rawkey_len);
    ctx->keyLength = rawkey_len;

    int status = ccaes_ios_hardware_support(operation);
    if (status) return status;

    ctx->init_complete=AES_HW_INIT_MAGIC;
    return 0;
}

size_t ccaes_ios_hardware_crypt(int operation, ccaes_hardware_aes_ctx_const_t ctx, uint8_t *iv,
                            const void *in, void *out, size_t nblocks)
{
    uint8_t *pt8, *ct8;
	struct IOAESAcceleratorRequest aesRequest;
	
    if(nblocks < ccaes_hardware_block_threshold) return 0; // 0 block processed
	size_t remaining = nblocks;
	size_t chunk;

    if ((ctx->init_complete!=AES_HW_INIT_MAGIC) || (ccaes_device < 0)) return 0;

    // Prepare data request
    if((operation&CCAES_HW_ENCRYPT)) {
        aesRequest.operation = (operation&CCAES_HW_CTR)?IOAESOperationEncryptCTR:IOAESOperationEncrypt;
        pt8 = __DECONST(uint8_t *,in);
        ct8 = (uint8_t *) out;
    } else {
        aesRequest.operation = (operation&CCAES_HW_CTR)?IOAESOperationDecryptCTR:IOAESOperationDecrypt;
        pt8 = (uint8_t *) out;
        ct8 = __DECONST(uint8_t *,in);
    }

    // Setup key and IV
	CC_MEMCPY(aesRequest.iv.ivBytes, iv, CCAES_BLOCK_SIZE);
	aesRequest.keyData.key.keyLength = (UInt32) (ctx->keyLength << 3); //Hardware needs it in bits.
	CC_MEMCPY(aesRequest.keyData.key.keyBytes, ctx->keyBytes, ctx->keyLength);
	aesRequest.keyData.keyHandle = kIOAESAcceleratorKeyHandleExplicit;

    // Last chunks of data, as large as supported by the HW
	while (remaining) {
        chunk = CC_MIN(ccaes_hardware_block_quantum,remaining);

        // In corecrypto, the counter width is 64bit for AES CTR
        uint64_t counter;
        bool isOverflow = false;
        CC_LOAD64_BE(counter,aesRequest.iv.ivBytes+8); // Get the lowest part of the counter
        if ((UINT64_MAX-counter <= chunk-1) && (operation&CCAES_HW_CTR)) {
            chunk = (size_t)(UINT64_MAX-counter)+1;
            isOverflow = true;
        }

        // Data
        aesRequest.plainText = pt8;
        aesRequest.cipherText = ct8;
        aesRequest.textLength = (IOByteCount32) (chunk * CCAES_BLOCK_SIZE); //The hardware needs textLength in bytes.
        if(ioctl(ccaes_device, IOAES_ENCRYPT_DECRYPT, &aesRequest) == -1) {
            break;
        }

        // Most significant bit was increased which does not match corecrypto
        // counter width, we decrement it.
        if (isOverflow) {
            CC_LOAD64_BE(counter,aesRequest.iv.ivBytes);
            counter--;
            CC_STORE64_BE(counter,aesRequest.iv.ivBytes);
        }

        remaining -= chunk;
        pt8 += (chunk*CCAES_BLOCK_SIZE);
        ct8 += (chunk*CCAES_BLOCK_SIZE);
	}
	//Copy the IV back.
	CC_MEMCPY(iv, aesRequest.iv.ivBytes, CCAES_BLOCK_SIZE);
    cc_clear(ctx->keyLength,aesRequest.keyData.key.keyBytes); // zero key bytes
	return (nblocks - remaining);
}




#endif /* CCAES_MUX */


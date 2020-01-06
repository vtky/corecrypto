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
#include <corecrypto/cc_debug.h>
#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccsha2.h>

#include "fipspost.h"
#include "fipspost_priv.h"
#include "fipspost_post_drbg_hmac.h"

// Test HMAC DRBG from
/*
 [SHA-256]
 [PredictionResistance = False]
 [EntropyInputLen = 256]
 [NonceLen = 128]
 [PersonalizationStringLen = 256]
 [AdditionalInputLen = 256]
 [ReturnedBitsLen = 1024]

 COUNT = 0
 EntropyInput = cdb0d9117cc6dbc9ef9dcb06a97579841d72dc18b2d46a1cb61e314012bdf416
 Nonce = d0c0d01d156016d0eb6b7e9c7c3c8da8
 PersonalizationString = 6f0fb9eab3f9ea7ab0a719bfa879bf0aaed683307fda0c6d73ce018b6e34faaa
 ** INSTANTIATE:
	V   = 6c02577c505aed360be7b1cecb61068d8765be1391bacb10f4180d91bd3915db
	Key = 108a7674f3348216c91f5745dd87a919f552fc44373b84ad4b3b843a26b574cb
 EntropyInputReseed = 8ec6f7d5a8e2e88f43986f70b86e050d07c84b931bcf18e601c5a3eee3064c82
 AdditionalInputReseed = 1ab4ca9014fa98a55938316de8ba5a68c629b0741bdd058c4d70c91cda5099b3
 ** RESEED:
	V   = 21a645aeca821899e7e733a10f64565deee5ced3cd5c0356b66c76dc8a906e69
	Key = e57f901d4bff2909f09467003096edfdb46c89af6bd82e904d11b6753d645c90

 AdditionalInput = 16e2d0721b58d839a122852abd3bf2c942a31c84d82fca74211871880d7162ff
 ** GENERATE (FIRST CALL):
	V   = 490c0b7786c80f16ad5ee1cc0efd29618968dce14cccebecec8964ea8a41b439
	Key = 648f92d385c3fbf61526deef48ca5ca4dfe4646d82fe8e73bc1705824e181dc9

 AdditionalInput = 53686f042a7b087d5d2eca0d2a96de131f275ed7151189f7ca52deaa78b79fb2
 ReturnedBits = dda04a2ca7b8147af1548f5d086591ca4fd951a345ce52b3cd49d47e84aa31a183e31fbc42a1ff1d95afec7143c8008c97bc2a9c091df0a763848391f68cb4a366ad89857ac725a53b303ddea767be8dc5f605b1b95f6d24c9f06be65a973a089320b3cc42569dcfd4b92b62a993785b0301b3fc452445656fce22664827b88f
 ** GENERATE (SECOND CALL):
	V   = 47390036d5cb308cf9592fdfe95bf19b8ed1a3db88ed8c3b2b2d77540dfb5470
	Key = db4853ca51700d43c5b6d63eb6cd20ea2dbe3dff512f2dc9531b5b3d9120121c
 */
int fipspost_post_drbg_hmac(int fips_mode)
{
    int result = CCERR_GENERIC_FAILURE;

    // Init
    const unsigned char  entropyInputBuffer[] =   {0xcd, 0xb0, 0xd9, 0x11, 0x7c, 0xc6, 0xdb, 0xc9, 0xef, 0x9d, 0xcb, 0x06,
        0xa9, 0x75, 0x79, 0x84, 0x1d, 0x72, 0xdc, 0x18, 0xb2, 0xd4, 0x6a, 0x1c,
        0xb6, 0x1e, 0x31, 0x40, 0x12, 0xbd, 0xf4, 0x16};

    const unsigned char nonceBuffer[] = {0xd0, 0xc0, 0xd0, 0x1d, 0x15, 0x60, 0x16, 0xd0, 0xeb, 0x6b, 0x7e, 0x9c,
        0x7c, 0x3c, 0x8d, 0xa8};

    const unsigned char personalizationStringBuffer[] = {0x6f, 0x0f, 0xb9, 0xea, 0xb3, 0xf9, 0xea, 0x7a, 0xb0, 0xa7, 0x19, 0xbf,
        0xa8, 0x79, 0xbf, 0x0a, 0xae, 0xd6, 0x83, 0x30, 0x7f, 0xda, 0x0c, 0x6d,
        0x73, 0xce, 0x01, 0x8b, 0x6e, 0x34, 0xfa, 0xaa};

    // Reseed
    const unsigned char entropyInputReseedBuffer[] = {
        0x8e, 0xc6, 0xf7, 0xd5, 0xa8, 0xe2, 0xe8, 0x8f, 0x43, 0x98, 0x6f, 0x70,
        0xb8, 0x6e, 0x05, 0x0d, 0x07, 0xc8, 0x4b, 0x93, 0x1b, 0xcf, 0x18, 0xe6,
        0x01, 0xc5, 0xa3, 0xee, 0xe3, 0x06, 0x4c, 0x82};

    const unsigned char additionalInputReseedBuffer[] = {
        0x1a, 0xb4, 0xca, 0x90, 0x14, 0xfa, 0x98, 0xa5, 0x59, 0x38, 0x31, 0x6d,
        0xe8, 0xba, 0x5a, 0x68, 0xc6, 0x29, 0xb0, 0x74, 0x1b, 0xdd, 0x05, 0x8c,
        0x4d, 0x70, 0xc9, 0x1c, 0xda, 0x50, 0x99, 0xb3};

    // Info
    const unsigned char entropyInputPR1Buffer [] = {  0x16, 0xe2, 0xd0, 0x72, 0x1b, 0x58, 0xd8, 0x39, 0xa1, 0x22, 0x85, 0x2a,
        0xbd, 0x3b, 0xf2, 0xc9, 0x42, 0xa3, 0x1c, 0x84, 0xd8, 0x2f, 0xca, 0x74,
        0x21, 0x18, 0x71, 0x88, 0x0d, 0x71, 0x62, 0xff};

    const unsigned char entropyInputPR2Buffer []= {  0x53, 0x68, 0x6f, 0x04, 0x2a, 0x7b, 0x08, 0x7d, 0x5d, 0x2e, 0xca, 0x0d,
        0x2a, 0x96, 0xde, 0x13, 0x1f, 0x27, 0x5e, 0xd7, 0x15, 0x11, 0x89, 0xf7,
        0xca, 0x52, 0xde, 0xaa, 0x78, 0xb7, 0x9f, 0xb2};

    // Output
    unsigned char returnedBitsBuffer[] =   {
        0xdd, 0xa0, 0x4a, 0x2c, 0xa7, 0xb8, 0x14, 0x7a, 0xf1, 0x54, 0x8f, 0x5d,
        0x08, 0x65, 0x91, 0xca, 0x4f, 0xd9, 0x51, 0xa3, 0x45, 0xce, 0x52, 0xb3,
        0xcd, 0x49, 0xd4, 0x7e, 0x84, 0xaa, 0x31, 0xa1, 0x83, 0xe3, 0x1f, 0xbc,
        0x42, 0xa1, 0xff, 0x1d, 0x95, 0xaf, 0xec, 0x71, 0x43, 0xc8, 0x00, 0x8c,
        0x97, 0xbc, 0x2a, 0x9c, 0x09, 0x1d, 0xf0, 0xa7, 0x63, 0x84, 0x83, 0x91,
        0xf6, 0x8c, 0xb4, 0xa3, 0x66, 0xad, 0x89, 0x85, 0x7a, 0xc7, 0x25, 0xa5,
        0x3b, 0x30, 0x3d, 0xde, 0xa7, 0x67, 0xbe, 0x8d, 0xc5, 0xf6, 0x05, 0xb1,
        0xb9, 0x5f, 0x6d, 0x24, 0xc9, 0xf0, 0x6b, 0xe6, 0x5a, 0x97, 0x3a, 0x08,
        0x93, 0x20, 0xb3, 0xcc, 0x42, 0x56, 0x9d, 0xcf, 0xd4, 0xb9, 0x2b, 0x62,
        0xa9, 0x93, 0x78, 0x5b, 0x03, 0x01, 0xb3, 0xfc, 0x45, 0x24, 0x45, 0x65,
        0x6f, 0xce, 0x22, 0x66, 0x48, 0x27, 0xb8, 0x8f};

    uint8_t resultBuffer[128];
    memset(resultBuffer, 0, 16);

    static struct ccdrbg_info info;
    struct ccdrbg_nisthmac_custom custom;
   	custom.di = ccsha256_di();
    custom.strictFIPS = 0;

    ccdrbg_factory_nisthmac(&info, &custom);

    uint8_t state[info.size];
    struct ccdrbg_state* rng = (struct ccdrbg_state *)state;
    uint32_t rc=0;
    size_t rc_ctr=0;

    if (FIPS_MODE_IS_FORCEFAIL(fips_mode))
    {
        returnedBitsBuffer[0] = returnedBitsBuffer[0] ^ 0x1;
    }

    if (0==ccdrbg_init(&info, rng, sizeof(entropyInputBuffer), entropyInputBuffer,
                   sizeof(nonceBuffer), nonceBuffer,
                       sizeof(personalizationStringBuffer), personalizationStringBuffer)) {rc|=1<<rc_ctr;}
    rc_ctr++;

    if (0==ccdrbg_reseed(&info, rng, sizeof(entropyInputReseedBuffer), entropyInputReseedBuffer,
                       sizeof(additionalInputReseedBuffer), additionalInputReseedBuffer))  {rc|=1<<rc_ctr;}
    rc_ctr++;

    if (0==ccdrbg_generate(&info, rng, sizeof(resultBuffer), resultBuffer,
                           sizeof(entropyInputPR1Buffer), entropyInputPR1Buffer)) {rc|=1<<rc_ctr;}
    rc_ctr++;

    if (0==ccdrbg_generate(&info, rng, sizeof(resultBuffer), resultBuffer,
                           sizeof(entropyInputPR2Buffer), entropyInputPR2Buffer)) {rc|=1<<rc_ctr;}
    rc_ctr++;

    // Check result
    result  = (rc != ((1<<rc_ctr)-1))
        || (memcmp(resultBuffer, returnedBitsBuffer, sizeof(returnedBitsBuffer))) ? CCERR_GENERIC_FAILURE : 0;

    if (result)
    {
        failf("rc: %d", (rc != ((1 << rc_ctr) - 1)))
        return result;
    }

    return 0;
}

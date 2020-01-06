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

#import <TargetConditionals.h>

#import <corecrypto/ccaes.h>
#import <corecrypto/ccmode.h>
#import <corecrypto/ccmode_factory.h>

#include "cavs_common.h"

#import "CavsAESTest.h"
#import "CavsMemoryHelpers.h"
#import "testbyteBuffer.h"
#import "CavsMonteCarloHelper.h"

@implementation CavsAESTest


/* --------------------------------------------------------------------------
    Method:         runMonteCarloTest:(TestFileData *)testData
    Description:    Run the  Monte Carlo cipher tests
                    These tests are described in the NIST document 800-20
                    which can be found at
                    http://csrc.nist.gov/groups/STM/cavp/documents/aes/AESAVS.pdf

    The following is from the NIST AESAVS document about Monte Carlo tests:

    Each Monte Carlo Test ciphers 100 pseudorandom texts. These texts are
    generated using the algorithm specified in the section below pertaining
    to the mode of operation being tested. For modes that use an IV, the IV
    is used at the beginning of each pseudorandom text. Within each text,
    values are chained as specified in the description of the modes of
    operation found in SP 800-38A, Recommendation for Block Cipher Modes
    of Operation: Methods and Techniques.

    The REQUEST file for the MCT test contains a set of pseudorandomly
    generated initial values for the Monte Carlo function described below.
    The initial values consist of a key, an IV (for all modes except ECB),
    and a plaintext for encryption (or a ciphertext for decryption). The
    following is a sample data set:

        KEY = 9dc2c84a37850c11699818605f47958c
        IV = 256953b2feab2a04ae0180d8335bbed6
        PLAINTEXT = 2e586692e647f5028ec6fa47a55a2aab

    The RESPONSE file for the MCT test contains a series of data sets
    consisting of a key, an IV (for all modes except ECB), a plaintext
    for encryption (or ciphertext for decryption), and a ciphertext
    for encryption (or a plaintext for decryption). The following is a
    sample data set:

        KEY = 9dc2c84a37850c11699818605f47958c
        IV = 256953b2feab2a04ae0180d8335bbed6
        PLAINTEXT = 2e586692e647f5028ec6fa47a55a2aab
        CIPHERTEXT = 1b1ebd1fc45ec43037fd4844241a437f
   -------------------------------------------------------------------------- */
- (BOOL)runMonteCarloTest:(TestFileData *)testData
{
    int i;
    int j;
    int iCnt;

    NSData* key;
    NSData* iv;
    NSData* pt;
    NSData* ct;
    NSData* previousPT  = nil;
    NSData* previousCT  = nil;
    NSData* tempData    = nil;

    debugf("");

    key =   [[NSData alloc] initWithData:testData.key];
    iv =    [[NSData alloc] initWithData:testData.iv];
    pt =    [[NSData alloc] initWithData:testData.plainText];

    size_t keyLength = [testData.key length] * 8; // keylength in bits

    MonteCarloHelper* mcHelper  = nil;

    unsigned char shiftChar     = 0;
    NSInteger ctBufferSize      = 16;
    unsigned char ctBuffer[16];
    unsigned int ctBufferCount  = 0;

    NSInteger cfb8KeyBufferSize  = [key length];
    unsigned char cfb8KeyBuffer[cfb8KeyBufferSize];
    unsigned int cfb8BufferCount = 0;

    const int outer_loop_iter = 100;
    const int inner_loop_iter = 1000;

    printf("[0%%...");
    fflush(stdout);

    for (i = 0; i < outer_loop_iter; i++) {
        if (i && (i % 5) == 0) {
            printf("%d%%...", i);
            fflush(stdout);
        }

        /* Print out the current outer loop input values. */
        [self outputFormat:@"COUNT = %d", i];
        [self outputFormat:@"KEY = %@", DataToHexString(key)];

        if (testData.modeType != TFModeECB) {
            [self outputFormat:@"IV = %@", DataToHexString(iv)];
        }

        // Output the results of this run
        [self outputFormat:@"%@ = %@",
                (testData.encryption) ? @"PLAINTEXT" : @"CIPHERTEXT",  DataToHexString(pt)];

        /*
         * For CFB8 mode a set of the cipher text or plain text results is
         * needed to create an IV sized buffer when doing the key generation.
         * The ptKeyBuffer array allows for doing this.
         */
        ctBufferCount = 0;
        memset(ctBuffer, 0, ctBufferSize);

        cfb8BufferCount = 0;
        memset(cfb8KeyBuffer, 0, cfb8KeyBufferSize);

        /* Start the inner loop for the Monte Carolo tests. */
        for (j = 0; j < inner_loop_iter; j++) {
            if (j == 0) {
                /* First time special processing. */
                if (mcHelper != nil) {
                    [mcHelper clearContext];
                    [mcHelper release];
                    mcHelper = nil;
                }

                mcHelper = [[MonteCarloHelper alloc] initForMode:testData.modeType
                                                   withKeyString:self.keyString
                                            withEncryptionCipher:kAES_Encryption_Cipher
                                                   forEncryption:testData.encryption
                                                         withKey:key
                                                          withIV:iv
                                                      testTarget:testData.testTarget];

                if (mcHelper == nil) {
                    debugf("Unable to create a context for test %s",
                            [testData.testName UTF8String]);
                    [pt release];
                    [iv release];
                    [key release];

                    return NO;
                }

                /* Do the actual work of the cipher by calling CCCryptorUpdate. */
                tempData = [mcHelper update:pt];
                if (tempData == nil && [pt length] > 0) {
                    bufferf([pt bytes], [pt length], "update returned nil unexpectedly on %d/%d", i, j);
                    return NO;
                }

                ct = [tempData copy];

                /* The previous pt or ct is used by mode processing and key generation. */
                [previousPT release];
                previousPT = [pt copy];
                [pt release];
                pt = nil;

                switch(testData.modeType) {
                case TFModeECB:
                    pt = [ct copy];
                    break;
                case TFModeCBC:
                case TFModeOFB:
                case TFModeCFB:
                    pt = [iv copy];
                    break;

                case TFModeCFB8:
                    {
                        const unsigned char* ct_bytes = (unsigned char *)[ct bytes];
                        ctBuffer[ctBufferCount] = (unsigned char)*ct_bytes;
                        ctBufferCount++;

                        cfb8KeyBuffer[cfb8BufferCount] = *ct_bytes;
                        cfb8BufferCount++;

                        const unsigned char* ivPtr = (const unsigned char*)[iv bytes];
                        const unsigned char ivChar = *ivPtr;

                        pt = [[NSData alloc] initWithBytes:&ivChar length:1];
                    }
                    break;
                default:
                    debugf("Unknown cipher mode");
                    return NO;
                }
                continue;
            }


            /* The previous pt or ct is used by mode processing and key generation. */
            [previousCT release];
            previousCT = [ct copy];
            [ct release];
            ct = nil;

            tempData = [mcHelper update:pt];
            if (tempData == nil && [pt length] > 0) {
                bufferf([pt bytes], [pt length], "update returned nil unexpectedly on %d/%d", i, j);
            }

            ct = [tempData copy];

            [previousPT release];
            previousPT = [pt copy];
            [pt release];
            pt = nil;

            switch (testData.modeType) {
            case TFModeECB:
                pt = [ct copy];
                break;

            case TFModeCBC:
            case TFModeOFB:
            case TFModeCFB:
                pt = [previousCT copy];
                break;

            case TFModeCFB8:
                {
                    if (j < 16) {
                        // For the first 16 bytes use the IV as the basis of the
                        // next input data
                        const char* ivPtr = (const char*)[iv bytes];
                        const char ivChar = ivPtr[j];
                        pt = [[NSData alloc] initWithBytes:&ivChar length:1];
                    } else {
                        // After the first 16 bytes use the ctBuffer which contains
                        // the last 16 results of the cipher
                        pt = [[NSData alloc] initWithBytes:&ctBuffer[0] length:1];
                    }

                    // The CFB8 mode requires a bit of bookkeeping.  Keep the
                    // last 16 bytes of the result of the cipher in a buffer.
                    // This buffer is used to create the next round's IV
                    // The 17th preiovus result is also keep in the shift character
                    // At the end of this inner loop it will become the next
                    // input value.
                    unsigned char* lastCipherTextPtr = (unsigned char*)[ct bytes];
                    if (ctBufferCount < 16) {
                        ctBuffer[ctBufferCount] = (unsigned char)*lastCipherTextPtr;
                        ctBufferCount++;
                    } else {
                        shiftChar = (unsigned char)ctBuffer[0];
                        for (iCnt = 0; iCnt < (15); iCnt++) {
                            ctBuffer[iCnt] = ctBuffer[iCnt + 1];
                        }
                        ctBuffer[15] = (unsigned char)*lastCipherTextPtr;
                    }

                    // The CFB8 mode also need to keep track of keysize
                    // amount of the previous results.  While it MIGHT
                    // end up being the same buffer as the ctBuffer
                    // used above, it also will be larger in some cases
                    // While I might have optimized this code between this
                    // buffer and the ctBuffer, I figured that some duplication
                    // was ok and easier to do.
                    if (cfb8BufferCount < cfb8KeyBufferSize) {
                        cfb8KeyBuffer[cfb8BufferCount] = *lastCipherTextPtr;
                        cfb8BufferCount++;
                    } else {
                        for (iCnt = 0; iCnt < (cfb8KeyBufferSize - 1); iCnt++) {
                            cfb8KeyBuffer[iCnt] = cfb8KeyBuffer[iCnt + 1];
                        }

                        cfb8KeyBuffer[(cfb8KeyBufferSize - 1)] = *lastCipherTextPtr;
                    }
                }
                break;
            default:
                debugf("Unknown cipher mode");
                return NO;
            }
        }

        /* Print the results of this inner loop pass. */
        [self outputFormat:@"%@ = %@",
            (testData.encryption) ? @"CIPHERTEXT" : @"PLAINTEXT",  DataToHexString(ct)];
        [self outputString:nil];

        /*
         * Generate the keys that will be used in the next outer loop.  This
         * processing is the same for all of the modes except CFB8.  In the
         * case of CFB8, the ptKeyBuffer buffer contains the last 24 cipher
         * results This is the same length as a Triple DES key.  This buffer is
         * split into DES keys and used to compute the next keys
         */
        const char* currentKeyBuffer = (const char*)[key bytes];
        const char* currentCipherTextBuffer = (const char*)[ct bytes];
        const char* previousCipherTextBuffer = (const char*)[previousCT bytes];
        size_t bufferLength = (size_t)[testData.key length];

        char ciphertext[bufferLength];
        memset(ciphertext, 0, bufferLength);

        char keyBuffer[bufferLength];
        memset(keyBuffer, 0, bufferLength);

        // For CFB8 mode the cfb8KeyBuffer was accumlated specifically
        // to be able to use it for the next key generation.
        if (TFModeCFB8 == testData.modeType) {
            memcpy(ciphertext, cfb8KeyBuffer, cfb8KeyBufferSize);
        } else {
            // All modes other than CFB8 use the following for
            // key generation
            switch(keyLength) {
            case 128:
                memcpy(ciphertext, currentCipherTextBuffer, 16);
                break;

            case 192:
                memcpy(ciphertext, previousCipherTextBuffer + 8, 8);
                memcpy(ciphertext + 8, currentCipherTextBuffer, 16);
                break;

            case 256:
                memcpy(ciphertext, previousCipherTextBuffer, 16);
                memcpy(ciphertext + 16, currentCipherTextBuffer, 16);
                break;
            }
        }

        for (int n = 0; n < bufferLength; n++) {
            keyBuffer[n] = currentKeyBuffer[n] ^ ciphertext[n];
        }

        [key release];
        key = nil;
        key = [[NSData alloc] initWithBytes:keyBuffer length:bufferLength];

        /*
         * Generate the next IV and input data to use in the next round. The
         * Mode used changes how these two values are generated.
         */
        [pt release];
        pt = nil;

        [iv release];
        iv = nil;

        switch (testData.modeType) {
        case TFModeECB:
            // ECB mode does not use an IV so only create the next input
            // value
            pt = [ct copy];
            break;

        case TFModeCBC:
        case TFModeOFB:
        case TFModeCFB:
            // CBC, OFB, and CFB64 all use the same means to
            // create the next input value and IV
            pt = [previousCT copy];
            iv = [ct copy];
            break;

        case TFModeCFB8:
/* --------------------------------------------------------------------------
For the CFB8 mode we need to use the last 16 results as the next IV.
The 17th previous result is used as the next input value.
-------------------------------------------------------------------------- */
            pt = [[NSData alloc] initWithBytes:&shiftChar length:1];
            iv = [[NSData alloc] initWithBytes:ctBuffer length:16];
            break;
        default:
            debugf("Unknown cipher type");
            return NO;
        }
    }

    printf("]\n");
    fflush(stdout);

    if (mcHelper != nil) {
        [mcHelper clearContext];
        [mcHelper release];
    }

    [key release];
    [iv release];
    [pt release];
    [ct release];
    [previousPT release];
    return YES;
}

@end

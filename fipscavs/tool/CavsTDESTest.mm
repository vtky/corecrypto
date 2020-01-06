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

#import <corecrypto/ccdes.h>
#import <corecrypto/ccmode.h>
#import <corecrypto/ccmode_factory.h>

#include "cavs_common.h"

#import "CavsTDESTest.h"
#import "CavsMemoryHelpers.h"
#import "testbyteBuffer.h"
#import "CavsTestDispatcher.h"

unsigned char odd_par(unsigned char in);
void fix_key_parity(unsigned char* input, unsigned char* output);

/* --------------------------------------------------------------------------
    Function:       odd_par(unsigned char in)
    Description:    count the number of bits set in a byte and if an odd
                    number of bits then clear the low bit in the byte
                    otherwise set the low bit.
   -------------------------------------------------------------------------- */
unsigned char odd_par(unsigned char in)
{
    unsigned char result = in;
    int odd_count = 0;
    for (int i = 1; i < 8; i++) {
        if (in & ( 1 << i)) {
            odd_count++;
        }
    }

    if (odd_count & 1) {
        result &= ~1; // clear the low bit
    } else {
        result |= 1; // set the low bit
    }

    return result;
}

/* --------------------------------------------------------------------------
    Method:         fix_key_parity(unsigned char* input, unsigned char* output)
    Description:    loop through all 8 bytes of a DES key ensuing the proper
                    parity for each byte.

    Parameters:
        input       A 8 byte buffer with the proposed new DES key
        output      A 8 byte buffer which will be filled in with the correct
                    parity for each byte.
   -------------------------------------------------------------------------- */
void fix_key_parity(unsigned char* input, unsigned char* output)
{
    for (int i = 0; i < CCDES_KEY_SIZE; i++) {
        output[i] = odd_par(input[i]);
    }
}


@implementation CAVTDESTest

/* --------------------------------------------------------------------------
    Method:         runMonteCarloTest:(TestFileData *)testData
    Description:    Run the Monte Carlo cipher tests
                    These tests are described in the NIST document 800-20
                    which can be found at
                    http://csrc.nist.gov/publications/nistpubs/800-20/800-20.pdf


    The following is from the NIST 800-20 document about Monte Carlo tests:

    The Monte Carlo Test is the second type of validation test required to
    validate IUTs. The Monte Carlo Test is based on the Monte-Carlo test
    discussed in Special Publication 500-20. It is designed to exercise
    he entire implementation of the TDEA, as opposed to testing only the
    individual components. The purpose of the Monte Carlo Test is to detect
    the presence of flaws in the IUT that were not detected with the
    controlled input of the Known Answer tests. Such flaws may include
    pointer problems, errors in the allocation of space, improper error
    handling, and incorrect behavior of the TDEA implementation when
    random values are introduced. The Monte Carlo Test does not guarantee
    ultimate reliability of the IUT that implements the TDEA
    (i.e., hardware failure, software corruption, etc.).

    The TMOVS supplies the IUT with initial input values for the keys, the
    plaintext(s) (or ciphertext(s)), and, if applicable, initialization
    vector(s). The Monte Carlo Test is then performed (as described in the
    following paragraph), and the resulting ciphertext (or plaintext) values
    are recorded and compared to expected values. If an error is detected,
    the erroneous result is recorded, and the test terminates abnormally.
    Otherwise, the test continues. If the IUT's results are correct, the
    Monte Carlo Test for the IUT ends successfully.

    Each Monte Carlo Test consists of four million cycles through the TDEA
    implemented in the IUT. These cycles are divided into four hundred
    groups of 10,000 iterations each. Each iteration consists of
    processing an input block through three operations of the DEA resulting
    in an output block. For IUTs of the encryption process, the three
    DES operations are encrypted with KEY1, decrypted with KEY2, and
    encrypted with KEY3. For IUTs of the decryption process, the three
    DES operations are decrypted with KEY3, encrypted with KEY2, and
    decrypted with KEY1. At the 10,000th cycle in an iteration, new values
    are assigned to the variables needed for the next iteration. The results
    of each 10,000th encryption or decryption cycle are recorded and
    evaluated as specified in the preceding paragraph.
   -------------------------------------------------------------------------- */
- (BOOL)runMonteCarloTest:(TestFileData *)testData
{
    NSAutoreleasePool* pool = [NSAutoreleasePool new];

    int i;
    int j;
    int iCnt;

    NSData* key1                = nil;
    NSData* key2                = nil;
    NSData* key3                = nil;
    NSData* key                 = nil;
    NSData* iv                  = nil;
    NSData* pt                  = nil;
    NSData* ct                  = nil;
    NSData* previousKey1        = nil;
    NSData* previousKey2        = nil;
    NSData* previousKey3        = nil;
    NSData* nextIV              = nil;
    NSData* previousIV          = nil;
    NSData* previousPT          = nil;
    NSData* originalPT          = nil;
    NSData* previousCT          = nil;
    NSData* previousPreviousCT  = nil;

    key1    = [[NSData alloc] initWithData:testData.key1];
    key2    = [[NSData alloc] initWithData:testData.key2];
    key3    = [[NSData alloc] initWithData:testData.key3];
    key     = [[NSData alloc] initWithData:testData.key];
    iv      = [[NSData alloc] initWithData:testData.iv];
    pt      = [[NSData alloc] initWithData:testData.plainText];

    NSInteger ivLength      = [testData.iv length];
    NSInteger origPTLength  = [testData.plainText length];

    unsigned char keyBuffer[CCDES_KEY_SIZE];
    unsigned char xorBuffer[CCDES_KEY_SIZE];
    unsigned char ptKeyBuffer[CCDES_KEY_SIZE * 3];
    unsigned int ptKeyBufferCount = 0;
    NSString* ctStr             = nil;
    MonteCarloHelper* mcHelper  = nil;
    NSData* tempData            = nil;

    const int outer_loop_iter = 400;
    const int inner_loop_iter = 10000;

    printf("[0%%...");
    fflush(stdout);

    for (i = 0; i < outer_loop_iter; i++)
    {
        if (i && (i % 20) == 0) {
            printf("%d%%...", (i * 100) / outer_loop_iter);
            fflush(stdout);
        }

        [self outputFormat:@"COUNT = %d", i];
        [self outputFormat:@"KEY1 = %@", DataToHexString(key1)];
        [self outputFormat:@"KEY2 = %@", DataToHexString(key2)];
        [self outputFormat:@"KEY3 = %@", DataToHexString(key3)];

        if (testData.modeType  != TFModeECB) {
            [self outputFormat:@"IV = %@", DataToHexString(iv)];
        }

        if (testData.encryption) {
            [self outputFormat:@"PLAINTEXT = %@", DataToHexString(pt)];
        } else {
            [self outputFormat:@"CIPHERTEXT = %@", DataToHexString(pt)];
        }

        [originalPT release];
        originalPT = nil;
        originalPT = [pt copy];

        ptKeyBufferCount = 0;
        memset(ptKeyBuffer, 0, CCDES_KEY_SIZE * 3);

        for (j = 0; j < inner_loop_iter; j++) {

            if (j == 0) {
                if (mcHelper != nil) {
                    [mcHelper clearContext];
                    [mcHelper release];
                    mcHelper = nil;
                }

                mcHelper = [[MonteCarloHelper alloc] initForMode:testData.modeType
                    withKeyString:self.keyString
                    withEncryptionCipher:kTDES_Encryption_Cipher
                    forEncryption:testData.encryption
                    withKey:key
                    withIV:iv
                    testTarget:testData.testTarget];

                if (mcHelper == nil) {
                    errorf("failed to create helper");
                    [pool drain];
                    return NO;
                }

                tempData = [mcHelper update:pt];
                if (tempData == nil && [pt length] > 0) {
                    bufferf([pt bytes], [pt length], "update returned nil unexpectedly on %d/%d", i, j);
                    return NO;
                }
                ct = [tempData copy];

                [previousPT release];
                previousPT = [[NSData alloc] initWithData:pt];
                [pt release];
                pt = nil;

                switch(testData.modeType) {
                    case TFModeECB:
                        pt = [ct copy];
                        break;

                    case TFModeOFB: {
                            // Next Input is the prvious IV
                            pt = [iv copy];

                            unsigned char* lastCipherTestPtr = (unsigned char*)[ct bytes];
                            unsigned char* lastTextPtr = (unsigned char*)[originalPT bytes];
                            unsigned char newptXORBuffer[CCDES_BLOCK_SIZE];
                            for (iCnt = 0; iCnt < ivLength; iCnt++) {
                                newptXORBuffer[iCnt] = lastCipherTestPtr[iCnt] ^ lastTextPtr[iCnt];
                            }

                            [previousIV release];
                            previousIV = nil;
                            previousIV = [nextIV copy];

                            [nextIV release];
                            nextIV = nil;
                            nextIV = [[NSData alloc] initWithBytes:newptXORBuffer length:ivLength];
                        }
                        break;

                    case TFModeCBC:
                        if (testData.encryption) {
                            pt = [iv copy];
                        } else {
                            pt = [ct copy];
                        }
                        break;

                    case TFModeCFB:
                    case TFModeCFB8:
                        {
                            unsigned char* ivPtr = (unsigned char*)[iv bytes];
                            unsigned char newIVBuffer[CCDES_BLOCK_SIZE];
                            unsigned char* lastCipherTestPtr = (unsigned char*)[ct bytes];

                            if (TFModeCFB8 == testData.modeType) {
                                unsigned char* iv0Bytes = (unsigned char *)[iv bytes];
                                unsigned char* ivPtr = &iv0Bytes[1];
                                memcpy(newIVBuffer, ivPtr, (ivLength - 1));
                                unsigned char* ctBytes = (unsigned char *)((testData.encryption) ? [ct bytes] : [previousPT bytes]);
                                newIVBuffer[(ivLength - 1)] = *ctBytes;
                            } else {
                                for (iCnt = 0; iCnt < ivLength; iCnt++) {
                                    newIVBuffer[iCnt] = lastCipherTestPtr[iCnt];
                                }
                            }
                            [nextIV release];
                            nextIV = nil;
                            nextIV = [[NSData alloc] initWithBytes:newIVBuffer length:ivLength];

                            // Compute the next input (either plain or cipher text) for the next round.
                            if (testData.encryption) {
                                unsigned char newPTBuffer[CCDES_BLOCK_SIZE];
                                memcpy(newPTBuffer, ivPtr, origPTLength);
                                pt = [[NSData alloc] initWithBytes:newPTBuffer length:origPTLength];

                                // For the CFB8 mode start populating the ptKeyBuffer
                                if (TFModeCFB8 == testData.modeType) {
                                    ptKeyBuffer[ptKeyBufferCount] = newPTBuffer[0];
                                    ptKeyBufferCount++;
                                }
                            } else {
                                unsigned char* lastTextPtr = (unsigned char*)[originalPT bytes];
                                unsigned char* lastCipherTestPtr = (unsigned char*)[ct bytes];
                                unsigned char newptXORBuffer[CCDES_BLOCK_SIZE];
                                for (iCnt = 0; iCnt < origPTLength; iCnt++) {
                                    newptXORBuffer[iCnt] = lastTextPtr[iCnt] ^ lastCipherTestPtr[iCnt];
                                }
                                pt = [[NSData alloc] initWithBytes:newptXORBuffer length:origPTLength];

                                // For the CFB8 mode start populating the ptKeyBuffer
                                if (TFModeCFB8 == testData.modeType && origPTLength > 0) {
                                    ptKeyBuffer[ptKeyBufferCount] = newptXORBuffer[0];
                                    ptKeyBufferCount++;
                                }
                            }
                        }
                        break;
                    default:
                        errorf("Unknown Mode %d\n", (int)testData.modeType);
                        [pool drain];
                        [key release];
                        [key1 release];
                        [key2 release];
                        [key3 release];
                        [ct release];
                        [iv release];
                        [originalPT release];
                        [previousPT release];
                        return NO;
                }
            } else {
                // Do the cipher
                 tempData = [mcHelper update:pt];

                // Keep track of the previous previous output and the previous output
                [previousPreviousCT release];
                previousPreviousCT = [previousCT copy];
                [previousCT release];
                previousCT = [ct copy];
                [ct release];
                ct = nil;
                ct = [tempData copy];

                // Keep track of the previous input
                [previousPT release];
                previousPT = [[NSData alloc] initWithData:pt];
                [pt release];
                pt = nil;

                switch (testData.modeType)
                {
                    case TFModeECB:
                        pt = [ct copy];
                        break;

                    case TFModeCBC:
                        if (testData.encryption) {
                            pt = [previousCT copy];
                        } else {
                            pt = [ct copy];
                        }
                        break;

                    case TFModeOFB:
                        {
                            unsigned char* lastCipherTestPtr = (unsigned char*)[ct bytes];
                            unsigned char* lastTextPtr = (unsigned char*)[previousPT bytes];
                            unsigned char newptXORBuffer[CCDES_BLOCK_SIZE];

                            for (iCnt = 0; iCnt < ivLength; iCnt++) {
                                newptXORBuffer[iCnt] = lastCipherTestPtr[iCnt] ^ lastTextPtr[iCnt];
                            }

                            [previousIV release];
                            previousIV = nil;
                            previousIV = [nextIV copy];

                            pt = [nextIV copy];
                            [nextIV release];
                            nextIV = nil;

                            nextIV = [[NSData alloc] initWithBytes:newptXORBuffer length:ivLength];
                        }
                        break;

                    case TFModeCFB:
                    case TFModeCFB8:
                        {
                            [previousIV release];
                            previousIV = nil;
                            previousIV = [nextIV copy];

                            unsigned char* ivPtr = (unsigned char*)[nextIV bytes];
                            unsigned char newIVBuffer[CCDES_BLOCK_SIZE];
                            unsigned char* lastCipherTestPtr = (unsigned char*)((testData.encryption) ? [ct bytes] : [previousPT bytes]);

                            if (TFModeCFB8 == testData.modeType) {
                                unsigned char* ivOffsetPtr = &ivPtr[1];
                                memcpy(newIVBuffer, ivOffsetPtr, (ivLength - 1));
                                newIVBuffer[(ivLength - 1)] = *lastCipherTestPtr;
                            } else {
                                for (iCnt = 0; iCnt < ivLength; iCnt++) {
                                    newIVBuffer[iCnt] = lastCipherTestPtr[iCnt];
                                }
                            }

                            [nextIV release];
                            nextIV = nil;
                            nextIV = [[NSData alloc] initWithBytes:newIVBuffer length:ivLength];

                            if (testData.encryption) {
                                unsigned char newPTBuffer[CCDES_BLOCK_SIZE];
                                memcpy(newPTBuffer, ivPtr, origPTLength);
                                pt = [[NSData alloc] initWithBytes:newPTBuffer length:origPTLength];

                                if (TFModeCFB8 == testData.modeType) {
                                    if (ptKeyBufferCount < kCCKeySize3DES) {
                                        ptKeyBuffer[ptKeyBufferCount] = lastCipherTestPtr[0];
                                        ptKeyBufferCount++;
                                    } else {
                                        for (iCnt = 0; iCnt < (kCCKeySize3DES - 1); iCnt++) {
                                            ptKeyBuffer[iCnt] = ptKeyBuffer[iCnt + 1];
                                        }
                                        ptKeyBuffer[(kCCKeySize3DES - 1)] = lastCipherTestPtr[0];
                                    }
                                }
                            } else {
                                // Compute the next input
                                unsigned char* lastTextPtr = (unsigned char*)[previousPT bytes];
                                unsigned char* lastCipherTestPtr = (unsigned char*)[ct bytes];
                                unsigned char newptXORBuffer[CCDES_BLOCK_SIZE];
                                for (iCnt = 0; iCnt < origPTLength; iCnt++) {
                                    newptXORBuffer[iCnt] = lastTextPtr[iCnt] ^ lastCipherTestPtr[iCnt];
                                }
                                pt = [[NSData alloc] initWithBytes:newptXORBuffer length:origPTLength];

                                // We need at the end of the rounds a 3DES sized buffer filled with
                                // the last 24 PTs for CFB8 mode.
                                if (TFModeCFB8 == testData.modeType) {
                                    if (ptKeyBufferCount < kCCKeySize3DES) {
                                        ptKeyBuffer[ptKeyBufferCount] = *lastCipherTestPtr;
                                        ptKeyBufferCount++;
                                    } else {
                                        for (iCnt = 0; iCnt < (kCCKeySize3DES - 1); iCnt++) {
                                            ptKeyBuffer[iCnt] = ptKeyBuffer[iCnt + 1];
                                        }
                                        ptKeyBuffer[(kCCKeySize3DES - 1)] = *lastCipherTestPtr;
                                    }
                                }
                            }
                        }
                        break;

                    default:
                        errorf("Unknown Mode %d\n", (int)testData.modeType);
                        [pool drain];
                        [pool drain];
                        [key release];
                        [key1 release];
                        [key2 release];
                        [key3 release];
                        [ct release];
                        [iv release];
                        [originalPT release];
                        [previousPT release];
                        [nextIV release];
                        [previousCT release];
                        [previousIV release];
                        [previousPreviousCT release];
                        return NO;
                }
            }
        }
        ctStr = DataToHexString(ct);

        [self outputFormat:@"%@ = %@",
            (testData.encryption) ? @"CIPHERTEXT" : @"PLAINTEXT",  ctStr];
        [self outputString:nil];

        // Generate the next set of keys
        NSData* cfb8Key1 = nil;
        NSData* cfb8Key2 = nil;
        NSData* cfb8Key3 = nil;

        if (TFModeCFB8 == testData.modeType) {
            cfb8Key1 = [[NSData alloc] initWithBytes:&ptKeyBuffer[CCDES_KEY_SIZE * 2] length:CCDES_KEY_SIZE];
            cfb8Key2 = [[NSData alloc] initWithBytes:&ptKeyBuffer[CCDES_KEY_SIZE] length:CCDES_KEY_SIZE];
            cfb8Key3 = [[NSData alloc] initWithBytes:ptKeyBuffer length:CCDES_KEY_SIZE];
        }

        [previousKey1 release];
        previousKey1 = nil;
        previousKey1 = [key1 copy];

        [previousKey2 release];
        previousKey2 = nil;
        previousKey2 = [key2 copy];

        [previousKey3 release];
        previousKey3 = nil;
        previousKey3 = [key3 copy];

        const unsigned char* keyBytes = (const unsigned char*)[key1 bytes];
        const unsigned char* resultBytes = nil;
        if (TFModeCFB8 == testData.modeType) {
            resultBytes = (const unsigned char*)[cfb8Key1 bytes];
        } else {
            resultBytes = (const unsigned char*)[ct bytes];
        }

        for (iCnt = 0; iCnt < CCDES_KEY_SIZE; iCnt++) {
            xorBuffer[iCnt] =  keyBytes[iCnt] ^ resultBytes[iCnt];
        }
        fix_key_parity(xorBuffer, keyBuffer);
        [key1 release];
        key1 = nil;

        key1 = [[NSData alloc] initWithBytes:keyBuffer length:CCDES_KEY_SIZE];

        if (![previousKey1 isEqualToData:key2]) {
            keyBytes = (const unsigned char*)[previousKey2 bytes];
            if (TFModeCFB8 == testData.modeType) {
                resultBytes = (const unsigned char*)[cfb8Key2 bytes];
            } else {
                resultBytes = (const unsigned char*)[previousCT bytes];
            }
        } else {
            keyBytes = (const unsigned char*)[key2 bytes];
            if (TFModeCFB8 == testData.modeType) {
                resultBytes = (const unsigned char*)[cfb8Key1 bytes];
            } else {
                resultBytes = (const unsigned char*)[ct bytes];
            }
        }

        for (iCnt = 0; iCnt < CCDES_KEY_SIZE; iCnt++) {
            xorBuffer[iCnt] =  keyBytes[iCnt] ^ resultBytes[iCnt];
        }
        fix_key_parity(xorBuffer, keyBuffer);
        [key2 release];
        key2 = nil;
        key2 = [[NSData alloc] initWithBytes:keyBuffer length:CCDES_KEY_SIZE];

        keyBytes = (const unsigned char*)[key3 bytes];
        if (![previousKey1 isEqualToData:key3]) {
            if (TFModeCFB8 == testData.modeType) {
                resultBytes = (const unsigned char*)[cfb8Key3 bytes];
            } else {
                resultBytes = (const unsigned char*)[previousPreviousCT bytes];
            }
        } else {
            if (TFModeCFB8 == testData.modeType) {
                resultBytes = (const unsigned char*)[cfb8Key1 bytes];
            } else {
                resultBytes = (const unsigned char*)[ct bytes];
            }
        }

        for (iCnt = 0; iCnt < CCDES_KEY_SIZE; iCnt++) {
            xorBuffer[iCnt] =  keyBytes[iCnt] ^ resultBytes[iCnt];
        }
        fix_key_parity(xorBuffer, keyBuffer);
        [key3 release];
        key3 = nil;
        key3 = [[NSData alloc] initWithBytes:keyBuffer length:CCDES_KEY_SIZE];

        NSMutableData* tempKey = [NSMutableData new];
        [key release];
        key = nil;
        [tempKey appendData:key1];
        [tempKey appendData:key2];
        [tempKey appendData:key3];
        key = [[NSData alloc] initWithData:tempKey];
        [tempKey release];

        [cfb8Key1 release];
        cfb8Key1 = nil;
        [cfb8Key2 release];
        cfb8Key2 = nil;
        [cfb8Key3 release];
        cfb8Key3 = nil;

        switch (testData.modeType) {
            case TFModeECB:
                [pt release];
                pt = nil;
                pt = [ct copy];
                break;

            case TFModeCBC:
                if (testData.encryption) {
                    [pt release];
                    pt = nil;
                    [iv release];
                    iv = nil;

                    pt = [previousCT copy];
                    iv = [ct copy];
                } else {
                    [iv release];
                    iv = nil;
                    iv = [previousPT copy];

                    [pt release];
                    pt = nil;
                    pt = [ct copy];
                }
                break;

            case TFModeOFB:
                {
                    const unsigned char* tempTextPtr = (const unsigned char *)[originalPT bytes];
                    unsigned char tempBuffer[CCDES_BLOCK_SIZE];
                    unsigned char* ucIVPtr = (unsigned char*)[previousIV bytes];
                    for (iCnt = 0; iCnt < ivLength; iCnt++) {
                        tempBuffer[iCnt] = tempTextPtr[iCnt] ^ ucIVPtr[iCnt];
                    }

                    pt = [[NSData alloc] initWithBytes:tempBuffer length:ivLength];

                    unsigned char* lastTextPtr = (unsigned char*)[previousPT bytes];
                    unsigned char* lastCipherTestPtr = (unsigned char*)[ct bytes];
                    unsigned char ivXORBuffer[CCDES_BLOCK_SIZE];
                    for (iCnt = 0; iCnt < ivLength; iCnt++) {
                        ivXORBuffer[iCnt] = lastTextPtr[iCnt] ^ lastCipherTestPtr[iCnt];
                    }
                    [iv release];
                    iv = nil;
                    iv = [[NSData alloc] initWithBytes:ivXORBuffer length:ivLength];

                    [previousIV release];
                    previousIV = nil;
                    [nextIV release];
                    nextIV = nil;
                }
                break;

            case TFModeCFB:
            case TFModeCFB8:
                {
                    if (testData.encryption) {
                        [pt release];
                        pt = nil;
                        unsigned char* ivPtr = (unsigned char*)[previousIV bytes];
                        unsigned char newPTBuffer[CCDES_BLOCK_SIZE];;
                        memcpy(newPTBuffer, ivPtr, origPTLength);
                        pt = [[NSData alloc] initWithBytes:newPTBuffer length:origPTLength];
                    } else {
                        // Compute the next input
                        unsigned char* lastTextPtr = (unsigned char*)[previousPT bytes];
                        unsigned char* lastCipherTestPtr = (unsigned char*)[ct bytes];

                        unsigned char newptXORBuffer[CCDES_BLOCK_SIZE];
                        for (iCnt = 0; iCnt < origPTLength; iCnt++) {
                            newptXORBuffer[iCnt] = lastTextPtr[iCnt] ^ lastCipherTestPtr[iCnt];
                        }

                        [pt release];
                        pt = [[NSData alloc] initWithBytes:newptXORBuffer length:origPTLength];
                    }

                    // common code for encryption or decryption for setting the next
                    // IV
                    if (TFModeCFB == testData.modeType) {
                        [iv release];
                        iv = nil;
                        if (testData.encryption) {
                            iv = [ct copy];
                        } else {
                            iv = [previousPT copy];
                        }
                    } else {
                        [iv release];
                        iv = nil;
                        iv = [[NSData alloc] initWithData:nextIV];
                    }
                    [previousIV release];
                    previousIV = nil;
                    [nextIV release];
                    nextIV = nil;
                }
                break;

            default:
                errorf("Unknown Mode %d\n", (int)testData.modeType);
                [pool drain];
                return NO;
        }
    }

    printf("]\n");
    fflush(stdout);

    if (mcHelper != nil) {
        [mcHelper clearContext];
        [mcHelper release];
    }

    [key1 release];
    [key2 release];
    [key3 release];
    [key release];
    [iv release];
    [pt release];
    [ct release];
    [previousPT release];
    [nextIV release];
    [previousIV release];
    [previousKey1 release];
    [previousKey2 release];
    [previousKey3 release];
    [pool drain];
    return YES;
}

@end

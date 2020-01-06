/*
 * Copyright (c) 2012,2013,2015,2016,2017,2018 Apple Inc. All rights reserved.
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

#import <Foundation/Foundation.h>

#include <string.h>
#include <stdint.h>

#include "cc_debug.h"

#import <mach/mach_types.h>
#import <mach/kmod.h>
#import <mach-o/loader.h>
#import <mach/machine.h>
#import <mach-o/fat.h>
#import <mach-o/swap.h>
#import <corecrypto/ccdigest.h>
#import <corecrypto/ccsha2.h>
#import <corecrypto/cchmac.h>

#include "hexToString.h"

#include "fipspost.h"

#include "fipspost_get_cpu_key.h"
#include "fipspost_get_hmac.h"

/* ==========================================================================
    The HMACFileTool is run as part of the creation of the corecrypto
    kext for BOTH OSX and iOS.  The tool itself is always an OSX command
    line tool that runs during the build process for creating the kext.

    When building for iOS I need to be able to distinguish between
    different CPU and CPU subtypes. So the correct "slice" can be chosen
    and written out so that when the device is run the correct slice is
    matched and the HMACs will be the same.

    ========================================================================== */

/* ==========================================================================
    End stolen defines from the iOS machine.h file
   ========================================================================== */

static NSString* kAppleTextHashesKey = @"AppleTextHashes";

FIPSPOST_DECLARE_PRECALC_HMAC;

static BOOL get_hmac_value(const struct mach_header *pmach_header,
        unsigned char *hmac_buffer, char *keyValue, size_t keyValue_length)
{
    BOOL result = NO;

    if (NULL == pmach_header || NULL == hmac_buffer || NULL == keyValue) {
        return result;
    }
    if (0 == fipspost_get_cpu_key(keyValue,keyValue_length,
            pmach_header->cputype, pmach_header->cpusubtype
            /*& ~CPU_SUBTYPE_MASK*/)) {
        return result;
    }

    return (0 == fipspost_get_hmac(pmach_header, hmac_buffer, 0));
}

static BOOL StringStartsWithDash(NSString *tempStr)
{
    const char *cStr = [tempStr UTF8String];
    return (*cStr == '-');
}

static void usage(const char* programName)
{
    printf("%s usage:\n", programName);
    printf(" [-h, --help]          \tPrint out this help message\n");
    printf(" [-i, --input]         \tSpecify the file that will be have a HMAC created\n");
    printf(" [-f, --file]          \tSpecifiy the file that will be written out with the generated HMAC\n");
    printf(" [-p, --plist]         \tSpecify the plist file that will received the HMAC data\n");
    printf(" [-b, --binary]        \tWrite the binary hash at the supplied offset in -f\n");
    printf(" [-u, --undo]          \tOverwrite the calculated hash with the expected hash (requires -b)\n");
    printf("\n");
}

int main (int argc, const char * argv[])
{

    @autoreleasepool
    {
        const char*      programName = argv[0];
        NSString*        inputPath  = nil;
        NSString*        plistPath = nil;
        NSString*        filePath = nil;
        NSFileManager*   fileManager = [NSFileManager defaultManager];
        BOOL             isDir = NO;
        BOOL             isForKext;
        BOOL             isBinary = NO;
        BOOL             isUndo = NO;
        NSError*         error = nil;

        for (int iCnt = 1; iCnt < argc; iCnt++) {
            const char *arg = argv[iCnt];

            if (!strcmp(arg, "-h") || !strcmp(arg, "--help")) {
                return -1;
            } else if (!strcmp(arg, "-b") || !strcmp(arg, "--binary")) {
                isBinary = YES;
            } else if (!strcmp(arg, "-i") || !strcmp(arg, "--input")) {
                if ((iCnt + 1) == argc) {
                    return -1;
                }

                inputPath = [NSString stringWithUTF8String:argv[iCnt + 1]];
                if (nil == inputPath || StringStartsWithDash(inputPath)) {
                    return -1;
                }

                iCnt++;

                inputPath = [inputPath stringByExpandingTildeInPath];

                if (![fileManager fileExistsAtPath:inputPath isDirectory:&isDir] || isDir) {
                    return -1;
                }
            } else if (!strcmp(arg, "-p") || !strcmp(arg, "--plist")) {
                if ((iCnt + 1) == argc) {
                    return -1;
                }

                plistPath = [NSString stringWithUTF8String:argv[iCnt + 1]];
                if (nil == plistPath || StringStartsWithDash(plistPath)) {
                    return -1;
                }

                iCnt++;

                plistPath = [plistPath stringByExpandingTildeInPath];

                if (![fileManager fileExistsAtPath:plistPath isDirectory:&isDir] || isDir) {
                    return -1;
                }
            } else if (!strcmp(arg, "-f") || !strcmp(arg, "--file")) {
                if ((iCnt + 1) == argc) {
                    return -1;
                }

                filePath = [NSString stringWithUTF8String:argv[iCnt + 1]];
                if (nil == filePath || StringStartsWithDash(filePath)) {
                    return -1;
                }

                iCnt++;

                filePath = [filePath stringByExpandingTildeInPath];
            } else if (!strcmp(arg, "-a") || !strcmp(arg, "--arch")) {

                if ((iCnt + 1) == argc) {
                    return -1;
                }

                iCnt++;  // ignore
            } else if (!strcmp(arg, "-u") || !strcmp(arg, "--undo")) {
                isUndo = TRUE;
            }
        }

        if (isUndo && !isBinary) {
            fprintf(stderr, "Error: Undo requires binary");
            usage(programName);
            return -1;
        }

        // Make sure we have what is needed
        if (nil == inputPath) {
            fprintf(stderr, "No input specified\n");
            usage(programName);
            return -1;
        }

        // Only one of either -p or -f can be used
        if (nil == filePath && nil == plistPath) {
            fprintf(stderr, "Only one of either -p or -f can be used\n");
            usage(programName);
            return -1;
        }

        if (nil != filePath && nil != plistPath) {
            fprintf(stderr, "Only one of filePath or plist can be used\n");
            usage(programName);
            return -1;
        }

        isForKext  = (nil != plistPath);

        // First generate the HMAC
        NSData* input_data = [NSData dataWithContentsOfFile:inputPath options:NSDataReadingMappedIfSafe error:&error];
        if (error != nil || nil == input_data) {
            fprintf(stderr, "Could not read the kext file at %s\n", [inputPath UTF8String]);
            usage(programName);
            return -1;
        }

        size_t file_length = [input_data length];
        unsigned char *pData = (unsigned char *)malloc(file_length);
        memcpy(pData, [input_data bytes], [input_data length]);

        NSMutableDictionary *recordsToWrite = [NSMutableDictionary dictionary];
        size_t sha256DigestBufferLength = FIPSPOST_PRECALC_HMAC_SIZE;
        unsigned char hmac_buffer[sha256DigestBufferLength];
        char keyStr[256]; // label in fips_data file
        NSData* hmacValue = nil;

        // Look to see if this is a FAT mach file.  While the
        struct fat_header fHeader;
        memset(&fHeader, 0, sizeof(fHeader));
        memcpy(&fHeader, (struct fat_header*)pData, sizeof(fHeader));

        struct fat_arch fArch;
        memset(&fArch, 0, sizeof(fArch));

        if (FAT_MAGIC == fHeader.magic || FAT_CIGAM == fHeader.magic) {
            NSLog(@"This MACH file is FAT");
            // This is a FAT mach header
            // Loop through the archs

            // Swap the fat_header
            swap_fat_header(&fHeader, NXHostByteOrder());
            uint32_t arch_cnt;
            size_t fat_header_size = sizeof(struct fat_header);
            size_t fat_arch_size = sizeof(struct fat_arch);

            NSLog(@"FAT: There are %d archs in the file", fHeader.nfat_arch);
            for (arch_cnt = 0; arch_cnt < fHeader.nfat_arch; arch_cnt++) {
                NSLog(@"FAT: Processing arch %d", arch_cnt);
                size_t arch_offset = fat_header_size + (fat_arch_size * arch_cnt);

                struct fat_arch *arch_struct = (struct fat_arch *)(pData + arch_offset);
                memset(&fArch, 0, fat_arch_size);
                memcpy(&fArch, arch_struct, fat_arch_size);

                swap_fat_arch(&fArch, 1, NXHostByteOrder());

                struct mach_header *pmach_header = (struct mach_header *)(((unsigned char *)pData) + fArch.offset);

                memset(hmac_buffer, 0, sha256DigestBufferLength);
                if (!get_hmac_value(pmach_header, hmac_buffer, keyStr, sizeof(keyStr))) {
                    fprintf(stderr, "Could not create the HMAC(1) for the file %s\n", [inputPath UTF8String]);
                    free (pData);
                    return -1;
                }
                NSLog(@"Slice label string {%s}",keyStr);
                NSString *keyNSStr = [NSString stringWithCString:keyStr encoding:NSASCIIStringEncoding];
                hmacValue = [NSData dataWithBytes:hmac_buffer length:sha256DigestBufferLength];
                [recordsToWrite setObject:hmacValue forKey:keyNSStr];
            }
        } else {
            NSLog(@"This is NOT a FAT MACH file. Processing a single arch");
            // This is not a FAT mach header
            const struct mach_header *pmach_header = (const struct mach_header *)[input_data bytes];
            memset(hmac_buffer, 0, sha256DigestBufferLength);
            if (!get_hmac_value(pmach_header, hmac_buffer, keyStr,sizeof(keyStr))) {
                fprintf(stderr, "Could not create the HMAC(2) for the file %s\n", [inputPath UTF8String]);
                free (pData);
                return -1;
            }

            NSString *keyNSStr = [NSString stringWithCString:keyStr encoding:NSASCIIStringEncoding];
            hmacValue = [NSData dataWithBytes:hmac_buffer length:sha256DigestBufferLength];
            [recordsToWrite setObject:hmacValue forKey:keyNSStr];
        }

        // Put together the data that will be parsed in corecrypto
        NSMutableData *file_data = [NSMutableData data];
        NSArray *hashKeys = [recordsToWrite allKeys];
        for (NSString *dictKeyStr in hashKeys) {
            NSLog(@"Setting the hash data for the %@ arch", dictKeyStr);
            NSData *hash_data = [recordsToWrite objectForKey:dictKeyStr];
            char *temp_buffer;
            size_t len = hexToString(NULL, 0, [hash_data bytes], [hash_data length], 0);
            temp_buffer = malloc(len);
            hexToString(temp_buffer, len, [hash_data bytes], [hash_data length], 0);

            NSString *hash_data_hex_str = [NSString stringWithUTF8String:(const char *)temp_buffer];
            NSLog(@"key = %@ hash_data_hex_str is %@", dictKeyStr, hash_data_hex_str);
            NSString *output_str = [NSString stringWithFormat:@"%@:%@\n", dictKeyStr, hash_data_hex_str];
            NSData *output_str_data = [output_str dataUsingEncoding:NSUTF8StringEncoding];
            [file_data appendData:output_str_data];
            free(temp_buffer);
        }

        // Print to file
        if (isForKext) {   // This is for the Kext on iOS and OSX
            NSMutableDictionary *kext_plist = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath];
            if (nil == kext_plist) {
                fprintf(stderr,"No plist was found at %s\n", [plistPath UTF8String]);
                free (pData);
                return -1;
            }
#if FIPS_POST_VERSION>1
            [kext_plist setObject:file_data forKey:kAppleTextHashesKey];
#else
            NSMutableDictionary *hash_dict = [NSMutableDictionary dictionary];
            for (NSString* dictKeyStr in hashKeys) {
                NSLog(@"Setting the hash data for the %@ arch", dictKeyStr);
                NSData *hash_data = [recordsToWrite objectForKey:dictKeyStr];
                [hash_dict setObject:hash_data forKey:dictKeyStr];
            }

            [kext_plist setObject:hash_dict forKey:kAppleTextHashesKey];
#endif
            [kext_plist writeToFile:plistPath atomically:TRUE];
        } else if (isBinary) {
            NSLog(@"Performing binary patching");
            if (![fileManager fileExistsAtPath:filePath]) {
                NSLog(@"File %@ not found for binary output", filePath);
                return -1;
            }

            // Get the contents of the file.
            NSMutableData *contents = [[fileManager contentsAtPath:filePath] mutableCopy];
            if ([contents length] < FIPSPOST_PRECALC_HMAC_SIZE) {
                NSLog(@"File %@ is insufficiently large", filePath);
                return -1;
            }

            // Find the appropriate precalculated hmac for each architecture
            // and replace it.
            for (NSString* dictKeyStr in hashKeys) {
                NSMutableData *keyBuffer;

                // Utility macro to render ugly code easier to read.
#define HMAC_AS_NSDATA(ARCH, VARIANT)                                       \
    [NSMutableData dataWithBytes:(uint8_t [FIPSPOST_PRECALC_HMAC_SIZE])     \
            FIPSPOST_PRECALC_HMAC_VALUE_ ## ARCH ## _ ## VARIANT            \
        length:FIPSPOST_PRECALC_HMAC_SIZE]

                /* Comprehensive list, in the order of mach/machine.h */
                if ([dictKeyStr isEqualToString:@"x86_64"])         { keyBuffer = HMAC_AS_NSDATA(X86, 64); }
                else if ([dictKeyStr isEqualToString:@"i386"])      { keyBuffer = HMAC_AS_NSDATA(X86, 32); }

                else if ([dictKeyStr isEqualToString:@"armv4t"])    { keyBuffer = HMAC_AS_NSDATA(ARM, 4T); }
                else if ([dictKeyStr isEqualToString:@"armv6"])     { keyBuffer = HMAC_AS_NSDATA(ARM, 6); }
                else if ([dictKeyStr isEqualToString:@"armv5tej"])  { keyBuffer = HMAC_AS_NSDATA(ARM, V5TEJ); }
                else if ([dictKeyStr isEqualToString:@"armxscale"]) { keyBuffer = HMAC_AS_NSDATA(ARM, XSCALE); }
                else if ([dictKeyStr isEqualToString:@"armv7"])     { keyBuffer = HMAC_AS_NSDATA(ARM, 7A); }
                else if ([dictKeyStr isEqualToString:@"armv7f"])    { keyBuffer = HMAC_AS_NSDATA(ARM, 7F); }
                else if ([dictKeyStr isEqualToString:@"armv7s"])    { keyBuffer = HMAC_AS_NSDATA(ARM, 7S); }
                else if ([dictKeyStr isEqualToString:@"armv7k"])    { keyBuffer = HMAC_AS_NSDATA(ARM, 7K); }
                else if ([dictKeyStr isEqualToString:@"armv6m"])    { keyBuffer = HMAC_AS_NSDATA(ARM, 6M); }
                else if ([dictKeyStr isEqualToString:@"armv7m"])    { keyBuffer = HMAC_AS_NSDATA(ARM, 7M); }
                else if ([dictKeyStr isEqualToString:@"armv7em"])   { keyBuffer = HMAC_AS_NSDATA(ARM, 7EM); }

                else if ([dictKeyStr isEqualToString:@"arm64"])     { keyBuffer = HMAC_AS_NSDATA(ARM, 64); }
                else if ([dictKeyStr isEqualToString:@"arm64v8"])   { keyBuffer = HMAC_AS_NSDATA(ARM, 64_V8); }
                else {
                    NSLog(@"Unknown architecture type: %@", dictKeyStr);
                    return -1;
                }
#undef HMAC_AS_NSDATA

                // Find the magic buffer range.
                NSMutableData *hashData = [[recordsToWrite objectForKey:dictKeyStr] mutableCopy];
                NSRange range;

                // Support reversing the operation, useful when forcing integrity
                // check failures.
                NSMutableData *fromData;
                NSMutableData *toData;

                if (isUndo) {
                    fromData = hashData;
                    toData = keyBuffer;
                } else {
                    fromData = keyBuffer;
                    toData = hashData;
                }

                NSLog(@"%@: From %@ to %@", dictKeyStr, fromData, toData);

                range = [contents rangeOfData:fromData options:0
                                                range:NSMakeRange(0, [contents length])];

                if (range.location == NSNotFound) {
                    NSLog(@"%@: File %@ does not contain the magic sequence", dictKeyStr, filePath);
                    // Check to see if it's already been populated.
                    range = [contents rangeOfData:toData options: 0
                                            range:NSMakeRange(0, [contents length])];
                    if (range.location == NSNotFound) {
                        NSLog(@"%@: File %@ does not contain the expected result, either", dictKeyStr, filePath);
                        if (isUndo) {
                            NSLog(@"%@: Ignoring failures when undoing, as not all architectures may be present; continuing.", dictKeyStr);
                            continue;
                        } else {
                            return -1;
                        }
                    }
                    NSLog(@"%@: Already populated", dictKeyStr);
                    continue;
                }

                // Replace the contents of the range with the calculated hash.
                [contents replaceBytesInRange:range withBytes:[toData mutableBytes]];

                // Make sure there's no other matching ranges before writing the file.
                range = [contents rangeOfData:fromData options:0
                                        range:NSMakeRange(0, [contents length])];
                if (range.location != NSNotFound) {
                    NSLog(@"%@: File %@ contains multiple copies of the magic sequence", dictKeyStr, filePath);
                    return -1;
                }
                NSLog(@"Replaced hash for architecture %@", dictKeyStr);
            }

            // Success; write the file back to disk.
            if ([contents writeToFile:filePath atomically:NO] == NO) {
                NSLog(@"File %@ was unable to be written to successfully.", filePath);
                return -1;
            }
        } else {
            // This is the OSX user space HMAC
            // First get the parent directory
            NSString *parent_dir = [filePath stringByDeletingLastPathComponent];
            if (![fileManager fileExistsAtPath:parent_dir isDirectory:&isDir] || !isDir) {
                // Need to create the directory
                if (![fileManager createDirectoryAtPath:parent_dir withIntermediateDirectories:YES attributes:nil error:&error]) {
                    fprintf(stderr,"Error creating the output directory %s\n", [[error localizedDescription] UTF8String]);
                    free (pData);
                    return -1;
                }
            }
            if (![file_data writeToFile:filePath options:0 error:&error]) {
                fprintf(stderr,"Error writing out the HMAC data %s\n", [[error localizedDescription] UTF8String]);
                free (pData);
                return -1;
            }
        }
        free (pData);
    }

    return 0;
}

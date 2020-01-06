/*
 * Copyright (c) 2015,2016,2017,2018 Apple Inc. All rights reserved.
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
#include <corecrypto/ccsha2.h>
#include <corecrypto/cchmac.h>

#if !CC_USE_L4
#include <sys/errno.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#endif

#if !CC_KERNEL && !CC_USE_L4
#include <unistd.h>
#endif

#if !CC_USE_L4
#include <mach-o/loader.h>
#else
#include <mach_loader.h>
#endif

#include "fipspost.h"
#include "fipspost_priv.h"

#include "fipspost_get_hmac.h"

static const struct segment_command* segment_advance(
        const struct segment_command* peek_seg_cmd);

/* --------------------------------------------------------------------------
   Advance the segment to the next segment_command. Because the 'cmdsize'
   member is at the same location for both the segment_command and the
   segment_command_64 structure, it's not necessary to cast the struct.
 -------------------------------------------------------------------------- */
static const struct segment_command* segment_advance(
        const struct segment_command* peek_seg_cmd)
{
    return (const struct segment_command*)(((const unsigned char*)peek_seg_cmd) +
            peek_seg_cmd->cmdsize);
}

/*
 * This function is used by both the iOS and OSX integrity checking code.
 * It handles reading the mach_header of the executable and creating the HMAC
 * of the __TEXT, __TEXT segment
 */
int fipspost_get_hmac(const struct mach_header* pmach_header,
        unsigned char* result_buf, size_t max_offset)
{
    int result = 0; // Set to zero for sucesses until it all works
    const uint8_t *end_region = NULL;
    const struct load_command* load_cmd = NULL;
    const struct segment_command* peek_seg_cmd = NULL;
    uint32_t num_load_commands = 0;
    uint32_t load_idx, sect_idx, num_sect;
    const unsigned char* sect_data;

    const struct ccdigest_info* di = ccsha256_di();
    unsigned char hmac_buffer[CCSHA256_OUTPUT_SIZE];
    unsigned char hmac_key = 0;
    int hash_created = 0;

    /*
     * Establish the maximum extent of the valid memory region to work with, if
     * supplied.
     */
    if (max_offset != 0) {
        end_region =  (const uint8_t *)pmach_header + max_offset;
    }

    /* Protect against the max_offset being large enough to place the end_region at 0. */
    if (max_offset != 0 && end_region == NULL) {
        return CCERR_GENERIC_FAILURE;
    }

    /* There must be at least enough space for the first two headers. */
    if (max_offset > 0 && max_offset <
            (sizeof(struct mach_header_64) + sizeof(struct load_command))) {
        return CCERR_GENERIC_FAILURE;
    }

    if (pmach_header->magic == MH_MAGIC_64) {
        const struct mach_header_64* pmach64_header =
                (const struct mach_header_64*)pmach_header;
        num_load_commands = pmach64_header->ncmds;
        load_cmd = (const struct load_command*)(pmach64_header + 1);
    } else if (pmach_header->magic == MH_MAGIC) {
        num_load_commands = pmach_header->ncmds;
        load_cmd = (const struct load_command*)(pmach_header + 1);
    }

    if (NULL == load_cmd) {
        return CCERR_LIBRARY_ERROR;
    }

    /* Setup the buffer to receive the HMAC. */
    memset(hmac_buffer, 0, sizeof(hmac_buffer));
    cchmac_ctx_decl(di->state_size, di->block_size, ctx);
    cchmac_init(di, ctx, 1, &hmac_key);

    peek_seg_cmd = (const struct segment_command*)load_cmd;

    /*
     * If the supplied ptr is after the available end region (when set), or
     * ever before the supplied pmach_header (which should always be earlier in
     * memory than any of the executable pages), then return failure.
     */
#define CHECK_REGION(ptr) do {                                                      \
        if ((end_region != NULL && (const uint8_t *)((ptr) + 1) > end_region) ||    \
                ((const uint8_t *)(ptr)) < (const uint8_t *)pmach_header) {         \
            return CCERR_GENERIC_FAILURE;                                           \
        }                                                                           \
    } while (0);

    /*
     * Iterate through all of the load commands and identify the ones relating
     * to the TEXT segments that must be hashed into the HMAC.
     */
    for (load_idx = 0; load_idx < num_load_commands; load_idx++,
            peek_seg_cmd = segment_advance(peek_seg_cmd)) {
        CHECK_REGION(peek_seg_cmd);

        /*
         * Both 64-bit and 32-bit segment_command objects contain the 'segname'
         * in the same place.
         */
        if (strncmp("__TEXT", peek_seg_cmd->segname, strlen("__TEXT")) &&
            strncmp("__TEXT_EXEC", peek_seg_cmd->segname, strlen("__TEXT_EXEC"))) {
            continue;
        }

        /* Identify the sub-segment that contains the TEXT data. */
        if (LC_SEGMENT_64 == load_cmd->cmd) {
            /* Almost identical to the the 32-bit section below. */
            const struct segment_command_64* seg_cmd;
            const struct section_64* sect;

            seg_cmd = (const struct segment_command_64*)peek_seg_cmd;
            sect = (const struct section_64*)(seg_cmd + 1);
            num_sect = (unsigned int)seg_cmd->nsects;

            CHECK_REGION(seg_cmd);

            for (sect_idx = 0; sect_idx < num_sect; sect_idx++, sect++) {
                CHECK_REGION(sect);
                /* Check the section name and the segment name. */
                if (strcmp(sect->sectname, "__text") ||
                        (strcmp(sect->segname, "__TEXT") && strcmp(sect->segname, "__TEXT_EXEC"))) {
                    continue;
                }
                /* Only match one section; calculate the hash from it and return. */
                sect_data = (const unsigned char*)pmach_header + sect->offset;

                CHECK_REGION(sect_data + sect->size - 1);
                cchmac_update(di, ctx, (size_t)sect->size, sect_data);
                hash_created = 1;
                break;
            }
            if (hash_created) {
                /* The text text section was found and processed. */
                break;
            }
        } else if (LC_SEGMENT == load_cmd->cmd) {
            /* Almost identical to the the 64-bit section above. */
            const struct segment_command* seg_cmd = NULL;
            const struct section* sect;

            seg_cmd = (const struct segment_command*)load_cmd;
            num_sect = (unsigned int)seg_cmd->nsects;
            sect = (const struct section*)(seg_cmd + 1);

            CHECK_REGION(seg_cmd);

            for (sect_idx = 0; sect_idx < num_sect; sect_idx++, sect++) {
                CHECK_REGION(sect);
                /* Check the section name and the segment name. */
                if (strcmp(sect->sectname, "__text") ||
                        (strcmp(sect->segname, "__TEXT") && strcmp(sect->segname, "__TEXT_EXEC"))) {
                    continue;
                }
                /* Only match one section; calculate the hash from it and return. */
                sect_data = (const unsigned char*)pmach_header + sect->offset;

                CHECK_REGION(sect_data + sect->size - 1);
                cchmac_update(di, ctx, (size_t)sect->size, sect_data);
                hash_created = 1;
                break;
            }
            if (hash_created) {
                /* The text text section was found and processed. */
                break;
            }
        }
    }
#undef CHECK_REGION

    if (hash_created) {
        cchmac_final(di, ctx, hmac_buffer);
        memcpy(result_buf, hmac_buffer, sizeof(hmac_buffer));
    } else {
        failf("could not create the hash");
        result = CCERR_GENERIC_FAILURE;
    }

    return result;
}

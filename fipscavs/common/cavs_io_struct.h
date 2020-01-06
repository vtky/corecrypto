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

/* No #pragma once so multiple structures can be declared in a source file. */

/*
 * The including source file defines the CAVS_OP_HEADER file to indicate which
 * file contains the CAVS_IO_STRUCT to be parsed.
 */
#ifndef CAVS_OP_HEADER
#error CAVS_OP_HEADER must be the string name of the header file defining the structure.
#endif

/*
 * Remove any of the default defines added by cavs_common.h to allow for
 * general inclusion of the header file.
 */
#undef CAVS_IO_STRUCT
#undef CAVS_IO_FIELD
#undef CAVS_IO_BUFFER
#undef CAVS_IO_END_STRUCT

/*
 * Create the serializer.
 *
 * Declare the method and start the buf_len accumulation.
 */
#define CAVS_IO_STRUCT(STRUCT)                                              \
    static uint32_t cavs_io_serialize_##STRUCT(void *req, uint8_t *result); \
    static uint32_t cavs_io_serialize_##STRUCT(void *req, uint8_t *result)  \
    {                                                                       \
        struct STRUCT *request = (struct STRUCT *)req;                      \
        uint32_t buf_len = cavs_io_sizeof_header();

#define CAVS_IO_FIELD(TYPE, MBR)                                            \
        buf_len += sizeof(request->MBR);

#define CAVS_IO_BUFFER(BUF_LEN, BUF)                                        \
        buf_len += sizeof(request->BUF_LEN);                                \
        buf_len += request->BUF_LEN;

#define CAVS_IO_END_STRUCT                                                  \
        if (!result) {                                                      \
            return buf_len;                                                 \
        }                                                                   \
                                                                            \
        uint8_t *buf;                                                       \
        buf = cavs_io_write_header(result, buf_len, request->vector);

#include CAVS_OP_HEADER

#undef CAVS_IO_STRUCT
#undef CAVS_IO_FIELD
#undef CAVS_IO_BUFFER
#undef CAVS_IO_END_STRUCT

/*
 * Create the cavs_io_write_* call for each member variable, and close the
 * function.
 */
#define CAVS_IO_STRUCT(STRUCT)
#define CAVS_IO_FIELD(TYPE, MBR)                                            \
        buf = cavs_io_write_##TYPE(buf, request->MBR);
#define CAVS_IO_BUFFER(BUF_LEN, BUF)                                        \
        buf = cavs_io_write_buffer(buf, request->BUF_LEN, request->BUF);
#define CAVS_IO_END_STRUCT                                                  \
        assert(result + buf_len == buf);                                    \
                                                                            \
        return buf_len;                                                     \
    }

#include CAVS_OP_HEADER

#undef CAVS_IO_STRUCT
#undef CAVS_IO_FIELD
#undef CAVS_IO_BUFFER
#undef CAVS_IO_END_STRUCT

/*
 * Now create the deserialize method.
 *
 * Declare the method, read the various members, and close the method.
 */
#define CAVS_IO_STRUCT(STRUCT)                                              \
    static void cavs_io_deserialize_##STRUCT(void *req, uint8_t *input);    \
    static void cavs_io_deserialize_##STRUCT(void *req, uint8_t *input)     \
    {                                                                       \
        struct STRUCT *request = (struct STRUCT *)req;                      \
        uint8_t *buf;                                                       \
        uint32_t buf_len;                                                   \
        cavs_vector vector;                                                 \
                                                                            \
        buf = cavs_io_read_header(input, &buf_len, &vector);

#define CAVS_IO_FIELD(TYPE, MBR)                                            \
        buf = cavs_io_read_##TYPE(buf, &request->MBR);

#define CAVS_IO_BUFFER(BUF_LEN, BUF)                                        \
        buf = cavs_io_read_buffer(buf, &request->BUF_LEN, &request->BUF);

#define CAVS_IO_END_STRUCT                                                  \
        assert(input + buf_len == buf);                                     \
    }

#include CAVS_OP_HEADER

#undef CAVS_IO_STRUCT
#undef CAVS_IO_FIELD
#undef CAVS_IO_BUFFER
#undef CAVS_IO_END_STRUCT

#if CAVS_IO_ENABLE_CPRINT
#include <stdio.h>
/*
 * Create the print-to-C-structure.
 *
 * This is used to capture vectors parsed off of disk in a C compatible format
 * to be used for generating unittest inputs or other isolated tests.
 *
 * Worth considering gating this on x86 and adding a FILE* pointer for logging
 * to a file rather than stdout.
 */
#define CAVS_IO_STRUCT(STRUCT)                                              \
    static void cavs_io_cprint_##STRUCT(FILE *f, void *req);                \
    static void cavs_io_cprint_##STRUCT(FILE *f, void *req)                 \
    {                                                                       \
        struct STRUCT *request = (struct STRUCT *)req;                      \
        fprintf(f, "struct " #STRUCT " v = {");

#define CAVS_IO_FIELD(TYPE, MBR)                                            \
        fprintf(f, "." #MBR " = " CAVS_IO_CPRINT_FMT_##TYPE ", ",           \
                CAVS_IO_CPRINT_##TYPE(MBR));

#define CAVS_IO_BUFFER(BUF_LEN, BUF)                                        \
        fprintf(f, "." #BUF_LEN " = %d, ", request->BUF_LEN);               \
        fprintf(f, "." #BUF " = (uint8_t *)\"");                                       \
        cavs_io_cprint_buffer(f, request->BUF, request->BUF_LEN);           \
        fprintf(f, "\", ");
#define CAVS_IO_END_STRUCT                                                  \
        fprintf(f, "};");                                                   \
    }
#include CAVS_OP_HEADER

/* Clean up back to defaults. */
#undef CAVS_IO_STRUCT
#undef CAVS_IO_FIELD
#undef CAVS_IO_BUFFER
#undef CAVS_IO_END_STRUCT
#endif

#define CAVS_IO_STRUCT(STRUCT)
#define CAVS_IO_FIELD(TYPE, MBR)
#define CAVS_IO_BUFFER(BUF_LEN, BUF)
#define CAVS_IO_END_STRUCT


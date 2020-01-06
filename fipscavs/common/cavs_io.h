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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/* General purpose headers used by drivers. */
uint32_t cavs_io_sizeof_header(void);
uint8_t *cavs_io_read_header(uint8_t *buf, uint32_t *l, cavs_vector *vector);

uint32_t cavs_io_serialize(cavs_vector vector, void *request, uint8_t *buf);
cavs_vector cavs_io_deserialize(void *request, uint8_t *buf);

/* Routines used in serialization/deserialization objects. */
#define cavs_io_declare_primitive_define(prim_type)                         \
    uint8_t *cavs_io_write_##prim_type(uint8_t *buf, prim_type pt);         \
    uint8_t *cavs_io_read_##prim_type(uint8_t *buf, prim_type *pt);
cavs_io_declare_primitive_define(uint32_t);
cavs_io_declare_primitive_define(cavs_vector);
cavs_io_declare_primitive_define(cavs_digest);
cavs_io_declare_primitive_define(cavs_target);
cavs_io_declare_primitive_define(cavs_cipher_curve);
cavs_io_declare_primitive_define(cavs_cipher_enc);
cavs_io_declare_primitive_define(cavs_cipher_mode);
cavs_io_declare_primitive_define(cavs_sha_is);
cavs_io_declare_primitive_define(cavs_aes_is);

uint8_t *cavs_io_write_buffer(uint8_t *buf, uint32_t l, uint8_t *b);
uint8_t *cavs_io_write_header(uint8_t *buf, uint32_t l, cavs_vector vector);
uint8_t *cavs_io_read_buffer(uint8_t *buf, uint32_t *l, uint8_t **b);

typedef uint32_t (*cavs_io_serializer)(void *request, uint8_t *result);
typedef void (*cavs_io_deserializer)(void *request, uint8_t *input);

#if !CAVS_IO_ENABLE_CPRINT
void cavs_io_register(cavs_vector vector, cavs_io_serializer serializer,
        cavs_io_deserializer deserializer);

/* Utility macro used in to register a type at process startup. */
#define CAVS_IO_REGISTER_STRUCT(VEC, STRUCT)                                \
    static void cavs_io_register_##VEC() __attribute__ ((constructor (101)));\
    static void cavs_io_register_##VEC()                                    \
    {                                                                       \
        cavs_io_register(VEC, cavs_io_serialize_##STRUCT,                   \
                cavs_io_deserialize_##STRUCT);                              \
    }
#else
#include <stdio.h>

typedef void (*cavs_io_cprint)(FILE *f, void *request);
void cavs_io_register(cavs_vector vector, cavs_io_serializer serializer,
        cavs_io_deserializer deserializer, cavs_io_cprint cprint);
void cavs_io_log_dispatch(cavs_vector vector, void *request, size_t exp_len,
        size_t result_len, uint8_t *result);
void cavs_io_cprintizer(FILE *f, cavs_vector vector, void *request);

/* Utility macro used in to register a type at process startup. */
#define CAVS_IO_REGISTER_STRUCT(VEC, STRUCT)                                \
    static void cavs_io_register_##VEC() __attribute__ ((constructor (101)));\
    static void cavs_io_register_##VEC()                                    \
    {                                                                       \
        cavs_io_register(VEC, cavs_io_serialize_##STRUCT,                   \
                cavs_io_deserialize_##STRUCT,                               \
                cavs_io_cprint_##STRUCT);                                   \
    }

void cavs_io_cprint_buffer(FILE *f, uint8_t *buf, size_t buf_len);
#define CAVS_IO_CPRINT_FMT_cavs_target "%s"
#define CAVS_IO_CPRINT_cavs_target(MBR) cavs_target_to_string(request->MBR)
#define CAVS_IO_CPRINT_FMT_cavs_vector "%s"
#define CAVS_IO_CPRINT_cavs_vector(MBR) cavs_vector_to_string(request->MBR)
#define CAVS_IO_CPRINT_FMT_cavs_digest "%s"
#define CAVS_IO_CPRINT_cavs_digest(MBR) cavs_digest_to_string(request->MBR)
#define CAVS_IO_CPRINT_FMT_cavs_sha_is "%s"
#define CAVS_IO_CPRINT_cavs_sha_is(MBR) cavs_sha_is_to_string(request->MBR)
#define CAVS_IO_CPRINT_FMT_cavs_aes_is "%s"
#define CAVS_IO_CPRINT_cavs_aes_is(MBR) cavs_aes_is_to_string(request->MBR)
#define CAVS_IO_CPRINT_FMT_cavs_cipher_curve "%s"
#define CAVS_IO_CPRINT_cavs_cipher_curve(MBR) cavs_cipher_curve_to_string(request->MBR)
#define CAVS_IO_CPRINT_FMT_cavs_cipher_enc "%s"
#define CAVS_IO_CPRINT_cavs_cipher_enc(MBR) cavs_cipher_enc_to_string(request->MBR)
#define CAVS_IO_CPRINT_FMT_cavs_cipher_mode "%s"
#define CAVS_IO_CPRINT_cavs_cipher_mode(MBR) cavs_cipher_mode_to_string(request->MBR)
#define CAVS_IO_CPRINT_FMT_uint32_t "%d"
#define CAVS_IO_CPRINT_uint32_t(MBR) request->MBR
#endif // CAVS_IO_ENABLE_CPRINT

#ifdef __cplusplus
}
#endif // __cplusplus


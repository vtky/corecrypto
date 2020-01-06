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

#include <stdint.h>

#include "cavs_common.h"

#include "cavs_io.h"

struct cavs_io_serializer
{
    cavs_io_serializer serializer;
    cavs_io_deserializer deserializer;
#if CAVS_IO_ENABLE_CPRINT
    cavs_io_cprint cprint;
#endif
};

/*
 * Populated by constructors or initializers in the various compiled-in vector
 * modules.
 */
static struct cavs_io_serializer cavs_io_serializers[CAVS_VECTOR_LAST];

/*
 * Utility methods and macros to serialize and deserialize IOFIPS
 * structures for dispatch to L4 execution spaces.
 */
#define cavs_io_implement_primitive_define(prim_type)                       \
    uint8_t *cavs_io_write_##prim_type(uint8_t *buf, prim_type pt)          \
    {                                                                       \
        memcpy(buf, &pt, sizeof(pt));                                       \
        return buf + sizeof(pt);                                            \
    }                                                                       \
    uint8_t *cavs_io_read_##prim_type(uint8_t *buf, prim_type *pt)          \
    {                                                                       \
        memcpy(pt, buf, sizeof(*pt));                                       \
        return buf + sizeof(*pt);                                           \
    }

/* Primitives, used for building the buffer results. */
cavs_io_implement_primitive_define(cavs_vector);
cavs_io_implement_primitive_define(cavs_digest);
cavs_io_implement_primitive_define(cavs_target);
cavs_io_implement_primitive_define(cavs_cipher_curve);
cavs_io_implement_primitive_define(cavs_cipher_enc);
cavs_io_implement_primitive_define(cavs_cipher_mode);
cavs_io_implement_primitive_define(cavs_sha_is);
cavs_io_implement_primitive_define(cavs_aes_is);
cavs_io_implement_primitive_define(uint32_t);

uint8_t *cavs_io_write_buffer(uint8_t *buf, uint32_t l, uint8_t *b)
{
    if (l > 0 && b == NULL) {
        errorf("invalid write_buffer call");
        return buf;
    } else {
        buf = cavs_io_write_uint32_t(buf, l);
        memcpy(buf, b, l);
        return buf + l;
    }
}

uint8_t *cavs_io_read_buffer(uint8_t *buf, uint32_t *l, uint8_t **b)
{
    buf = cavs_io_read_uint32_t(buf, l);
    if (*l == 0) {
        *b = NULL;
    } else {
        *b = buf;
    }
    return buf + *l;
}

uint8_t *cavs_io_write_header(uint8_t *buf, uint32_t l, cavs_vector vector)
{
    buf = cavs_io_write_uint32_t(buf, l);
    return cavs_io_write_cavs_vector(buf, vector);
}

uint8_t *cavs_io_read_header(uint8_t *buf, uint32_t *l, cavs_vector *vector)
{
    buf = cavs_io_read_uint32_t(buf, l);
    return cavs_io_read_cavs_vector(buf, vector);
}

uint32_t cavs_io_sizeof_header()
{
    return sizeof(uint32_t) + sizeof(cavs_vector);
}

/*
 * cavs_serialize always returns the required buffer length for
 * the supplied object.  Call with a NULL buf to safely acquire
 * that value.
 *
 * Serializes vector 'request' into 'buf'.
 */
uint32_t cavs_io_serialize(cavs_vector vector, void *request, uint8_t *buf)
{
    struct cavs_io_serializer *io = &cavs_io_serializers[vector];
    if (io->serializer) {
        return (*io->serializer)(request, buf);
    }

    errorf("unsupported vector: %s/%d", cavs_vector_to_string(vector), vector);

    return 0;
}

/*
 * Returns the type of the resulting object populated in result.  The resulting
 * object maintains pointers to the supplied buf for any variable-length
 * buffers that may be contained within it, and it is the responsibility of the
 * caller to control those lifetimes.
 *
 * The supplied 'request' object must be at least sizeof(IOFIPS*) bytes large.
 *
 * Deserializes 'buf' into 'request'.
 */
cavs_vector cavs_io_deserialize(void *request, uint8_t *buf)
{
    uint32_t buf_len;
    cavs_vector vector;

    cavs_io_read_header(buf, &buf_len, &vector);

    if (!request) {
        return vector;
    }

    struct cavs_io_serializer *io = &cavs_io_serializers[vector];
    if (io->deserializer) {
        (*io->deserializer)(request, buf);
        return vector;
    }
    errorf("unsupported vector: %s/%d", cavs_vector_to_string(vector), vector);
    return CAVS_VECTOR_UNKNOWN;
}

#if CAVS_IO_ENABLE_CPRINT
void cavs_io_cprintizer(FILE *f, cavs_vector vector, void *request)
{
    struct cavs_io_serializer *io = &cavs_io_serializers[vector];
    if (io->serializer) {
        return (*io->cprint)(f, request);
    }

    errorf("unsupported vector: %s/%d", cavs_vector_to_string(vector), vector);
}
#endif

void cavs_io_register(cavs_vector vector, cavs_io_serializer serializer,
        cavs_io_deserializer deserializer
#if CAVS_IO_ENABLE_CPRINT
        , cavs_io_cprint cprint
#endif
        )
{
    debug("Registering: %s", cavs_vector_to_string(vector));
    assert(cavs_io_serializers[vector].serializer == NULL);
    cavs_io_serializers[vector].serializer = serializer;
    assert(cavs_io_serializers[vector].deserializer == NULL);
    cavs_io_serializers[vector].deserializer = deserializer;
#if CAVS_IO_ENABLE_CPRINT
    assert(cavs_io_serializers[vector].cprint == NULL);
    cavs_io_serializers[vector].cprint = cprint;
#endif
}

#if CAVS_IO_ENABLE_CPRINT
/* Utility function used to print buffers as C strings. */
void cavs_io_cprint_buffer(FILE *f, uint8_t *buf, size_t buf_len)
{
    for (size_t i = 0; i < buf_len; i++) { fprintf(f, "\\x%02X", buf[i]); }
}

void cavs_io_log_dispatch(cavs_vector vector, void *request, size_t exp_len, size_t result_len, uint8_t *result)
{
    FILE *f = fopen("/tmp/vector_log.c", "a");
    fprintf(f, "\t/* %s */\n", cavs_vector_to_string(vector));
    fprintf(f, "\t{\n\t\t");
    cavs_io_cprintizer(f, vector, request);
    fprintf(f, "\n\t\tsize_t len = %zu;\n", exp_len);
    fprintf(f, "\t\tuint8_t *wksp = NULL;\n");
    
    fprintf(f, "\t\tis(CAVS_STATUS_OK, cavs_dispatch(CAVS_TARGET_USER, v.vector, &v, &wksp, &len), \"dispatch\");\n");
    
    fprintf(f, "\t\tconst char *exp_result = \"");
    cavs_io_cprint_buffer(f, result, result_len);
    fprintf(f, "\";\n");
    fprintf(f, "\t\tis(len, (size_t)%zu, \"expected length\");\n", result_len);
    fprintf(f, "\t\tok_memcmp(exp_result, wksp, %zu, \"expected result\");\n", result_len);
    fprintf(f, "\t}\n");
    fclose(f);
}

#endif

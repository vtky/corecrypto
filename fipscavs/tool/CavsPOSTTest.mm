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

extern "C" {
#include "cavs_common.h"
#include "cavs_dispatch.h"

#include "cavs_op_post.h"

#include "fipspost_get_hmac.h"
#include "fipspost_trace.h"
#include "fipspost_trace_priv.h"
}

#import "CavsPOSTTest.h"

@interface CavsPOSTTest (PrivateMethods)
- (BOOL)runPOSTTest:(TestFileData *)testData withCounter:(NSInteger)counter;
@end

/*
 * This parsing code might find a home elsewhere, but it lives here now.
 */
struct fipscavs_trace_test_parse_ctx {
    struct fipspost_trace_hdr *hdr;
    const char *hooks[FIPSPOST_TRACE_MAX_HOOKS];
    fipspost_trace_id_t trace[16*1024];
    size_t trace_len;
};

/*
 * Parse the supplied buffer into the fipscavs_trace_test_parse_ctx.
 */
static int fipscavs_trace_test_parse(struct fipscavs_trace_test_parse_ctx *ctx, uint8_t *buf, size_t len)
{
    /* The header is the fist value in the buffer. */
    ctx->hdr = (struct fipspost_trace_hdr *)buf;
    fipspost_trace_id_t nstr;
    fipspost_trace_id_t slen;
    fipspost_trace_id_t *wlk = (fipspost_trace_id_t *)(ctx->hdr + 1);

    /* Walk through the samples until the string table starts. */
    while (*wlk != FIPSPOST_TRACE_TABLE_ID) {
        wlk++;
        if (wlk == (fipspost_trace_id_t *)(buf + len)) {
            return -1;
        }
    }

    /* Copy into the ctx->trace buffer for later analysis. */
    ctx->trace_len = wlk - (fipspost_trace_id_t *)(ctx->hdr + 1);
    memcpy(ctx->trace, ctx->hdr + 1, ctx->trace_len);
    wlk++;

    /*
     * Populate the ctx->hooks table with pointers into the
     * already-NULL-terminated strings in the buffer.
     */
    nstr = *wlk++;
    for (int i = 0; i < nstr; i++) {
        slen = *wlk;
        wlk++;
        ctx->hooks[i] = (const char *)wlk;
        wlk += slen;
    }

    /* Verify that there wasn't any data lingering at the end. */
    if (wlk != (fipspost_trace_id_t *)(buf + len)) {
        return -1;
    }

    return 0;
}

@implementation CavsPOSTTest

+ (void)setupTest
{
    return;
}

+ (void)cleanUpTest
{
    return;
}

- (id)initWithFileParser:(TestFileParser *)fileParser
    withTestDictionary:(NSDictionary *)testsToRun
{
    return [super initWithFileParser:fileParser withTestDictionary:testsToRun];
}

- (BOOL)runTest:(TestFileData *)testData withCounter:(NSInteger)counter
{
    int ret;

    struct cavs_op_post request;
    request.vector = CAVS_VECTOR_POST;
    request.fips_mode = (uint32_t)[testData.nValue intValue];

    size_t len = 0;
    uint8_t *wksp = NULL;
    ret = cavs_dispatch(testData.testTarget, request.vector, &request, &wksp, &len);
    if (ret != CAVS_STATUS_OK) {
        errorf("failed cavs_dispatch");
        return NO;
    }

    /* Parse the results; allocated because of the large structure. */
    struct fipscavs_trace_test_parse_ctx *ctx =
        (struct fipscavs_trace_test_parse_ctx *)malloc(sizeof(struct fipscavs_trace_test_parse_ctx));
    if (ctx == NULL) {
        errorf("failed to allocate");
        return NO;
    }
    
    ret = fipscavs_trace_test_parse(ctx, wksp, len);
    if (ret != 0) {
        errorf("failed to parse");
        free(ctx);
        return NO;
    }

    /*
     * Print the output as JSON, because why not.
     *
     * Note: The resulting file will have a "comment" at the top of it - the "# FIPSPOST" line.
     * This will need to be trimmed off before it can be parsed by any normal JSON reader.
     */
    [self outputString:@"{"];
    [self outputFormat:@"\t\"magic\": \"0x%04X\",", ctx->hdr->magic];
    [self outputFormat:@"\t\"version\": %d,", ctx->hdr->version];
    [self outputFormat:@"\t\"fips_mode\": %d,", ctx->hdr->fips_mode];
    [self outputFormat:@"\t\"integ_hmac\": \"%@\",", BufToHexString(ctx->hdr->integ_hmac, FIPSPOST_PRECALC_HMAC_SIZE)];
    [self outputFormat:@"\t\"system_flags\": \"0x%08llX\",", ctx->hdr->system_flags];

    [self outputString:@"\t\"events\": ["];
    for (int i = 0; i < ctx->trace_len; i++) {
        [self outputFormat:@"\t\t\"%s\",", ctx->hooks[ctx->trace[i]]];
    }

    [self outputString:@"\t]"];
    [self outputString:@"}"];

    free(ctx);
    return YES;
}

@end

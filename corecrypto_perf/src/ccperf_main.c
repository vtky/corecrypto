/*
 * Copyright (c) 2011,2012,2014,2015,2016,2017,2018 Apple Inc. All rights reserved.
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

#include <corecrypto/ccperf.h>

#if defined(_WIN32)
  static int optind = 1;
#else
  #include <unistd.h>
#endif

#include <corecrypto/cc_macros.h>
#include "cc_debug.h"
#include <corecrypto/ccec_priv.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccrng_test.h>

typedef enum{
    PERF_DISPLAY_SHORT=0,             /* Default */
    PERF_DISPLAY_DETAIL,              /* Detailled */
    PERF_DISPLAY_KEYVAL,              /* Parser friendly */
    PERF_DISPLAY_MAX=PERF_DISPLAY_KEYVAL
} ccperf_display_mode_e;

static struct ccrng_test_state test_rng;
struct ccrng_state *rng=(struct ccrng_state *)&test_rng;

static int tests_rng(void) {
    int status=-1; // Allocation error;
    uint8_t random_seed[16];
    size_t seed_size;

    // Generate random seed
    seed_size=sizeof(random_seed); // Default size of the seed
    cc_require((status=ccrng_generate(ccrng(NULL), seed_size, random_seed))==0, errOut);
    cc_print("random seed value:",seed_size,random_seed);

    // Init the rng from the seed
    cc_require((status=ccrng_test_init(&test_rng, seed_size,random_seed,NULL))==0, errOut);
    return status;
errOut:
    printf("Error initializing test rng: %d\n",status);
    return -1;
}
static int tests_rng_done(void) {
    ccrng_test_done(&test_rng);
    return 0;
}

static double perf_noop(size_t loops)
{
    perf_start();
    while(loops--);
    return perf_seconds();
}

static void perf_test_family(struct ccperf_family *f, ccperf_display_mode_e display_mode)
{
    double noop_time = perf_noop(f->loops);

    if(f->ntests==0) return;

    printf("\nPerf test for family: %s\n\n", f->name);

    for(unsigned int j=0; j<f->nsizes; j++) {

        printf("[BEGIN] Perf test for family: %s - Size = %zu\n",
               f->name, f->sizes[j]);

        for (unsigned int i = 0; i < f->ntests; i++) {
            double duration = histogram_sieve(f, f->sizes[j], f->tests[i]);

            if (duration==0) {
                continue; // Test skipped
            }
            if (duration >= noop_time) {
                duration -= noop_time;
            }

            struct units ud = dur2units(duration / f->loops);
            struct units udb = dur2units(duration / (f->loops * f->sizes[j]));
            struct units uop = dur2units(f->loops / duration);
            struct units ubs = dur2units((f->loops * f->sizes[j])/duration);

            const char *su_name;
            switch (f->size_kind) {
                case ccperf_size_bytes: su_name = "byte"; break;
                case ccperf_size_bits: su_name = "bit"; break;
                case ccperf_size_iterations: su_name = "itn"; break;
                case ccperf_size_units: su_name = "unit"; break;
            }

            // Add info at the end of line.
            char extra_info_endofline[60]={0};
            if (f->run_time>RUN_TIMEOUT) {
                snprintf(extra_info_endofline, sizeof(extra_info_endofline),
                         "- %zu runs in %.3gs",f->nruns,f->run_time);
            }

            // Display the numbers
            if (display_mode==PERF_DISPLAY_DETAIL) {
                // The original, all variations
                printf("%-47s %8.3g %ss/op | %8.3g %sops/s | %8.3g %ss/%s | %8.3g %s%s/s | [%zu] %s\n",
                       f->tests[i]->name,
                       (duration * ud.scale) / f->loops, ud.name,
                       f->loops/duration * uop.scale, uop.name,
                       (duration * udb.scale) / (f->loops * f->sizes[j]), udb.name, su_name,
                       (f->loops * f->sizes[j] * ubs.scale) / duration, ubs.name, su_name,
                       f->sizes[j],extra_info_endofline);
            } else if (display_mode==PERF_DISPLAY_KEYVAL) {
                // For perf tracking
                printf("[RESULT_KEY] %s:%ss\n",f->tests[i]->name, ud.name);
                printf("[RESULT_VALUE] %.4f\n",(duration * ud.scale) / f->loops);
            }
            else { // Default
                printf("%-47s %8.3g %ss/op | %8.3g %s%s/s | [%zu] %s\n",
                   f->tests[i]->name,
                   (duration * ud.scale) / f->loops, ud.name,
                   (f->loops * f->sizes[j] * ubs.scale) / duration, ubs.name, su_name,
                   f->sizes[j],extra_info_endofline);
            }
        }

        printf("[PASS] Perf test for family: %s - Size = %zu\n",
               f->name, f->sizes[j]);
    }
}

static void test_list(struct ccperf_family *f)
{
    size_t i;
    printf("\nFamily %s [", f->name);
    for(i=0; i<f->nsizes; i++)
        printf(" %zu,", f->sizes[i]);
    printf(" ]\n");
    for(i=0; i<f->ntests; i++)
        printf(" %s\n", f->tests[i]->name);
}

struct ccperf_family *(*ccperf_families[])(int argc, char *argv[]) = {
    ccperf_family_ccrng,
    ccperf_family_ccdrbg,
    ccperf_family_ccecb_init,
    ccperf_family_ccecb_update,
    ccperf_family_ccecb_one_shot,
    ccperf_family_cccbc_init,
    ccperf_family_cccbc_update,
    ccperf_family_cccbc_one_shot,
    ccperf_family_cccfb8_init,
    ccperf_family_cccfb8_update,
    ccperf_family_cccfb8_one_shot,
    ccperf_family_cccfb_init,
    ccperf_family_cccfb_update,
    ccperf_family_cccfb_one_shot,
    ccperf_family_ccctr_init,
    ccperf_family_ccctr_update,
    ccperf_family_ccctr_one_shot,
    ccperf_family_ccgcm_init,
    ccperf_family_ccgcm_set_iv,
    ccperf_family_ccgcm_gmac,
    ccperf_family_ccgcm_update,
    ccperf_family_ccgcm_finalize,
    ccperf_family_ccgcm_one_shot,
    ccperf_family_ccccm_init,
    ccperf_family_ccccm_set_iv,
    ccperf_family_ccccm_cbcmac,
    ccperf_family_ccccm_update,
    ccperf_family_ccccm_finalize,
    ccperf_family_ccccm_one_shot,
    ccperf_family_ccofb_init,
    ccperf_family_ccofb_update,
    ccperf_family_ccofb_one_shot,
    ccperf_family_ccomac_init,
    ccperf_family_ccomac_update,
    ccperf_family_ccomac_one_shot,
    ccperf_family_ccxts_init,
    ccperf_family_ccxts_set_tweak,
    ccperf_family_ccxts_update,
    ccperf_family_ccxts_one_shot,
    ccperf_family_ccchacha_init,
    ccperf_family_ccchacha_update,
    ccperf_family_ccchacha_one_shot,
    ccperf_family_ccpoly_init,
    ccperf_family_ccpoly_update,
    ccperf_family_ccpoly_one_shot,
    ccperf_family_ccchachapoly_encrypt_and_sign,
    ccperf_family_ccchachapoly_decrypt_and_verify,
    ccperf_family_ccsiv_init,
    ccperf_family_ccsiv_aad_or_nonce,
    ccperf_family_ccsiv_one_shot,
    ccperf_family_ccdigest,
    ccperf_family_cchmac,
    ccperf_family_cccmac,
    ccperf_family_ccn,
    ccperf_family_cczp,
    ccperf_family_ccec,
    ccperf_family_ccec25519,
    ccperf_family_ccrsa,
    ccperf_family_cczp_inv,
    ccperf_family_ccpbkdf2,
    ccperf_family_ccansikdf,
    ccperf_family_ccsrp,
    ccperf_family_ccdh_generate_key,
    ccperf_family_ccdh_compute_shared_secret,
};

#define PIFLAG(L) printf(" " #L "=%d", L)

static void perf_banner(const char *testName, int argc, char **argv)
{
	int i;
    char *date = __DATE__;
    char *time = __TIME__;
	printf("Starting %s; Flags: ", testName);
    PIFLAG(CC_KERNEL);
    PIFLAG(CCN_ADD_ASM);
    PIFLAG(CCN_SUB_ASM);
    PIFLAG(CCN_MUL_ASM);
    PIFLAG(CCN_ADDMUL1_ASM);
    PIFLAG(CCN_MUL1_ASM);
    PIFLAG(CCN_CMP_ASM);
    PIFLAG(CCN_ADD1_ASM);
    PIFLAG(CCN_SUB1_ASM);
    PIFLAG(CCN_N_ASM);
    PIFLAG(CCN_SET_ASM);
    PIFLAG(CCN_USE_BUILTIN_CLZ);

    PIFLAG(CCEC_USE_TWIN_MULT);
    PIFLAG(CCAES_ARM_ASM);
    PIFLAG(CCAES_INTEL_ASM);
    PIFLAG(CCAES_MUX);
#if defined(CCEC_DOUBLE_CT)
    PIFLAG(CCEC_DOUBLE_CT);
#endif
#if defined(CCEC_FULL_ADD_CT)
    PIFLAG(CCEC_FULL_ADD_CT);
#endif
#if defined(CCN_HIGEST_BIT_CT)
    PIFLAG(CCN_HIGEST_BIT_CT);
#endif
    printf(";\n");
    printf("CCN_UNIT_BITS=%zu bits\n", CCN_UNIT_BITS);
	printf("Arguments: '");
	for(i = 1; i < argc; i++) {
		printf("%s ", argv[i]);
	}
	printf("'\n");
#if defined(__i386__)
    printf("Architecture: intel 386");
#elif defined(__x86_64__)
    printf("Architecture: intel x86_64");
#elif defined(__arm64__)
    printf("Architecture: arm64");
#elif defined(__arm__)
    printf("Architecture: arm");
#endif

#if defined(__ARM_NEON__)
    printf(" with __ARM_NEON__");
#endif
    printf("\n");
    printf("Date: %s - %s\n",date,time);
}

#if !defined(_WIN32)
static void print_family_list(void)
{
    for (size_t i=0; i<numof(ccperf_families); i++) {
        struct ccperf_family *f=ccperf_families[i](0,NULL);
        printf("%s\n", f->name);
    }
}

static CC_NORETURN void usage(char **argv)
{
	printf("usage: %s [options] [test_name...]\n", argv[0]);
	printf("   Options:\n");
	printf("   -d display: override default display type (0:short ; 1:full ; 2:key/value)\n");
    printf("   -f family : test only the given family\n");
	printf("   -n loops  : override default loops number\n");
	printf("   -s size   : override default sizes\n");
    printf("   -l        : don\'t run the test, just print a list\n");
	printf("   -h        : help\n");
    print_family_list();
    exit(1);
}
#endif

/* Return -1 if f->name is in family_names otherwise returns 0. */
static int family_in(struct ccperf_family *f, size_t family_n,
              char **family_names) {
    while (family_n--) {
        if (strcmp(family_names[family_n], f->name) == 0)
            return -1;
    }
    return 0;
}

int ccperf_main(int argc CC_UNUSED, char **argv CC_UNUSED)
{
    size_t i;
    int norun=0;
    size_t family_n = 0;
    char **family_names = NULL;
    ccperf_display_mode_e display_mode=PERF_DISPLAY_SHORT;

    if(tests_rng()<0) {
        perror("Could not initialize RNG\n");
        exit(-1);
    }

    perf_banner("perf", argc, argv);

#if CORECRYPTO_DEBUG
	printf("***WARNING: DEBUG on, timing measurements are not reliable!\n");
#endif
#if TARGET_IPHONE_SIMULATOR
    printf("***WARNING: iOS Simulator\n");
#endif

	int loops = -1;
	size_t sizes = 0;
#if defined(_WIN32) //command-line excluded form windows
    printf("command-line options are not supported under Windows");
#else
    int r;

    do {
        r=getopt(argc, argv, "hlf:n:s:d:");
        bool err=false;
        switch(r){
        case 'l':
            norun=1;
            break;
        case 'f':
            family_names = realloc(family_names, sizeof(*family_names) * family_n + 1);
            family_names[family_n++] = optarg;
            break;
        case 'n':
            loops=atoi(optarg);
            printf("Overriding loops = %d\n", loops);
            break;
        case 's':
            printf("Overriding sizes = %s\n", optarg);
            sizes=(size_t)atol(optarg);
            break;
        case 'd':
            printf("Overriding display mode = %s\n", optarg);
            display_mode=(ccperf_display_mode_e)atol(optarg);
            if (display_mode>PERF_DISPLAY_MAX) err=true;
            break;
        case -1:
            break;
        case '?':
        default:
            printf("Unrecognised option %c\n", optopt);
            usage(argv);
        }
        if (err) {
            printf("Invalid argument\n");
            usage(argv);
        }
    } while(r!=-1);
#endif
    perf_start();
    for(i=0; i<numof(ccperf_families); i++) {
        struct ccperf_family *f;

        f=ccperf_families[i](argc-optind, argv+optind);

        /* override loops */
        if(loops>0)
            f->loops=(size_t)loops;

        if (sizes) {
            f->nsizes=1;
            f->sizes=realloc(f->sizes, f->nsizes*sizeof(size_t));
            f->sizes[0] = sizes;
        }

        /* Skip this family if names are specified and this one is not listed */
        if (family_n == 0 || family_in(f, family_n, family_names))
        {
            if(norun)
                test_list(f);
            else
                perf_test_family(f,display_mode);
        }
        free(f->sizes);
        free(f->tests);
    }
    printf("\n\nTotal execution time %f seconds\n", perf_seconds());
    tests_rng_done();
    free(family_names);
    return 0;
}

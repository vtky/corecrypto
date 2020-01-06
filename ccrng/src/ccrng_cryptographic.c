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

#include <corecrypto/ccdrbg.h>
#include <corecrypto/ccaes.h>
#include "cc_debug.h"
#include <corecrypto/cc_priv.h>
#include <corecrypto/ccrng_priv.h>
#include <corecrypto/cc_absolute_time.h>
#include <corecrypto/cc_macros.h>
#include "ccrng_cryptographic_priv.h"
#include <corecrypto/ccrng.h>
#include <corecrypto/ccrng_cryptographic.h>

#if CC_KERNEL
#include <kern/clock.h>
static uint64_t cc_uptime_seconds(void) {
    clock_sec_t sec;
    clock_usec_t discard;
    clock_get_calendar_microtime(&sec,&discard);
    discard=0;
    return sec;
}
#else
static uint64_t cc_uptime_seconds(void) {
    return (uint64_t)(cc_absolute_time_sf()*cc_absolute_time());
}
#endif

/*
 This file maintains the state of a static and thread safe cryto random number generator.
 The random number generator is reseeded upon fork, so that child and parent random number genetators have different states.
 This file exports the single function ccrng().
*/

// Security/Performance configuration
#define RNG_MAX_SEED_RETRY 100   // To prevent looping forever.
#define ENTROPY_SOURCE_BLOCK_SIZE 32   // FIPS 140-2 states that this value
                                       // must be equal to the block size of the underlying
                                       // source of entropy or the random number generator.
                                       // It is not modifiable.
#define RNG_ENTROPY_SIZE 2*ENTROPY_SOURCE_BLOCK_SIZE  // The bigger the better for security.
#define RNG_RESEED_INTERVAL 5    // Number of calls to "generate" before reseeding
                                 // The smaller the better for security.
                                 // must be <= CCDRBG_RESEED_INTERVAL

#define RNG_RESEED_PERIOD_SECONDS (60*60) // (60*60sec == 1hour)
                                    // Time elapsed in second beyond which a reseed is forced.
                                    // ie. Maximum time a compromised state leads to predictable output

#define RNG_MAGIC_INIT (0xD1D)

#if CORECRYPTO_DEBUG && 0   // Flip this bit to enable debug
#define RNG_CRYPTO_DEBUG 1
#define rng_debug_cc_printf(x...) cc_printf(x)
#else
#define RNG_CRYPTO_DEBUG 0
#define rng_debug_cc_printf(x...)
#endif

//==============================================================================
//
//          Internal state
//
//==============================================================================

#if CC_USE_ASM
// DRBG_STATE_BYTE_SIZE must be bigger than drbg_info.size, which depends on the size of the ECB state
// Unfortunatelly we don't know at compile time the exact size.
// If the size is too small, ccrng_cryptographic_init_once will fail and an abort follows
// If too big, a print will indicate so.
#define DRBG_STATE_BYTE_SIZE 1104    // Fits all current assembly/mux implementations
#else
#define DRBG_STATE_BYTE_SIZE 1280    // Fits C version for 32 and 64bit platforms
#endif

struct ccrng_cryptographic_internal_state {
    
    struct ccdrbg_info   drbg_info;
    uint8_t drbg_state_buf[DRBG_STATE_BYTE_SIZE];

    int      init_status_rd_only;
    int      init_complete_rd_only;
    int      predictionBreak_status;  // status of asynchronous prediction_break
    int      predictionBreak_countdown;
    uint64_t predictionBreak_timer;
#if CC_RNG_MULTITHREAD_DISPATCH
    dispatch_queue_t  crypto_rng_q;     // safe concurrency use of DRBG internal state
    dispatch_source_t source;           // coalesce multiple pending prediction_break
#elif CC_RNG_MULTITHREAD_POSIX
    pthread_mutex_t mutex;
#elif CC_RNG_MULTITHREAD_KERNEL
    lck_mtx_t         *crypto_rng_q;
    lck_grp_t         *crypto_rng_lock_grp;
#elif CC_RNG_MULTITHREAD_WIN
	HANDLE hMutex;
#else
   #error Undefined thread management variables
#endif

    // This is the variable that we return upon calls to ccrng().
    // It contains only a pointer to the generate() function, that users can call.
    struct ccrng_state rng;
};

// the g_ccrng_cryptographic_state state is static to the library and available in this file only
// this variable is the one that ccrng_cryptographic.c work with
static struct ccrng_cryptographic_internal_state g_ccrng_cryptographic_state
= {
    .init_status_rd_only=CCERR_INTERNAL,
    .init_complete_rd_only=0, // init once
    .predictionBreak_status=CCDRBG_STATUS_NEED_RESEED,
    .predictionBreak_countdown=RNG_RESEED_INTERVAL,
};
//==============================================================================
//
//      Prediction Break
//
//==============================================================================

#if CC_RNG_MULTITHREAD_DISPATCH || CC_RNG_MULTITHREAD_POSIX
static void force_prediction_break_atfork(void)
{
    rng_debug_cc_printf("Forking! Force prediction break on next generate %d\n", getpid());
    if (0==g_ccrng_cryptographic_state.predictionBreak_status) {
        g_ccrng_cryptographic_state.predictionBreak_status=CCDRBG_STATUS_NEED_RESEED;
    }
}

static void force_prediction_break_atfork_child(void)
{
    // new queue
#if   CC_RNG_MULTITHREAD_DISPATCH
    g_ccrng_cryptographic_state.crypto_rng_q = dispatch_queue_create("ccrng_cryptographic prediction break dispatch", NULL);
#elif CC_RNG_MULTITHREAD_POSIX
    pthread_mutex_init(&g_ccrng_cryptographic_state.mutex, NULL);
#endif
    // force prediction
    force_prediction_break_atfork();
}
#endif

// applies continuous random number generator test, per FIPS 140-2 §4.9.2 Conditional Tests
// Generate three blocks of entropy (each block of size ENTROPY_SOURCE_BLOCK_SIZE).
// Throw away the first block(instead of saving the last generated block for the next time that the function is invoked)
// and return the last two blocks.
static int get_two_blocks_entropy(char *entropy)
{
#if RNG_ENTROPY_SIZE!= 2*ENTROPY_SOURCE_BLOCK_SIZE
#error can only get two blocks of entropy
#endif

    int status;
    size_t blk_len=ENTROPY_SOURCE_BLOCK_SIZE;
    char entropy_ref[blk_len];
    
    status = cc_get_entropy(blk_len, entropy_ref);
    cc_require(status==0, errOut);
    
    // Generate another two blocks of entropy.
    status = cc_get_entropy(2*blk_len, entropy);
    cc_require(status==0, errOut);
    
    // Compare each block to the previous block.
    if(0==cc_cmp_safe(blk_len, entropy, entropy_ref)
   || (0==cc_cmp_safe(blk_len, entropy, &entropy[blk_len]))) {
        status=CCERR_OUT_OF_ENTROPY;
    }
    
errOut:
    return status;
}

// mix in fresh entropy in the rng state.
// to be called within a thread safe environment
static int prediction_break(struct ccrng_cryptographic_internal_state *rng)
{
	char entropy[RNG_ENTROPY_SIZE];
    int status;
    struct ccdrbg_state *drbg_state=(struct ccdrbg_state *)rng->drbg_state_buf;
    
    status = get_two_blocks_entropy(entropy);
    if(status==0){
        uint64_t now = cc_absolute_time();
        status=ccdrbg_reseed(&rng->drbg_info, drbg_state, sizeof(entropy), entropy, sizeof(now), &now);
    }

    cc_clear(sizeof(entropy), entropy);
    rng->predictionBreak_status=status;

    rng_debug_cc_printf("Prediction break status (%d), countdown (%d)\n",
                        rng->predictionBreak_status,
                        rng->predictionBreak_countdown);

    if (status==0) {
        rng->predictionBreak_countdown=RNG_RESEED_INTERVAL;
        rng->predictionBreak_timer=cc_uptime_seconds();
    }
    return status;
}

// Needs to be executed in a LOCK()
static int reseed_in_generate_lock(int gen_status) {
    struct  ccrng_cryptographic_internal_state *rng=&g_ccrng_cryptographic_state;

    // Prediction break previously encountered an error or end of current seed life
    // Try hard and exit after too many tries
    // in normal conditions there is only one iteration of this loop
    // In case the time value rolls over, we may reseed too soon. A rare case.
    int64_t time_delta=cc_uptime_seconds()-rng->predictionBreak_timer;
    if (gen_status!=CCDRBG_STATUS_NEED_RESEED      /* Imposed by the DRBG */
        && rng->predictionBreak_status==0          /* Imposed by previous failure */
        && time_delta<RNG_RESEED_PERIOD_SECONDS) { /* Imposed by time out */
        return gen_status; // skip reseed
    }
    for (size_t i=0; i<RNG_MAX_SEED_RETRY;i++) {
            rng_debug_cc_printf("Entering prediction break in generate: gen_status (%d), Pred Break (%d), countdown (%d), timer (%lld)\n",
                   gen_status,rng->predictionBreak_status,rng->predictionBreak_countdown,time_delta);
            // Get entropy and reseed the drbg
            if (prediction_break(rng) == 0) {
                gen_status = CCDRBG_STATUS_OK; // Done reseeding
                break;
            }
    }
    return gen_status;
}

//==============================================================================
//
//      Generate function
//
//==============================================================================

static int
ccrng_cryptographic_generate(struct ccrng_state *input_rng, size_t count, void *bytes)
{

    struct  ccrng_cryptographic_internal_state *rng=&g_ccrng_cryptographic_state;
    struct  ccdrbg_state *drbg_state=(struct ccdrbg_state *)rng->drbg_state_buf;

    VAR_IN_LOCK int gen_status = CCDRBG_STATUS_OK;
    VAR_IN_LOCK int countdown = 0;
    VAR_IN_LOCK size_t readAmount = CCDRBG_MAX_REQUEST_SIZE;

    size_t	readRemainingBytes = count;
    
    //we don't need input_rng and we don't use it either. This is a sanity check to make sure
    //corecrypto functions has been used correctly.
    cc_require_action((void *)input_rng == (void *)&(rng->rng) ||
                      (input_rng->generate==rng->rng.generate && input_rng->generate==ccrng_cryptographic_generate),
                      errOut, gen_status = CCERR_PERMS);
    //---------------------------------------
    // Main loop
    //---------------------------------------
    // Two reasons to loop:
	// - to break down generation into CCDRBG_MAX_REQUEST_SIZE bytes chunks, per FIPS requirement
	// - to reseed when needed
    
	while ((readRemainingBytes > 0) &&
           ((gen_status==CCDRBG_STATUS_OK) || (gen_status==CCDRBG_STATUS_NEED_RESEED)))
    {
        LOCK(rng);

        //---------------------------------------
        // Reseed when needed
        //---------------------------------------
        // This call updates rng->predictionBreak_countdown
        gen_status=reseed_in_generate_lock(gen_status);

        // Make sure never to exceed CCDRBG_MAX_REQUEST_SIZE when calling the generate command
        if (readRemainingBytes < CCDRBG_MAX_REQUEST_SIZE) {
            readAmount = readRemainingBytes;
            countdown  = --rng->predictionBreak_countdown;
        } else {
            readAmount = CCDRBG_MAX_REQUEST_SIZE-1;
        }

        //---------------------------------------
        // Generate
        //---------------------------------------
        // All tentatives of reseed failed and seed is end of life
        if (gen_status==CCDRBG_STATUS_NEED_RESEED) {
            gen_status=rng->predictionBreak_status;
            //cc_try_abort() does NOT always abort. See cc_try_abort.c for the exact implementation.
            cc_try_abort("Fatal error with prediction break, cannot reseed");
        }else{
       
            // Whether or not we had recently failed a prediction break, we generate random as long as we
            // can do so (Possible until DRBG requires reseeded).
            // This is safer than not writing values or crashing our clients right away.
#if RNG_CRYPTO_DEBUG
#include "../../ccdrbg/src/ccdrbg_nistctr.h"
            if (rng->predictionBreak_status) {
                rng_debug_cc_printf("Non-fatal error (%d). Generate with the current seed, reseed counter %llu\n",
                rng->predictionBreak_status, ((struct ccdrbg_nistctr_state*)drbg_state)->reseed_counter);
            }
#else
            cc_assert(rng->predictionBreak_status==0); // Catch prediction break failures in debug builds
#endif
            gen_status = ccdrbg_generate(&rng->drbg_info, drbg_state, readAmount, bytes, 0, NULL);
        }
        
        rng_debug_cc_printf("Generate %zu bytes (%d)\n",readAmount,gen_status);
        UNLOCK(rng);
        if (gen_status==CCDRBG_STATUS_OK) {
            // Move forward in output buffer only if the generation was successful
            // That can happen if last ccdrbg_generate requested reseeding for example
            bytes += readAmount;
            readRemainingBytes -= readAmount;
        }
	} // while()

    // If we exited the previous loop prematurily, something is really wrong.
    // Abort so that we get crash reports.
    if (readRemainingBytes>0 || gen_status!=CCDRBG_STATUS_OK) {
        cc_try_abort("Unexpected error in ccrng_cryptographic generation");
        goto errOut;
    }

    //---------------------------------------
    // Prediction break after generate
    //---------------------------------------
    if (countdown<=0) {
        rng_debug_cc_printf("Prediction break end of generate (%d), countdown (%d)\n",
                            rng->predictionBreak_status,
                            rng->predictionBreak_countdown);
#if CC_RNG_MULTITHREAD_DISPATCH
        //corecrypto may be called in the child or parent of a fork.
        //reseed the child synchronously and reseed the parent Asynchronously.
        if (!_dispatch_is_fork_of_multithreaded_parent()) {
            // parent
            // make a call to prediction_break() on a background thread.
            // will check the status on next generate with predictionBreak_status
            dispatch_source_merge_data(rng->source, 1);
        } else
#endif
        { // child of a fork, or when there is no multitheading, or linux
            LOCK(rng);
            prediction_break(rng);
            UNLOCK(rng);
        }
    }
    
errOut:
	return gen_status;
}

//==============================================================================
//
//      Init
//
//==============================================================================
//The following two functions are used in the corecrypto kernel module only
//they are defined here because they use the g_ccrng_cryptographic_state static variable
#if CC_RNG_MULTITHREAD_KERNEL
static void init_lock_kext(struct ccrng_cryptographic_internal_state *rng) {

    /* allocate lock group attribute and group */
    lck_grp_attr_t  *rng_slock_grp_attr;
    lck_attr_t      *rng_slock_attr;

    rng_slock_grp_attr = lck_grp_attr_alloc_init();
    lck_grp_attr_setstat(rng_slock_grp_attr);
    rng->crypto_rng_lock_grp = lck_grp_alloc_init("corecrypto_rng_lock", rng_slock_grp_attr);

    rng_slock_attr = lck_attr_alloc_init();
#if CORECRYPTO_DEBUG
    lck_attr_setdebug(rng_slock_attr); // set the debug flag
#endif
    rng->crypto_rng_q=lck_mtx_alloc_init(rng->crypto_rng_lock_grp,rng_slock_attr);

    lck_attr_free(rng_slock_attr);
    lck_grp_attr_free(rng_slock_grp_attr);
}

/*
 // Corecrypto kext is never unloaded
static void done_lock_kext(void) {
    lck_mtx_free(g_ccrng_cryptographic_state.crypto_rng_q,
                 g_ccrng_cryptographic_state.crypto_rng_lock_grp);
    lck_grp_free(g_ccrng_cryptographic_state.crypto_rng_lock_grp);
}
 */
#endif // CC_RNG_MULTITHREAD_KERNEL

static int init_thread_mechanisms(struct ccrng_cryptographic_internal_state *rng)
{
    int rc;
    
#if CC_RNG_MULTITHREAD_DISPATCH
    // Create dispatch queue
    rng->crypto_rng_q = dispatch_queue_create("ccrng_cryptographic prediction break dispatch", NULL);
    
    // Force reseed on first RNG generation for the child and parent
    rc = pthread_atfork(NULL, force_prediction_break_atfork, force_prediction_break_atfork_child);
    cc_require_action(rc==0, errOut, rc=CCERR_ATFORK);

    rng->source = dispatch_source_create(DISPATCH_SOURCE_TYPE_DATA_ADD, 0, 0, rng->crypto_rng_q);
    if (rng->source) {
        dispatch_source_set_event_handler(rng->source, ^{
            prediction_break(rng);
            rng_debug_cc_printf("Fire source prediction break dispatch (%d)\n",rng->predictionBreak_status);
        });
        dispatch_resume(rng->source);
    }
    rc = 0;
    
#elif CC_RNG_MULTITHREAD_POSIX
    rc = pthread_mutex_init(&rng->mutex, NULL);
    cc_require_action(rc==0, errOut, rc=CCERR_INTERNAL);
  
    rc=pthread_atfork(NULL, force_prediction_break_atfork, force_prediction_break_atfork_child);
    cc_require_action(rc==0, errOut, rc=CCERR_ATFORK);
    
#elif CC_RNG_MULTITHREAD_WIN
    rc = 0;
    rng->hMutex = CreateMutex(NULL,              // default security attributes
                              FALSE,             // initially not owned
                              NULL);             // unnamed mutex
    cc_require_action(rng->hMutex!=NULL, errOut, rc=CCERR_INTERNAL);
    
#elif CC_RNG_MULTITHREAD_KERNEL
    init_lock_kext(rng);
    rc=0;
    cc_require(rc==0, errOut);
#else
#warning one of CC_RNG_MULTITHREAD_* macros must be defined
#endif // CC_RNG_MULTITHREAD_*
errOut:
    return rc;
}

// One time initialization of the global structure
// To be called within a thread-safe environment.
int ccrng_cryptographic_init_once(void) {
    int status=0; //okay
    char   entropy[RNG_ENTROPY_SIZE];
    struct ccdrbg_state *drbg_state;
    struct ccrng_cryptographic_internal_state *rng=&g_ccrng_cryptographic_state;

    // Check for init once violation
    cc_require_action((g_ccrng_cryptographic_state.init_complete_rd_only!=RNG_MAGIC_INIT),
                      errOut,status=CCERR_INTERNAL);

    //---------------------------------------
    // initialize the rng->drbg_info structure
    //---------------------------------------
    // Choosing an AES based DRBG since AES acceleration are the most
    // common accross devices.
    // Set DRBG - NIST CTR
    static struct ccdrbg_nistctr_custom custom;
    custom.ctr_info=ccaes_ctr_crypt_mode();
    custom.keylen=32;
    custom.strictFIPS=1;
    custom.use_df=1;
    ccdrbg_factory_nistctr(&rng->drbg_info, &custom);

    //---------------------------------------
    // initialize the drbg based on rng->drbg_info
    //---------------------------------------
    
    if (sizeof(rng->drbg_state_buf)<rng->drbg_info.size) {
#if CORECRYPTO_DEBUG
        cc_printf("Cryptographic DRBG state is too small. Need %d, Got %d,",
                  (int)rng->drbg_info.size,(int)sizeof(rng->drbg_state_buf));
#endif
        // If hitting this assert, it means the state size requirement of either the DRBG or the AES encryption
        // changed. It is required to update DRBG_STATE_BYTE_SIZE accordingly.
        cc_assert(sizeof(rng->drbg_state_buf)>rng->drbg_info.size);
        status = CCERR_INTERNAL;
    }else if (sizeof(rng->drbg_state_buf)>rng->drbg_info.size) {
#if CORECRYPTO_DEBUG
        // If seeing this message, it means that the allocated size is bigger than necessary
        // Not a major issue other than wasting memory.
        // Testing is required on all platforms when reducing the value since the size requirement of the DRBG state
        // depends on the size of the AES context and both Intel and ARM have different flavors.
        // Flavors may be decided at runtime (eg. AVX1 vs AVX2, or HW accelerator support on iOS devices).
        cc_printf("Cryptographic DRBG state is bigger than necessary. Need %d, Got %d,",
                  (int)rng->drbg_info.size,(int)sizeof(rng->drbg_state_buf));
#endif
    }
    cc_require(status==0, errOut);
    rng_debug_cc_printf("Cryptographic rng initialization\n");

    drbg_state=(struct ccdrbg_state *)rng->drbg_state_buf;
    rng->predictionBreak_status=CCERR_INTERNAL;
    rng->predictionBreak_timer=cc_uptime_seconds();
    status = get_two_blocks_entropy(entropy);
    cc_require(status==0, errOut);    

    // Get a nonce. NIST recommends using the time it's called
    // as a nonce. We use timing information from the OS as additional
    // Input. Inside the DRBG, the pointers are all just
    // concatenated together, so it doesn't really matter how
    // we do it. It's one big nonce.
    uint64_t now=cc_absolute_time();
    status=ccdrbg_init(&rng->drbg_info, drbg_state, sizeof(entropy), entropy, sizeof(now), &now, 0, NULL);
    cc_require(status==0, errOut);
    
    /* We might return an error here if the underlying DRBG init fails
     This may happen if, for example, the entropy length is not supported */

    status = init_thread_mechanisms(rng);
    cc_require(status==0, errOut);

errOut:
    //init_status_rd_only is read only and is set here once.
    g_ccrng_cryptographic_state.init_status_rd_only=status;
    g_ccrng_cryptographic_state.init_complete_rd_only=RNG_MAGIC_INIT;
    g_ccrng_cryptographic_state.predictionBreak_status=status; // To prevent generation, if error
    g_ccrng_cryptographic_state.rng.generate =
    (g_ccrng_cryptographic_state.init_status_rd_only==0)? ccrng_cryptographic_generate: NULL;
    cc_clear(sizeof(entropy), entropy);
	return status;
}

#if CC_RNG_MULTITHREAD_WIN
BOOL CALLBACK ccrng_cryptographic_init_once_win(PINIT_ONCE InitOnce, PVOID Parameter, PVOID *lpContext) {
    return ccrng_cryptographic_init_once() == 0 ? TRUE : FALSE;
}
#endif

struct ccrng_state *ccrng(int *error)
{
#if !CC_RNG_MULTITHREAD_KERNEL
    // In the kext, one time initialization calls are done in corecrypto_kext_start
    CC_INIT_ONCE(ccrng_cryptographic_init_once);
#endif

    int status = g_ccrng_cryptographic_state.init_status_rd_only;
    if (error!=NULL)
        *error=status;
        
    return status==0? &g_ccrng_cryptographic_state.rng : NULL;
}
    



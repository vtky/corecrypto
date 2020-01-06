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

#include "crypto_test_rng.h"
#include "ccrng_cryptographic_priv.h"
#include "testmore.h"
#if CC_RNG_MULTITHREAD_WIN
#include <Windows.h>
#else
#include <pthread.h>
#endif
#include <stdio.h>
#include <stdlib.h>

#define ccrng_diag(...) //diag

//==============================================================================
//
//      Thread safe test for ccrng
//
//==============================================================================

/* the thread routine for generating randoms */

#if CC_RNG_MULTITHREAD_WIN
DWORD WINAPI gen_routine(LPVOID p)
#else
void *gen_routine(void *p)
#endif
{
	struct gen_thread_data *data = (struct gen_thread_data *)p;
	int status = 0;
	struct ccrng_state* rng = data->rng;
	uint64_t *results = data->results;

#if CC_RNG_MULTITHREAD_WIN
    if (data->barrier!=NULL)
		EnterSynchronizationBarrier(data->barrier, 0);
#endif
	
	for (int i = 0; i<THREAD_RESULT_ARRAY_LEN && status == 0; i++) {
		status |= ccrng_generate(rng, sizeof(*results), &results[i]);
	}
    data->status = status;
	return 0;
}

#if CC_RNG_MULTITHREAD_WIN
HANDLE winthread_create(LPTHREAD_START_ROUTINE start_address, LPVOID param) {
	HANDLE thread = CreateThread(NULL, 0, start_address, param, 0, NULL);
	return thread;
}
#endif

// creates a thread, generates random numbers in that thread,
// and compares the generated numbers with the random numbers created in the
// main thread

static int two_threads_test(struct ccrng_state* rng)
{
	struct gen_thread_data gen_thread_data;
    uint64_t results_buf[2 * THREAD_RESULT_ARRAY_LEN];
    memset(results_buf, -1, sizeof(results_buf));
    ccrng_diag("two threads test");
    
    //This part of the buffer is for the thread we are creating.
    //The top part belongs to the main thread.
    gen_thread_data.results = &results_buf[THREAD_RESULT_ARRAY_LEN];
    gen_thread_data.rng = rng;
    gen_thread_data.status = -1;
    
    int rc = 1; //ok

    /* Create a second thread to generate random numbers.         */
	/* gen_thread variable is our reference to the second thread. */
#if CC_RNG_MULTITHREAD_WIN
    gen_thread_data.barrier = NULL;
	HANDLE gen_thread = winthread_create(gen_routine, &gen_thread_data);
	ok_or_fail(gen_thread != NULL, "Error creating thread");
#else
	pthread_t gen_thread;
    ok_or_fail(pthread_create(&gen_thread, NULL, gen_routine, &gen_thread_data)==0, "Error creating thread");
#endif
    
    uint64_t *results = results_buf;
    int status = 0;

	/* generate numbers in the current thread */
	for (int i = 0; i<THREAD_RESULT_ARRAY_LEN && status == 0; i++) {
		status |= ccrng_generate(rng, sizeof(*results), &results[i]);
	}
	rc &= is(status, 0, "Generate in parent");

	/* wait for the second thread to finish */
#if CC_RNG_MULTITHREAD_WIN
	rc &= ok(WAIT_OBJECT_0 == WaitForSingleObject(gen_thread, INFINITE), "Error joining thread\n");
#else
	rc &= ok(0 == pthread_join(gen_thread, NULL), "Error joining thread\n");
#endif

	rc &= is(gen_thread_data.status, 0, "Generate in the second thread");

	rc &= find_duplicate_uint64(results, 2 * THREAD_RESULT_ARRAY_LEN);
    ok(rc==1, "two threads test failed");
	return rc;
}

#if CC_RNG_MULTITHREAD_WIN
int multi_thread_test(struct ccrng_state* rng)
{
    int rc;
    
    rc  = two_threads_test(rng);
    rc &= test_rng_win(rng);
    return rc;
}
#else //Linux and macOS
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#if CC_RNG_MULTITHREAD_DISPATCH 
#include <dispatch/dispatch.h>
static int many_threads_test(struct ccrng_state* rng)
{

    uint64_t results_buf[2*THREAD_RESULT_ARRAY_LEN];
    memset(results_buf, -1, sizeof(results_buf));

    uint64_t *results=results_buf;
    ccrng_diag("many threads test");

    // 2*THREAD_RESULT_ARRAY_LEN threads test
    dispatch_queue_t the_queue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    dispatch_apply(2*THREAD_RESULT_ARRAY_LEN, the_queue, ^(size_t idx) {
        ccrng_generate(rng, sizeof(*results), &results[idx]);
    });
    
    int rc = find_duplicate_uint64(results,2*THREAD_RESULT_ARRAY_LEN);
    ok(rc==1, "many threads test failed");
    
    return rc;
}
#else
static int many_threads_test(struct ccrng_state* rng)
{
    rng = rng;
    return 1;
}
#endif

static int generate_randoms(struct ccrng_state* rng, uint64_t *results)
{
    struct gen_thread_data data;
    data.rng=rng;
    data.status=-1;
    data.results = results;
    gen_routine(&data);
    return data.status;
}

static int fork_test(struct ccrng_state* rng)
{
    int     fd[2];
    pid_t   child_pid;
    int rc=0;//error
    uint64_t results[2*THREAD_RESULT_ARRAY_LEN]; //the parent needs two times larger buffer
    memset(results, -1, sizeof(results));
    ccrng_diag("fork test");
    
    ok_or_fail(pipe(fd)!= -1, "cannot create a pipe");
    child_pid = fork();
    ok_or_fail(child_pid!=-1, "cannot fork");
    
    //generate random in child and send to parent for duplicate check
    if(child_pid == 0)
    {
        close(fd[0]);
        ccrng_diag("forked child started\n");

        int status = generate_randoms(rng, results);
        //write to the pipe
        write(fd[1], &status, sizeof(status));
        write(fd[1], results, THREAD_RESULT_ARRAY_LEN*sizeof(results[0]));
        close(fd[1]);

        exit(0);
    }else {
        close(fd[1]);
        int child_status, parent_status;
        
        parent_status=generate_randoms(rng, results);
        
        /* wait for completion of the child */
        while (waitpid(child_pid,&child_status,0)!=child_pid)
            ;
        ccrng_diag("waitpid %d with errno %d. Status is %d\n", child_pid, errno, child_status);
        read(fd[0], &child_status, sizeof(child_status)); // the child's ccrng_generate() return value
        read(fd[0], results+THREAD_RESULT_ARRAY_LEN, THREAD_RESULT_ARRAY_LEN*sizeof(results[0]));
        
        rc =is(child_status,0,"Child rng status. Child may have crashed.");
        rc&=is(parent_status,0,"Parent rng status");
        
        rc&= find_duplicate_uint64(results,2*THREAD_RESULT_ARRAY_LEN);
        ok(rc==1, "fork test failed");
        close(fd[0]);

    }
    
    return rc;
}

int multi_thread_test(struct ccrng_state* rng)
{
    //experience shows these tests must be repeated a lot to trigger possible errors.
    //increase N_TESTS orders of magnitudes, while developing code
#define N_TESTS 500 
    int rc=1;
    for(int i=0; i<N_TESTS; i++){
        rc &= two_threads_test(rng);
        rc &= many_threads_test(rng);
        rc &= fork_test(rng);
    }
    
    for(int i=0; i<N_TESTS; i++)
        rc &= two_threads_test(rng);
    
    for(int i=0; i<N_TESTS; i++)
        rc &= many_threads_test(rng);
    
    for(int i=0; i<N_TESTS; i++)
        rc &= fork_test(rng);
    
    return rc;
}

#endif

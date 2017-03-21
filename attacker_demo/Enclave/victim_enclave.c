#include "aes.h"
#include "victim_enclave.h"


#define KEYLEN 16

/*
 * Global variables exist for alignment reasons.
 * Must not interfer with SBox cachelines.
 */

static volatile int alignment_dummy __attribute__ ((aligned(4096)));
static volatile int alignment_dummy_2 __attribute__ ((aligned(1024)));
static AES_KEY expanded;
static unsigned long state[8];
static unsigned long roundkey[4];
static volatile int tmp;

/*
 * Run AES round 1-9.
 */
void encrypt_step( unsigned char *input ) {
	AES_encrypt_step(input, &expanded, state, roundkey);
}

/*
 * Run AES round 10.
 */
void encrypt_final( unsigned char *output ) {
	AES_encrypt_final(output, state, roundkey);
}

/*
 * Main loop, encrypt input and return ciphertext on
 * output. Use flag and flag_out for communication
 * with mainthread.
 */
void encrypt_loop( unsigned char *input, unsigned char	*output, int *flag, int *flag_out) {
	tmp = 0;
	// wait for signal to start
	do {
		tmp = *flag;
		// are we done?
		if (tmp == 0x4) {
			return;
		}
	} while (tmp != 0x1);

	// aes round 0-9
	encrypt_step(input);
	*flag_out = 0x1;
	
	// wait for signal to continue
	do {
		tmp = *flag;
	} while (tmp != 0x2);


	// aes round 10	
	encrypt_final(output);
	*flag_out = 0x2;
	
	// wait for signal to finish
	do {
		tmp = *flag;
	} while (tmp != 0x3);
	*flag_out = 0x3;

}

/*
 * Generate AES-key with random bytes.
 */
sgx_status_t createSecret(void) {
	unsigned char key[KEYLEN];	
	sgx_status_t ret;
	if ( SGX_SUCCESS != (ret = sgx_read_rand(key, KEYLEN))) {
		return ret;
	}
	AES_set_encrypt_key(key, KEYLEN*8, &expanded);
	return SGX_SUCCESS;
}

/*
 * Return the size of encrypted AES-KEY.
 */
uint32_t getSecretSize(void) {
	return sgx_calc_sealed_data_size(0, sizeof(AES_KEY)); 
}

/*
 * Store AES-Key sealed in untrusted memory.
 */
sgx_status_t  storeSecret(sgx_sealed_data_t *storage, uint32_t sealed_data_size) {
	return sgx_seal_data(0, NULL, sizeof(AES_KEY), (uint8_t *) &expanded, sealed_data_size, storage);
}	

/*
 * Load sealed AES-Key from untrusted memory.
 */
sgx_status_t loadSecret(sgx_sealed_data_t *storage) {
	sgx_status_t ret;
	int i;
	uint32_t dec_len;
	uint8_t *dec_text;
	uint32_t sealed_data_size;
	sgx_sealed_data_t *int_storage;

	if ( SGX_SUCCESS != (ret = sgx_calc_sealed_data_size(0, sizeof(AES_KEY)))) {
		return ret;
	}

	int_storage = malloc(sealed_data_size);
	if (int_storage == NULL) {
		return SGX_ERROR_UNEXPECTED;
	}
	for(i = 0; i < sealed_data_size; i++) {
		((uint8_t *) int_storage)[i] = ((uint8_t *) storage)[i];
	}
	
	dec_len = sgx_get_encrypt_txt_len(int_storage);	
	dec_text = malloc(dec_len);
	if (dec_text == NULL) {
		free(int_storage);
		return SGX_ERROR_UNEXPECTED;
	}
	if ( SGX_SUCCESS != (ret = sgx_unseal_data(int_storage, NULL, 0, dec_text, &dec_len))) {
		free(int_storage);
		free(dec_text);
		return ret;
	}

	for(i = 0; i < sizeof(AES_KEY); i++) {
		((uint8_t *) &expanded)[i] = ((uint8_t *) dec_text)[i];
	}
	free(int_storage);
	free(dec_text);
	return SGX_SUCCESS;
}	

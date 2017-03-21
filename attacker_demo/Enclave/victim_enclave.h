#ifndef VICTIM_ENCLAVE_H
#define VICTIM_ENCLAVE_H
#include <stdlib.h>
#include <sgx_trts.h>
#include <sgx_tseal.h>

/*
 * Generate AES-key with random bytes.
 */
sgx_status_t createSecret(void);

/*
 * Return the size of encrypted AES-Key.
 */
uint32_t getSecretSize(void);

/*
 * Store AES-Key sealed in untrusted memory.
 */
sgx_status_t  storeSecret(sgx_sealed_data_t *storage, uint32_t sealed_secret_size);

/*
 * Load sealed AES-Key from untrusted memory.
 */
sgx_status_t loadSecret(sgx_sealed_data_t *storage);

/*
 * Run AES round 1-9.
 */
void encrypt_step( unsigned char *input );

/*
 * Run AES round 10.
 */
void encrypt_final( unsigned char *output );

/*
 * Main loop, encrypt input and return ciphertext on
 * output. Use flag and flag_out for communication
 * with mainthread.
 */
void encrypt_loop( unsigned char *input, unsigned char *output, int *flag, int *flag_out );

#endif


#ifndef AES_H
#define AES_H
void g_hash(unsigned char* input, int inputLen, unsigned char* H, unsigned char* macBlock);

void cbc_mac(unsigned char* input, int inputLen, unsigned char* macBlock, unsigned char* key, int keyLen);

void aes_block_encrypt(unsigned char* inputBlock, unsigned char* outBlock, unsigned char* key, int keyLen);

void aes_128_encrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* key);

void aes_128_decrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* key);

void aes_256_encrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* key);

void aes_256_decrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* key);

void aes_128_ctr_encrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* key);

void aes_128_ctr_decrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* key);

void aes_256_ctr_encrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* key);

void aes_256_ctr_decrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* key);

void aes_128_ccm_encrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* add, int addLen, unsigned char* key);

void aes_128_ccm_decrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* add, int addLen, unsigned char* key);

void aes_256_ccm_encrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* add, int addLen, unsigned char* key);

void aes_256_ccm_decrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* add, int addLen, unsigned char* key);

void aes_128_gcm_encrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* add, int addLen, unsigned char* key);

void aes_128_gcm_decrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* add, int addLen, unsigned char* key);

void aes_256_gcm_encrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* add, int addLen, unsigned char* key);

void aes_256_gcm_decrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* add, int addLen, unsigned char* key);
#endif
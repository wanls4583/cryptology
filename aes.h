#ifndef AES_H
#define AES_H
void gHash(unsigned char* input, int inputLen, unsigned char* H, unsigned char* macBlock);

void cbcMac(unsigned char* input, int inputLen, unsigned char* macBlock, unsigned char *key, int keyLen);

void aesBlockEncrypt(unsigned char* inputBlock, unsigned char* outBlock, unsigned char* key, int keyLen);

void aes128Encrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, int ivLen, unsigned char* key);

void aes128Decrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, int ivLen, unsigned char* key);

void aes256Encrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, int ivLen, unsigned char* key);

void aes256Decrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, int ivLen, unsigned char* key);

void aes128CtrEncrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, int ivLen, unsigned char* key);

void aes128CtrDecrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, int ivLen, unsigned char* key);

void aes256CtrEncrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, int ivLen, unsigned char* key);

void aes256CtrDecrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, int ivLen, unsigned char* key);

void aes128GcmEncrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, int ivLen, unsigned char* add, int addLen, unsigned char* key);

void aes128GcmDecrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, int ivLen, unsigned char* add, int addLen, unsigned char* key);

void aes256GcmEncrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, int ivLen, unsigned char* add, int addLen, unsigned char* key);

void aes256GcmDecrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, int ivLen, unsigned char* add, int addLen, unsigned char* key);
#endif
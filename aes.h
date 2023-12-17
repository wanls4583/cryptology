#ifndef AES_H
#define AES_H
void aes128Encrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, int iv_len, unsigned char* key);

void aes256Encrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, int iv_len, unsigned char* key);

void aes128Decrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, int iv_len, unsigned char* key);

void aes256Decrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, int iv_len, unsigned char* key);
#endif
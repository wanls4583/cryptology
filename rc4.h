#ifndef RC4_H
#define RC4_H

#define RC4_STATE_ARRAY_LEN  256

typedef struct {
	int i;
	int j;
	unsigned char S[RC4_STATE_ARRAY_LEN];
}
rc4_state;

void rc4_40_encrypt(
	unsigned char* plaintext,
	int plaintext_len,
	unsigned char ciphertext[],
	void* state,
	unsigned char* key
);
void rc4_40_decrypt(
	unsigned char* ciphertext,
	int ciphertext_len,
	unsigned char plaintext[],
	void* state,
	unsigned char* key
);
void rc4_128_encrypt(
	unsigned char* plaintext,
	int plaintext_len,
	unsigned char ciphertext[],
	void* state,
	unsigned char* key
);
void rc4_128_decrypt(
	unsigned char* ciphertext,
	int ciphertext_len,
	unsigned char plaintext[],
	void* state,
	unsigned char* key
);

#endif

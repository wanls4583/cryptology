#ifndef RSA_H
#define RSA_H

#define RSA_NO_PADDING 0
#define RSA_PKCS1_PADDING 1
#define RSA_PKCS1_OAEP_PADDING 2

#include "huge.h"

typedef struct {
	huge* p; //模数
	huge* key; //公钥/私钥
}
rsa_key;

int rsa_encrypt(
	rsa_key* public_key,
	unsigned char* input,
	unsigned int len,
	unsigned char** output,
	int padded_mode
);
int rsa_decrypt(
	rsa_key* private_key,
	unsigned char* input,
	unsigned int len,
	unsigned char** output,
	int padded_mode
);

#endif

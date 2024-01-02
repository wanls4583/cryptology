#ifndef RSA_H
#define RSA_H

#include "huge.h"

typedef struct {
	huge* p; //模数
	huge* key; //公钥/私钥
}
rsa_key;

int rsa_encrypt(
	unsigned char* input,
	unsigned int len,
	unsigned char** output,
	rsa_key* public_key
);
int rsa_decrypt(
	unsigned char* input,
	unsigned int len,
	unsigned char** output,
	rsa_key* private_key
);

#endif

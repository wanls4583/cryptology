#ifndef DES_H
#define DES_H

#define DES_KEY_SIZE 8 // 56 bits used, but must supply 64 (8 are ignored)

typedef enum { OP_ENCRYPT, OP_DECRYPT } op_type;

void des_encrypt(
	unsigned char* input,
	int input_len,
	unsigned char* out,
	unsigned char* iv,
	unsigned char* key
);

void des_decrypt(
	unsigned char* input,
	int input_len,
	unsigned char* out,
	unsigned char* iv,
	unsigned char* key
);

void des3_encrypt(
	unsigned char* input,
	int input_len,
	unsigned char* out,
	unsigned char* iv,
	unsigned char* key
);

void des3_decrypt(
	unsigned char* input,
	int input_len,
	unsigned char* out,
	unsigned char* iv,
	unsigned char* key
);

#endif

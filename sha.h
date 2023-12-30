#ifndef SHA_H
#define SHA_H

#define SHA1_INPUT_BLOCK_SIZE 56
#define SHA1_BLOCK_SIZE 64

#define SHA256_INPUT_BLOCK_SIZE SHA1_INPUT_BLOCK_SIZE
#define SHA256_BLOCK_SIZE SHA1_BLOCK_SIZE

#define SHA512_INPUT_BLOCK_SIZE 112
#define SHA512_BLOCK_SIZE 128

#define SHA1_RESULT_SIZE 5
#define SHA1_WORD_SIZE 4
#define SHA1_BYTE_SIZE SHA1_RESULT_SIZE * SHA1_WORD_SIZE

#define SHA256_RESULT_SIZE 8
#define SHA256_WORD_SIZE 4
#define SHA256_BYTE_SIZE SHA256_RESULT_SIZE * SHA256_WORD_SIZE

#define SHA224_RESULT_SIZE 7

#define SHA512_RESULT_SIZE 8
#define SHA512_WORD_SIZE 8
#define SHA512_BYTE_SIZE SHA512_RESULT_SIZE * SHA512_WORD_SIZE

#include "digest.h"

unsigned int sha1_initial_hash[SHA1_RESULT_SIZE];
unsigned int sha224_initial_hash[SHA256_RESULT_SIZE];
unsigned int sha256_initial_hash[SHA256_RESULT_SIZE];
u_int64_t sha512_initial_hash[SHA512_RESULT_SIZE];

int sha1_hash(unsigned char* input, int len, unsigned int hash[SHA1_RESULT_SIZE]);
void sha1_block_operate(const unsigned char* block, unsigned int hash[SHA1_RESULT_SIZE]);
void sha256_block_operate(const unsigned char* block, unsigned int hash[SHA256_RESULT_SIZE]);
void sha512_block_operate(const unsigned char* block, u_int64_t hash[SHA512_RESULT_SIZE]);
void sha1_finalize(unsigned char* padded_block, int length_in_bits);
void new_sha1_digest(digest_ctx* context);
void new_sha256_digest(digest_ctx* context);
void new_sha224_digest(digest_ctx* context);
void new_sha512_digest(digest_ctx* context);

#endif

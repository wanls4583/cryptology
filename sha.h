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

#define SHA384_RESULT_SIZE 6

#include "digest.h"

u32 sha1_initial_hash[SHA1_RESULT_SIZE];
u32 sha224_initial_hash[SHA256_RESULT_SIZE];
u32 sha256_initial_hash[SHA256_RESULT_SIZE];
u64 sha512_initial_hash[SHA512_RESULT_SIZE];

int sha1_hash(u8* input, int len, u32 hash[SHA1_RESULT_SIZE]);
void sha1_block_operate(const u8* block, u32 hash[SHA1_RESULT_SIZE]);
void sha256_block_operate(const u8* block, u32 hash[SHA256_RESULT_SIZE]);
void sha512_block_operate(const u8* block, u64 hash[SHA512_RESULT_SIZE]);
void sha1_finalize(u8* padded_block, int length_in_bits);
void sha512_finalize(u8* padded_block, int length_in_bits);
void new_sha1_digest(digest_ctx* context);
void new_sha256_digest(digest_ctx* context);
void new_sha224_digest(digest_ctx* context);
void new_sha512_digest(digest_ctx* context);
void new_sha384_digest(digest_ctx* context);

#endif

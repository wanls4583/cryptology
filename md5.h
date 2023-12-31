#ifndef MD5_H
#define MD5_H

#define MD5_BLOCK_SIZE 64
#define MD5_INPUT_BLOCK_SIZE 56
#define MD5_RESULT_SIZE 4
#define MD5_WORD_SIZE 4
#define MD5_BYTE_SIZE MD5_RESULT_SIZE * MD5_WORD_SIZE

#include "digest.h"

u32 md5_initial_hash[MD5_RESULT_SIZE];

int md5_hash(const u8* input, int len, u32 hash[MD5_RESULT_SIZE]);
void md5_block_operate(const u8* input, u32 hash[MD5_RESULT_SIZE]);
void md5_finalize(u8* padded_block, int length_in_bits);
void new_md5_digest(digest_ctx* context);

#endif

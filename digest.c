#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "digest.h"
#include "md5.h"
#include "hex.h"

void show_hash(unsigned int* hash, int hash_len) {
    unsigned char* display_hash = (unsigned char*)hash;
    for (int i = 0; i < (hash_len * 4); i++) {
        printf("%.02x", display_hash[i]);
    }
    printf("\n");
}

int digest_hash(
    unsigned char* input,
    int len,
    unsigned int* hash,
    void (*block_operate)(const unsigned char* input, unsigned int hash[]),
    void (*block_finalize)(unsigned char* block, int length)
) {
    unsigned char padded_block[DIGEST_BLOCK_SIZE];
    int length_in_bits = len * 8;

    while (len >= DIGEST_BLOCK_SIZE) {
        block_operate(input, hash);
        len -= DIGEST_BLOCK_SIZE;
        input += DIGEST_BLOCK_SIZE;
    }

    memset(padded_block, 0, DIGEST_BLOCK_SIZE);
    padded_block[0] = 0x80;

    if (len) {
        memcpy(padded_block, input, len);
        padded_block[len] = 0x80;
        if (len >= INPUT_BLOCK_SIZE) {
            block_operate(padded_block, hash);
            memset(padded_block, 0, DIGEST_BLOCK_SIZE);
        }
    }

    block_finalize(padded_block, length_in_bits);
    block_operate(padded_block, hash);

    return 0;
}

// #define DIGEST_HASH
#ifdef DIGEST_HASH
int main() {
    unsigned char* decoded_input;
    int str_len;
    unsigned int* hash;
    int hash_len;

    unsigned char s1[] = "abc";
    unsigned char s2[] = "abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca";
    unsigned char s3[] = "abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca123";
    unsigned char s4[] = "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcddddddddddddddddddddddddddddddqqqqqqqqeeee123";
    hash_len = MD5_RESULT_SIZE;

    hash = malloc(sizeof(int) * MD5_RESULT_SIZE);
    str_len = (int)strlen((const char*)s1);
    memcpy(hash, md5_initial_hash, sizeof(int) * MD5_RESULT_SIZE);
    digest_hash(s1, str_len, hash, md5_block_operate, md5_finalize);
    printf("str_len=%d\n", str_len);
    show_hash(hash, hash_len);

    hash = malloc(sizeof(int) * MD5_RESULT_SIZE);
    str_len = (int)strlen((const char*)s2);
    memcpy(hash, md5_initial_hash, sizeof(int) * MD5_RESULT_SIZE);
    digest_hash(s2, str_len, hash, md5_block_operate, md5_finalize);
    printf("str_len=%d\n", str_len);
    show_hash(hash, hash_len);

    hash = malloc(sizeof(int) * MD5_RESULT_SIZE);
    str_len = (int)strlen((const char*)s3);
    memcpy(hash, md5_initial_hash, sizeof(int) * MD5_RESULT_SIZE);
    digest_hash(s3, str_len, hash, md5_block_operate, md5_finalize);
    printf("str_len=%d\n", str_len);
    show_hash(hash, hash_len);

    hash = malloc(sizeof(int) * MD5_RESULT_SIZE);
    str_len = (int)strlen((const char*)s4);
    memcpy(hash, md5_initial_hash, sizeof(int) * MD5_RESULT_SIZE);
    digest_hash(s4, str_len, hash, md5_block_operate, md5_finalize);
    printf("str_len=%d\n", str_len);
    show_hash(hash, hash_len);

    return 0;
}
#endif
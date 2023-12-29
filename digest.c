#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "digest.h"
#include "md5.h"
#include "hex.h"

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

#define DIGEST_HASH
#ifdef DIGEST_HASH
int main() {
    unsigned char* decoded_input;
    int decoded_len;
    unsigned int* hash;
    int hash_len;

    decoded_len = hex_decode((unsigned char*)"abc", &decoded_input);
    hash = malloc(sizeof(int) * MD5_RESULT_SIZE);
    hash_len = MD5_RESULT_SIZE;
    memcpy(hash, md5_initial_hash, sizeof(int) * MD5_RESULT_SIZE);
    digest_hash(decoded_input, decoded_len, hash, md5_block_operate, md5_finalize);

    unsigned char* display_hash = (unsigned char*)hash;
    for (int i = 0; i < (hash_len * 4); i++) {
        printf("%.02x", display_hash[i]);
    }
    return 0;
}
#endif
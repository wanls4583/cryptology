#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sha.h"

#define SHA1_INPUT_BLOCK_SIZE 56
#define SHA1_BLOCK_SIZE 64

unsigned int sha1_initial_hash[] = {
    0x01234567,
    0x89abcdef,
    0xfedcba98,
    0x76543210,
    0xf0e1d2c3
};

unsigned int sha256_initial_hash[] = {
    0x67e6096a,
    0x85ae67bb,
    0x72f36e3c,
    0x3af54fa5,
    0x7f520e51,
    0x8c68059b,
    0xabd9831f,
    0x19cde05b
};

int sha1_k[] = {
    0x5a827999, // 0 <= t <= 19
    0x6ed9eba1, // 20 <= t <= 39
    0x8f1bbcdc, // 40 <= t <= 59
    0xca62c1d6 // 60 <= t <= 79
};

void sha1_block_operate(const unsigned char* block, unsigned int hash[SHA1_RESULT_SIZE]) {
    unsigned int w[80];
    unsigned int a, b, c, d, e, tmp;

    for (int t = 0; t < 80; t++) { // 16个字扩展成80个字
        if (t < 16) { // 将以小端排序的明文分组存入w[0..15]
            w[t] = (block[t * 4] << 24) | (block[t * 4 + 1] << 16) | (block[t * 4 + 2] << 8) | block[t * 4 + 3];
        } else {
            w[t] = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
            w[t] = (w[t] << 1) | ((w[t] & 0x80000000) >> 31); // 循环左移一位
        }
    }

    // 大端排序转化成小段排序
    hash[0] = ntohl(hash[0]);
    hash[1] = ntohl(hash[1]);
    hash[2] = ntohl(hash[2]);
    hash[3] = ntohl(hash[3]);
    hash[4] = ntohl(hash[4]);

    a = hash[ 0 ];
    b = hash[ 1 ];
    c = hash[ 2 ];
    d = hash[ 3 ];
    e = hash[ 4 ];

    for (int t = 0; t < 80; t++) {
        tmp = ((a << 5) | (a >> 27)) + e + w[t] + sha1_k[t / 20];
        if (t < 20) {
            tmp += (b & c) ^ (~b & d);
        } else if (t < 40) {
            tmp += b ^ c ^ d;
        } else if (t < 60) {
            tmp += (b & c) ^ (b & d) ^ (c & d);
        } else {
            tmp += b ^ c ^ d;
        }

        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = tmp;
    }

    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;

    // hash最终结果为大端排序
    hash[0] = htonl(hash[0]);
    hash[1] = htonl(hash[1]);
    hash[2] = htonl(hash[2]);
    hash[3] = htonl(hash[3]);
    hash[4] = htonl(hash[4]);
}

void sha256_block_operate(const unsigned char* block, unsigned int hash[SHA256_RESULT_SIZE]) {

}

// 大端排序存储真实数据长度
void sha1_finalize(unsigned char* padded_block, int length_in_bits) {
    padded_block[SHA1_BLOCK_SIZE - 4] = (length_in_bits & 0xFF000000) >> 24;
    padded_block[SHA1_BLOCK_SIZE - 3] = (length_in_bits & 0x00FF0000) >> 16;
    padded_block[SHA1_BLOCK_SIZE - 2] = (length_in_bits & 0x0000FF00) >> 8;
    padded_block[SHA1_BLOCK_SIZE - 1] = (length_in_bits & 0x000000FF);
}

int sha1_hash(unsigned char* input, int len, unsigned int hash[SHA1_RESULT_SIZE]) {
    unsigned char padded_block[SHA1_BLOCK_SIZE];
    int length_in_bits = len * 8;

    hash[0] = sha1_initial_hash[0];
    hash[1] = sha1_initial_hash[1];
    hash[2] = sha1_initial_hash[2];
    hash[3] = sha1_initial_hash[3];
    hash[4] = sha1_initial_hash[4];

    while (len >= SHA1_BLOCK_SIZE) {
        sha1_block_operate(input, hash);
        len -= SHA1_BLOCK_SIZE;
        input += SHA1_BLOCK_SIZE;
    }

    memset(padded_block, 0, SHA1_BLOCK_SIZE);
    padded_block[0] = 0x80;

    if (len) {
        memcpy(padded_block, input, len);
        padded_block[len] = 0x80;
        if (len >= SHA1_INPUT_BLOCK_SIZE) {
            sha1_block_operate(padded_block, hash);
            memset(padded_block, 0, SHA1_BLOCK_SIZE);
        }
    }

    sha1_finalize(padded_block, length_in_bits);
    sha1_block_operate(padded_block, hash);

    return 0;
}

void new_sha1_digest(digest_ctx* context) {
    context->hash_len = SHA1_RESULT_SIZE;
    context->input_len = 0;
    context->block_len = 0;
    context->hash = (unsigned int*)malloc(context->hash_len * sizeof(unsigned int));
    memcpy(context->hash, sha1_initial_hash, context->hash_len * sizeof(unsigned int));
    memset(context->block, '\0', SHA1_BLOCK_SIZE);
    context->block_operate = sha1_block_operate;
    context->block_finalize = sha1_finalize;
}

void new_sha256_digest(digest_ctx* context) {
    context->hash_len = SHA256_RESULT_SIZE;
    context->input_len = 0;
    context->block_len = 0;
    context->hash = (unsigned int*)malloc(context->hash_len * sizeof(unsigned int));
    memcpy(context->hash, sha256_initial_hash, context->hash_len * sizeof(unsigned int));
    memset(context->block, '\0', SHA1_BLOCK_SIZE);
    context->block_operate = sha256_block_operate;
    context->block_finalize = sha1_finalize;
}
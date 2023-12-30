#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sha.h"

unsigned int sha1_initial_hash[] = {
    0x01234567,
    0x89abcdef,
    0xfedcba98,
    0x76543210,
    0xf0e1d2c3
};

unsigned int sha224_initial_hash[] = {
    0xd89e05c1,
    0x07d57c36,
    0x17dd7030,
    0x39590ef7,
    0x310bc0ff,
    0x11155868,
    0xa78ff964,
    0xa44ffabe
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

static const int sha1_k[] = {
    0x5a827999, // 0 <= t <= 19
    0x6ed9eba1, // 20 <= t <= 39
    0x8f1bbcdc, // 40 <= t <= 59
    0xca62c1d6 // 60 <= t <= 79
};

static const unsigned int sha256_k[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

unsigned int ch(unsigned int x, unsigned int y, unsigned int z) {
    return (x & y) ^ (~x & z);
}

unsigned int maj(unsigned int x, unsigned int y, unsigned int z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

unsigned int parity(unsigned int x, unsigned int y, unsigned int z) {
    return x ^ y ^ z;
}

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

    a = hash[0];
    b = hash[1];
    c = hash[2];
    d = hash[3];
    e = hash[4];

    for (int t = 0; t < 80; t++) {
        tmp = ((a << 5) | (a >> 27)) + e + w[t] + sha1_k[t / 20];
        if (t < 20) {
            tmp += ch(b, c, d);
        } else if (t < 40) {
            tmp += parity(b, c, d);
        } else if (t < 60) {
            tmp += maj(b, c, d);
        } else {
            tmp += parity(b, c, d);
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

unsigned int rotr(unsigned int x, unsigned int n) {
    return (x >> n) | (x << (32 - n));
}

unsigned int shr(unsigned int x, unsigned int n) {
    return x >> n;
}

unsigned int sigma_rot(unsigned int x, int i) {
    if (i) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    } else {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }
}

unsigned int sigma_shr(unsigned int x, int i) {
    if (i) {
        return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10);
    } else {
        return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3);
    }
}

void sha256_block_operate(const unsigned char* block, unsigned int hash[SHA256_RESULT_SIZE]) {
    unsigned int w[64];
    unsigned int a, b, c, d, e, f, g, h;
    unsigned int t1, t2;

    for (int t = 0; t < 64; t++) { // 16个字扩展成80个字
        if (t < 16) { // 将以小端排序的明文分组存入w[0..15]
            w[t] = (block[t * 4] << 24) | (block[t * 4 + 1] << 16) | (block[t * 4 + 2] << 8) | block[t * 4 + 3];
        } else {
            w[t] = sigma_shr(w[t - 2], 1) + w[t - 7] + sigma_shr(w[t - 15], 0) + w[t - 16];
        }
    }

    for (int i = 0; i < 8; i++) {
        hash[i] = ntohl(hash[i]);
    }

    a = hash[0];
    b = hash[1];
    c = hash[2];
    d = hash[3];
    e = hash[4];
    f = hash[5];
    g = hash[6];
    h = hash[7];

    for (int i = 0; i < 64; i++) {
        t1 = h + sigma_rot(e, 1) + ch(e, f, g) + sha256_k[i] + w[i];
        t2 = sigma_rot(a, 0) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    hash[0] = a + hash[0];
    hash[1] = b + hash[1];
    hash[2] = c + hash[2];
    hash[3] = d + hash[3];
    hash[4] = e + hash[4];
    hash[5] = f + hash[5];
    hash[6] = g + hash[6];
    hash[7] = h + hash[7];

    for (int i = 0; i < 8; i++) {
        hash[i] = htonl(hash[i]);
    }
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

int sha256_hash(unsigned char* input, int len, unsigned int hash[SHA256_RESULT_SIZE]) {
    unsigned char padded_block[SHA256_BLOCK_SIZE];
    int length_in_bits = len * 8;

    hash[0] = sha1_initial_hash[0];
    hash[1] = sha1_initial_hash[1];
    hash[2] = sha1_initial_hash[2];
    hash[3] = sha1_initial_hash[3];
    hash[4] = sha1_initial_hash[4];

    while (len >= SHA256_BLOCK_SIZE) {
        sha1_block_operate(input, hash);
        len -= SHA256_BLOCK_SIZE;
        input += SHA256_BLOCK_SIZE;
    }

    memset(padded_block, 0, SHA256_BLOCK_SIZE);
    padded_block[0] = 0x80;

    if (len) {
        memcpy(padded_block, input, len);
        padded_block[len] = 0x80;
        if (len >= SHA256_INPUT_BLOCK_SIZE) {
            sha1_block_operate(padded_block, hash);
            memset(padded_block, 0, SHA256_BLOCK_SIZE);
        }
    }

    sha1_finalize(padded_block, length_in_bits);
    sha256_block_operate(padded_block, hash);

    return 0;
}

void new_sha1_digest(digest_ctx* context) {
    context->word_size = SHA1_WORD_SIZE;
    context->hash_len = SHA1_RESULT_SIZE;
    context->hash_result_len = SHA1_RESULT_SIZE;
    context->digest_block_size = SHA1_BLOCK_SIZE;
    context->digest_input_block_size = SHA1_INPUT_BLOCK_SIZE;
    context->input_len = 0;
    context->block_len = 0;
    context->hash = (unsigned int*)malloc(context->hash_len * sizeof(unsigned int));
    context->block = (unsigned char*)malloc(context->digest_block_size);
    memcpy(context->hash, sha1_initial_hash, context->hash_len * sizeof(unsigned int));
    memset(context->block, '\0', context->digest_block_size);
    context->block_operate = sha1_block_operate;
    context->block_finalize = sha1_finalize;
}

void new_sha256_digest(digest_ctx* context) {
    context->word_size = SHA256_WORD_SIZE;
    context->hash_len = SHA256_RESULT_SIZE;
    context->hash_result_len = SHA256_RESULT_SIZE;
    context->digest_block_size = SHA256_BLOCK_SIZE;
    context->digest_input_block_size = SHA256_INPUT_BLOCK_SIZE;
    context->input_len = 0;
    context->block_len = 0;
    context->hash = (unsigned int*)malloc(context->hash_len * sizeof(unsigned int));
    context->block = (unsigned char*)malloc(context->digest_block_size);
    memcpy(context->hash, sha256_initial_hash, context->hash_len * sizeof(unsigned int));
    memset(context->block, '\0', context->digest_block_size);
    context->block_operate = sha256_block_operate;
    context->block_finalize = sha1_finalize;
}

void new_sha224_digest(digest_ctx* context) {
    context->word_size = SHA256_WORD_SIZE;
    context->hash_len = SHA256_RESULT_SIZE;
    context->hash_result_len = SHA224_RESULT_SIZE;
    context->digest_block_size = SHA256_BLOCK_SIZE;
    context->digest_input_block_size = SHA256_INPUT_BLOCK_SIZE;
    context->input_len = 0;
    context->block_len = 0;
    context->hash = (unsigned int*)malloc(context->hash_len * sizeof(unsigned int));
    context->block = (unsigned char*)malloc(context->digest_block_size);
    memcpy(context->hash, sha224_initial_hash, context->hash_len * sizeof(unsigned int));
    memset(context->block, '\0', context->digest_block_size);
    context->block_operate = sha256_block_operate;
    context->block_finalize = sha1_finalize;
}
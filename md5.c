#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "md5.h"

#define BASE_T 4294967296.0

u32 md5_initial_hash[] = {
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476
};

u32 md5_initial_ti[MD5_BLOCK_SIZE] = { 0 };

u32 F(u32 X, u32 Y, u32 Z) {
    return (X & Y) | ((~X) & Z);
}

u32 G(u32 X, u32 Y, u32 Z) {
    return  (X & Z) | (Y & (~Z));
}

u32 H(u32 X, u32 Y, u32 Z) {
    return X ^ Y ^ Z;
}

u32 I(u32 X, u32 Y, u32 Z) {
    return Y ^ (X | (~Z));
}

void FF(u32* a, u32 b, u32 c, u32 d, int mi, int s, int ti) {
    u32 tmp = *a + F(b, c, d) + mi + ti;
    tmp = (tmp << s) | (tmp >> (32 - s));
    tmp += b;
    *a = tmp;
}

void GG(u32* a, u32 b, u32 c, u32 d, int mi, int s, int ti) {
    u32 tmp = *a + G(b, c, d) + mi + ti;
    tmp = (tmp << s) | (tmp >> (32 - s));
    tmp += b;
    *a = tmp;
}

void HH(u32* a, u32 b, u32 c, u32 d, int mi, int s, int ti) {
    u32 tmp = *a + H(b, c, d) + mi + ti;
    tmp = (tmp << s) | (tmp >> (32 - s));
    tmp += b;
    *a = tmp;
}

void II(u32* a, u32 b, u32 c, u32 d, int mi, int s, int ti) {
    u32 tmp = *a + I(b, c, d) + mi + ti;
    tmp = (tmp << s) | (tmp >> (32 - s));
    tmp += b;
    *a = tmp;
}

int md5_hash(const u8* input, int len, u32 hash[MD5_RESULT_SIZE]) {
    u8 padded_block[MD5_BLOCK_SIZE];
    int length_in_bits = len * 8;

    hash[0] = md5_initial_hash[0];
    hash[1] = md5_initial_hash[1];
    hash[2] = md5_initial_hash[2];
    hash[3] = md5_initial_hash[3];

    while (len >= MD5_BLOCK_SIZE) {
        md5_block_operate(input, hash);
        len -= MD5_BLOCK_SIZE;
        input += MD5_BLOCK_SIZE;
    }

    memset(padded_block, 0, MD5_BLOCK_SIZE);
    padded_block[0] = 0x80;

    if (len) {
        memcpy(padded_block, input, len);
        padded_block[len] = 0x80;
        if (len >= MD5_INPUT_BLOCK_SIZE) {
            md5_block_operate(padded_block, hash);
            memset(padded_block, 0, MD5_BLOCK_SIZE);
        }
    }

    md5_finalize(padded_block, length_in_bits);
    md5_block_operate(padded_block, hash);

    return 0;
}

void md5_block_operate(const u8* input, u32 hash[MD5_RESULT_SIZE]) {
    u32 a, b, c, d;
    u32 m[16];

    a = hash[0];
    b = hash[1];
    c = hash[2];
    d = hash[3];

    if (!md5_initial_ti[0]) { //初始化ti数组
        for (int i = 1; i <= MD5_BLOCK_SIZE; i++) {
            md5_initial_ti[i - 1] = (u32)(BASE_T * fabs(sin((double)i)));
        }
    }

    for (int i = 0; i < 16; i++) { //将以小端排序的明文分组存入u32
        m[i] = (input[i * 4 + 3] << 24) | (input[i * 4 + 2] << 16) | (input[i * 4 + 1] << 8) | input[i * 4];
    }

    // Round 1
    FF(&a, b, c, d, m[0], 7, md5_initial_ti[0]);
    FF(&d, a, b, c, m[1], 12, md5_initial_ti[1]);
    FF(&c, d, a, b, m[2], 17, md5_initial_ti[2]);
    FF(&b, c, d, a, m[3], 22, md5_initial_ti[3]);
    FF(&a, b, c, d, m[4], 7, md5_initial_ti[4]);
    FF(&d, a, b, c, m[5], 12, md5_initial_ti[5]);
    FF(&c, d, a, b, m[6], 17, md5_initial_ti[6]);
    FF(&b, c, d, a, m[7], 22, md5_initial_ti[7]);
    FF(&a, b, c, d, m[8], 7, md5_initial_ti[8]);
    FF(&d, a, b, c, m[9], 12, md5_initial_ti[9]);
    FF(&c, d, a, b, m[10], 17, md5_initial_ti[10]);
    FF(&b, c, d, a, m[11], 22, md5_initial_ti[11]);
    FF(&a, b, c, d, m[12], 7, md5_initial_ti[12]);
    FF(&d, a, b, c, m[13], 12, md5_initial_ti[13]);
    FF(&c, d, a, b, m[14], 17, md5_initial_ti[14]);
    FF(&b, c, d, a, m[15], 22, md5_initial_ti[15]);

    // Round 2
    GG(&a, b, c, d, m[1], 5, md5_initial_ti[16]);
    GG(&d, a, b, c, m[6], 9, md5_initial_ti[17]);
    GG(&c, d, a, b, m[11], 14, md5_initial_ti[18]);
    GG(&b, c, d, a, m[0], 20, md5_initial_ti[19]);
    GG(&a, b, c, d, m[5], 5, md5_initial_ti[20]);
    GG(&d, a, b, c, m[10], 9, md5_initial_ti[21]);
    GG(&c, d, a, b, m[15], 14, md5_initial_ti[22]);
    GG(&b, c, d, a, m[4], 20, md5_initial_ti[23]);
    GG(&a, b, c, d, m[9], 5, md5_initial_ti[24]);
    GG(&d, a, b, c, m[14], 9, md5_initial_ti[25]);
    GG(&c, d, a, b, m[3], 14, md5_initial_ti[26]);
    GG(&b, c, d, a, m[8], 20, md5_initial_ti[27]);
    GG(&a, b, c, d, m[13], 5, md5_initial_ti[28]);
    GG(&d, a, b, c, m[2], 9, md5_initial_ti[29]);
    GG(&c, d, a, b, m[7], 14, md5_initial_ti[30]);
    GG(&b, c, d, a, m[12], 20, md5_initial_ti[31]);

    // Round 3
    HH(&a, b, c, d, m[5], 4, md5_initial_ti[32]);
    HH(&d, a, b, c, m[8], 11, md5_initial_ti[33]);
    HH(&c, d, a, b, m[11], 16, md5_initial_ti[34]);
    HH(&b, c, d, a, m[14], 23, md5_initial_ti[35]);
    HH(&a, b, c, d, m[1], 4, md5_initial_ti[36]);
    HH(&d, a, b, c, m[4], 11, md5_initial_ti[37]);
    HH(&c, d, a, b, m[7], 16, md5_initial_ti[38]);
    HH(&b, c, d, a, m[10], 23, md5_initial_ti[39]);
    HH(&a, b, c, d, m[13], 4, md5_initial_ti[40]);
    HH(&d, a, b, c, m[0], 11, md5_initial_ti[41]);
    HH(&c, d, a, b, m[3], 16, md5_initial_ti[42]);
    HH(&b, c, d, a, m[6], 23, md5_initial_ti[43]);
    HH(&a, b, c, d, m[9], 4, md5_initial_ti[44]);
    HH(&d, a, b, c, m[12], 11, md5_initial_ti[45]);
    HH(&c, d, a, b, m[15], 16, md5_initial_ti[46]);
    HH(&b, c, d, a, m[2], 23, md5_initial_ti[47]);

    // Round 4
    II(&a, b, c, d, m[0], 6, md5_initial_ti[48]);
    II(&d, a, b, c, m[7], 10, md5_initial_ti[49]);
    II(&c, d, a, b, m[14], 15, md5_initial_ti[50]);
    II(&b, c, d, a, m[5], 21, md5_initial_ti[51]);
    II(&a, b, c, d, m[12], 6, md5_initial_ti[52]);
    II(&d, a, b, c, m[3], 10, md5_initial_ti[53]);
    II(&c, d, a, b, m[10], 15, md5_initial_ti[54]);
    II(&b, c, d, a, m[1], 21, md5_initial_ti[55]);
    II(&a, b, c, d, m[8], 6, md5_initial_ti[56]);
    II(&d, a, b, c, m[15], 10, md5_initial_ti[57]);
    II(&c, d, a, b, m[6], 15, md5_initial_ti[58]);
    II(&b, c, d, a, m[13], 21, md5_initial_ti[59]);
    II(&a, b, c, d, m[4], 6, md5_initial_ti[60]);
    II(&d, a, b, c, m[11], 10, md5_initial_ti[61]);
    II(&c, d, a, b, m[2], 15, md5_initial_ti[62]);
    II(&b, c, d, a, m[9], 21, md5_initial_ti[63]);

    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
}

// 小端排序存储真实数据长度
void md5_finalize(u8* padded_block, int length_in_bits) {
    padded_block[MD5_BLOCK_SIZE - 5] = (length_in_bits & 0xFF000000) >> 24;
    padded_block[MD5_BLOCK_SIZE - 6] = (length_in_bits & 0x00FF0000) >> 16;
    padded_block[MD5_BLOCK_SIZE - 7] = (length_in_bits & 0x0000FF00) >> 8;
    padded_block[MD5_BLOCK_SIZE - 8] = (length_in_bits & 0x000000FF);
}

void new_md5_digest(digest_ctx* context) {
    context->hash_size = MD5_RESULT_SIZE;
    context->word_size = MD5_WORD_SIZE;
    context->result_size = MD5_BYTE_SIZE;
    context->digest_block_size = MD5_BLOCK_SIZE;
    context->digest_input_block_size = MD5_INPUT_BLOCK_SIZE;
    context->input_len = 0;
    context->block_len = 0;
    context->input = NULL;
    context->hash = (void*)malloc(context->hash_size * sizeof(u32));
    context->block = (u8*)malloc(context->digest_block_size);
    memcpy(context->hash, md5_initial_hash, context->hash_size * sizeof(u32));
    memset(context->block, '\0', context->digest_block_size);
    context->block_operate = (block_operate)md5_block_operate;
    context->block_finalize = md5_finalize;
}
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "digest.h"
#include "md5.h"
#include "sha.h"
#include "hex.h"

void show_hash(unsigned int* hash, int hash_len, int word_size) {
    unsigned char* display_hash = (unsigned char*)hash;
    for (int i = 0; i < (hash_len * word_size); i++) {
        printf("%.02x", display_hash[i]);
    }
    printf("\n");
}

int digest_hash(
    unsigned char* input,
    int len,
    unsigned int* hash,
    void (*block_operate)(const unsigned char* input, unsigned int hash[]),
    void (*block_finalize)(unsigned char* block, int length),
    int digest_block_size,
    int digest_input_block_size
) {
    unsigned char padded_block[digest_block_size];
    int length_in_bits = len * 8;

    while (len >= digest_block_size) {
        block_operate(input, hash);
        len -= digest_block_size;
        input += digest_block_size;
    }

    memset(padded_block, 0, digest_block_size);
    padded_block[0] = 0x80;

    if (len) {
        memcpy(padded_block, input, len);
        padded_block[len] = 0x80;
        if (len >= digest_input_block_size) {
            block_operate(padded_block, hash);
            memset(padded_block, 0, digest_block_size);
        }
    }

    block_finalize(padded_block, length_in_bits);
    block_operate(padded_block, hash);

    return 0;
}

// 在尾部添加消息
void update_digest(digest_ctx* context, const unsigned char* input, int input_len) {
    context->input_len += input_len;

    if (context->block_len && context->block_len + input_len >= context->digest_block_size) {
        int size = context->digest_block_size - context->block_len;
        memcpy(context->block + context->block_len, input, size);
        context->block_operate(context->block, context->hash);
        memset(context->block, 0, context->digest_block_size);
        context->block_len = 0;
        input_len -= size;
        input += size;
    }

    while (input_len >= context->digest_block_size) {
        context->block_operate(input, context->hash);
        input_len -= context->digest_block_size;
        input += context->digest_block_size;
    }

    if (input_len) {
        memcpy(context->block + context->block_len, input, input_len);
        context->block_len += input_len;
    }
}

// 消息添加结束，生成最终的摘要
void finalize_digest(digest_ctx* context) {
    context->block[context->block_len] = 0x80;
    if (context->block_len >= context->digest_input_block_size) {
        context->block_operate(context->block, context->hash);
        memset(context->block, 0, context->digest_block_size);
    }
    context->block_finalize(context->block, context->input_len * 8);
    context->block_operate(context->block, context->hash);
}

// #define DIGEST_HASH
#ifdef DIGEST_HASH
void test_md5() {
    int str_len;
    unsigned int* hash;
    int hash_result_len;

    unsigned char* s[] = {
        (unsigned char*)"abc", //3
        (unsigned char*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca", //64
        (unsigned char*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca123", //67
        (unsigned char*)"abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcddddddddddddddddddddddddddddddqqqqqqqqeeee123" //123
    };
    hash_result_len = MD5_RESULT_SIZE;
    for (int i = 0; i < 4; i++) {
        hash = malloc(sizeof(int) * MD5_RESULT_SIZE);
        str_len = (int)strlen((const char*)(s[i]));
        memcpy(hash, md5_initial_hash, sizeof(int) * MD5_RESULT_SIZE);
        digest_hash(s[i], str_len, hash, md5_block_operate, md5_finalize, MD5_BLOCK_SIZE, MD5_INPUT_BLOCK_SIZE);
        printf("str_len=%d\n", str_len);
        show_hash(hash, hash_result_len, 4);
    }
}

void test_sha1() {
    int str_len;
    unsigned int* hash;
    int hash_result_len;

    unsigned char* s[] = {
        (unsigned char*)"abc",
        (unsigned char*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca",
        (unsigned char*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca123",
        (unsigned char*)"abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcddddddddddddddddddddddddddddddqqqqqqqqeeee123"
    };
    hash_result_len = SHA1_RESULT_SIZE;
    for (int i = 0; i < 4; i++) {
        hash = malloc(sizeof(int) * SHA1_RESULT_SIZE);
        str_len = (int)strlen((const char*)(s[i]));
        memcpy(hash, sha1_initial_hash, sizeof(int) * SHA1_RESULT_SIZE);
        digest_hash(s[i], str_len, hash, sha1_block_operate, sha1_finalize, SHA1_BLOCK_SIZE, SHA1_INPUT_BLOCK_SIZE);
        printf("str_len=%d\n", str_len);
        show_hash(hash, hash_result_len, 4);
    }
}

void test_sha224() {
    int str_len;
    unsigned int* hash;
    int hash_result_len;

    unsigned char* s[] = {
        (unsigned char*)"abc",
        (unsigned char*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca",
        (unsigned char*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca123",
        (unsigned char*)"abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcddddddddddddddddddddddddddddddqqqqqqqqeeee123"
    };
    hash_result_len = SHA224_RESULT_SIZE;
    for (int i = 0; i < 4; i++) {
        hash = malloc(sizeof(int) * SHA256_RESULT_SIZE);
        str_len = (int)strlen((const char*)(s[i]));
        memcpy(hash, sha224_initial_hash, sizeof(int) * SHA256_RESULT_SIZE);
        digest_hash(s[i], str_len, hash, sha256_block_operate, sha1_finalize, SHA256_BLOCK_SIZE, SHA256_INPUT_BLOCK_SIZE);
        printf("str_len=%d\n", str_len);
        show_hash(hash, hash_result_len, 4);
    }
}

void test_sha256() {
    int str_len;
    unsigned int* hash;
    int hash_result_len;

    unsigned char* s[] = {
        (unsigned char*)"abc",
        (unsigned char*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca",
        (unsigned char*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca123",
        (unsigned char*)"abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcddddddddddddddddddddddddddddddqqqqqqqqeeee123"
    };
    hash_result_len = SHA256_RESULT_SIZE;
    for (int i = 0; i < 4; i++) {
        hash = malloc(sizeof(int) * SHA256_RESULT_SIZE);
        str_len = (int)strlen((const char*)(s[i]));
        memcpy(hash, sha256_initial_hash, sizeof(int) * SHA256_RESULT_SIZE);
        digest_hash(s[i], str_len, hash, sha256_block_operate, sha1_finalize, SHA256_BLOCK_SIZE, SHA256_INPUT_BLOCK_SIZE);
        printf("str_len=%d\n", str_len);
        show_hash(hash, hash_result_len, 4);
    }
}

void test_update() {
    digest_ctx ctx;

    // new_md5_digest(&ctx);
    // new_sha1_digest(&ctx);
    new_sha256_digest(&ctx);
    update_digest(&ctx, (unsigned char*)"abc", 3);
    finalize_digest(&ctx);
    show_hash(ctx.hash, ctx.hash_result_len, ctx.word_size);

    // new_md5_digest(&ctx);
    // new_sha1_digest(&ctx);
    new_sha256_digest(&ctx);
    update_digest(&ctx, (unsigned char*)"abcabcabcabcabcaabcabcabcabcabca", 32);
    update_digest(&ctx, (unsigned char*)"abcabcabcabcabcaabcabcabcabcabca", 32);
    finalize_digest(&ctx);
    show_hash(ctx.hash, ctx.hash_result_len, ctx.word_size);

    // new_md5_digest(&ctx);
    // new_sha1_digest(&ctx);
    new_sha256_digest(&ctx);
    update_digest(&ctx, (unsigned char*)"abcabcabcabcabcaabcabcabcabcabca", 32);
    update_digest(&ctx, (unsigned char*)"abcabcabcabcabcaabcabcabcabcabca", 32);
    update_digest(&ctx, (unsigned char*)"123", 3);
    finalize_digest(&ctx);
    show_hash(ctx.hash, ctx.hash_result_len, ctx.word_size);

    // new_md5_digest(&ctx);
    // new_sha1_digest(&ctx);
    new_sha256_digest(&ctx);
    update_digest(&ctx, (unsigned char*)"abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabca", 64);
    update_digest(&ctx, (unsigned char*)"bcabcabcabcabcddddddddddddddddddddddddddddddqqqqqqqqeeee123", 59);
    finalize_digest(&ctx);
    show_hash(ctx.hash, ctx.hash_result_len, ctx.word_size);
}

int main() {
    printf("\ntest_md5:\n");
    test_md5();
    printf("\ntest_sha1:\n");
    test_sha1();
    printf("\ntest_sha224:\n");
    test_sha224();
    printf("\ntest_sha256:\n");
    test_sha256();
    printf("\ntest_update:\n");
    test_update();
    return 0;
}
#endif
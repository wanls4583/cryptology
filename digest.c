#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "digest.h"
#include "md5.h"
#include "sha.h"
#include "hex.h"

void show_hash(void* hash, int result_size) {
    u8* display_hash = (u8*)hash;
    for (int i = 0; i < result_size; i++) {
        printf("%.02x", display_hash[i]);
    }
    printf("\n");
}

int digest_hash(digest_ctx* context, u8* input, int len) {
    u8* padded_block = (u8*)malloc(context->digest_block_size);
    int length_in_bits = len * 8;

    while (len >= context->digest_block_size) {
        context->block_operate(input, context->hash);
        len -= context->digest_block_size;
        input += context->digest_block_size;
    }

    memset(padded_block, 0, context->digest_block_size);
    padded_block[0] = 0x80;

    if (len) {
        memcpy(padded_block, input, len);
        padded_block[len] = 0x80;
        if (len >= context->digest_input_block_size) {
            context->block_operate(padded_block, context->hash);
            memset(padded_block, 0, context->digest_block_size);
        }
    }

    context->block_finalize(padded_block, length_in_bits);
    context->block_operate(padded_block, context->hash);

    return 0;
}

// 在尾部添加消息
void update_digest(digest_ctx* context, u8* input, int input_len) {
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
    digest_ctx ctx;

    u8* s[] = {
        (u8*)"abc",
        (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca",
        (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca123",
        (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca"
    };
    for (int i = 0; i < 4; i++) {
        int str_len = (int)strlen((const char*)(s[i]));
        new_md5_digest(&ctx);
        digest_hash(&ctx, s[i], str_len);
        show_hash(ctx.hash, ctx.result_size);
    }
}

void test_sha1() {
    digest_ctx ctx;

    u8* s[] = {
        (u8*)"abc",
        (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca",
        (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca123",
        (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca"
    };
    for (int i = 0; i < 4; i++) {
        int str_len = (int)strlen((const char*)(s[i]));
        new_sha1_digest(&ctx);
        digest_hash(&ctx, s[i], str_len);
        show_hash(ctx.hash, ctx.result_size);
    }
}

void test_sha224() {
    digest_ctx ctx;

    u8* s[] = {
        (u8*)"abc",
        (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca",
        (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca123",
        (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca"
    };
    for (int i = 0; i < 4; i++) {
        int str_len = (int)strlen((const char*)(s[i]));
        new_sha224_digest(&ctx);
        digest_hash(&ctx, s[i], str_len);
        show_hash(ctx.hash, ctx.result_size);
    }
}

void test_sha256() {
    digest_ctx ctx;

    u8* s[] = {
        (u8*)"abc",
        (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca",
        (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca123",
        (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca"
    };
    for (int i = 0; i < 4; i++) {
        int str_len = (int)strlen((const char*)(s[i]));
        new_sha256_digest(&ctx);
        digest_hash(&ctx, s[i], str_len);
        show_hash(ctx.hash, ctx.result_size);
    }
}

void test_sha384() {
    digest_ctx ctx;
    u8* s[] = {
        (u8*)"abc",
        (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca",
        (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca123",
        (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca"
    };
    for (int i = 0; i < 4; i++) {
        int str_len = (int)strlen((const char*)(s[i]));
        new_sha384_digest(&ctx);
        digest_hash(&ctx, s[i], str_len);
        show_hash(ctx.hash, ctx.result_size);
    }
}


void test_sha512_224() {
    digest_ctx ctx;

    u8* s[] = {
        (u8*)"abc",
        (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca",
        (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca123",
        (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca"
    };
    for (int i = 0; i < 4; i++) {
        int str_len = (int)strlen((const char*)(s[i]));
        new_sha512_224_digest(&ctx);
        digest_hash(&ctx, s[i], str_len);
        show_hash(ctx.hash, ctx.result_size);
    }
}

void test_sha512_256() {
    digest_ctx ctx;

    u8* s[] = {
        (u8*)"abc",
        (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca",
        (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca123",
        (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca"
    };
    for (int i = 0; i < 4; i++) {
        int str_len = (int)strlen((const char*)(s[i]));
        new_sha512_256_digest(&ctx);
        digest_hash(&ctx, s[i], str_len);
        show_hash(ctx.hash, ctx.result_size);
    }
}

void test_sha512() {
    digest_ctx ctx;

    u8* s[] = {
        (u8*)"abc",
        (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca",
        (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca123",
        (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca"
    };
    for (int i = 0; i < 4; i++) {
        int str_len = (int)strlen((const char*)(s[i]));
        new_sha512_digest(&ctx);
        digest_hash(&ctx, s[i], str_len);
        show_hash(ctx.hash, ctx.result_size);
    }
}

void test_update() {
    digest_ctx ctx;

    // new_md5_digest(&ctx);
    // new_sha1_digest(&ctx);
    // new_sha224_digest(&ctx);
    // new_sha256_digest(&ctx);
    // new_sha384_digest(&ctx);
    // new_sha512_224_digest(&ctx);
    // new_sha512_256_digest(&ctx);
    new_sha512_digest(&ctx);
    update_digest(&ctx, (u8*)"abc", 3);
    finalize_digest(&ctx);
    show_hash(ctx.hash, ctx.result_size);

    // new_md5_digest(&ctx);
    // new_sha1_digest(&ctx);
    // new_sha224_digest(&ctx);
    // new_sha256_digest(&ctx);
    // new_sha384_digest(&ctx);
    // new_sha512_224_digest(&ctx);
    // new_sha512_256_digest(&ctx);
    new_sha512_digest(&ctx);
    update_digest(&ctx, (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca", 64);
    update_digest(&ctx, (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca", 64);
    finalize_digest(&ctx);
    show_hash(ctx.hash, ctx.result_size);

    // new_md5_digest(&ctx);
    // new_sha1_digest(&ctx);
    // new_sha224_digest(&ctx);
    // new_sha256_digest(&ctx);
    // new_sha384_digest(&ctx);
    // new_sha512_224_digest(&ctx);
    // new_sha512_256_digest(&ctx);
    new_sha512_digest(&ctx);
    update_digest(&ctx, (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca", 64);
    update_digest(&ctx, (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca", 64);
    update_digest(&ctx, (u8*)"123", 3);
    finalize_digest(&ctx);
    show_hash(ctx.hash, ctx.result_size);

    // new_md5_digest(&ctx);
    // new_sha1_digest(&ctx);
    // new_sha224_digest(&ctx);
    // new_sha256_digest(&ctx);
    // new_sha384_digest(&ctx);
    // new_sha512_224_digest(&ctx);
    // new_sha512_256_digest(&ctx);
    new_sha512_digest(&ctx);
    update_digest(&ctx, (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca", 64);
    update_digest(&ctx, (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca", 64);
    update_digest(&ctx, (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca", 64);
    update_digest(&ctx, (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca", 48);
    finalize_digest(&ctx);
    show_hash(ctx.hash, ctx.result_size);
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
    printf("\ntest_sha384:\n");
    test_sha384();
    printf("\ntest_sha512_224:\n");
    test_sha512_224();
    printf("\ntest_sha512_256:\n");
    test_sha512_256();
    printf("\ntest_sha512:\n");
    test_sha512();
    printf("\ntest_update:\n");
    test_update();
    return 0;
}
#endif
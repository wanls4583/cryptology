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

    context->input = (unsigned char*)malloc(len);
    memcpy(context->input, input, len);

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
    context->input = (u8*)realloc(context->input, context->input_len + input_len);
    memcpy(context->input + context->input_len, input, input_len);
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

void copy_digest(digest_ctx* target, digest_ctx* src) {
    memcpy(target, src, sizeof(digest_ctx));
    target->hash = (void*)malloc(src->hash_size * src->word_size);
    target->block = (unsigned char*)malloc(src->digest_block_size);
    target->input = (unsigned char*)malloc(src->input_len);
    memcpy(target->hash, src->hash, src->hash_size * src->word_size);
    memcpy(target->block, src->block, src->digest_block_size);
    memcpy(target->input, src->input, src->input_len);
}

void free_digest(digest_ctx* ctx) {
    free(ctx->hash);
    free(ctx->block);
    free(ctx->input);
}

// #define TEST_DIGEST
#ifdef TEST_DIGEST
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
    // printf("\ntest_md5:\n");
    // test_md5();
    // printf("\ntest_sha1:\n");
    // test_sha1();
    // printf("\ntest_sha224:\n");
    // test_sha224();
    // printf("\ntest_sha256:\n");
    // test_sha256();
    // printf("\ntest_sha384:\n");
    // test_sha384();
    // printf("\ntest_sha512_224:\n");
    // test_sha512_224();
    // printf("\ntest_sha512_256:\n");
    // test_sha512_256();
    // printf("\ntest_sha512:\n");
    // test_sha512();
    // printf("\ntest_update:\n");
    // test_update();

    digest_ctx ctx;
    unsigned char* input;
    int input_len = 0;

    new_md5_digest(&ctx);

    input_len = hex_decode("0x010001360303afb304bdb873d3014085202e20b72dd282303efd0e943a1a8a699038dfcb0ea82040364d37c3eea52698bc3fc263b7aeb2891c1da4358b534dfd5cb34c7f8ed9e30062130213031301c030c02cc028c024c014c00a009f006b0039cca9cca8ccaaff8500c400880081009d003d003500c00084c02fc02bc027c023c013c009009e0067003300be0045009c003c002f00ba0041c011c00700050004c012c0080016000a00ff0100008b002b0009080304030303020301003300260024001d0020b440369294b7f345f36d0ebcdcca2372fda82678b18bcbfd79a01b5f4377b3320000000e000c0000096c6f63616c686f7374000b00020100000a000a0008001d001700180019000d00180016080606010603080505010503080404010403020102030010000e000c02683208687474702f312e31", &input);
    update_digest(&ctx, input, input_len);
    show_hex(ctx.hash, ctx.result_size, 1);

    input_len = hex_decode("0x0200002603019571ab650000000000000000000000000000000000000000000000000000000000003500", &input);
    update_digest(&ctx, input, input_len);
    show_hex(ctx.hash, ctx.result_size, 1);

    input_len = hex_decode("0x0b0003470003440003413082033d308202e7a003020102020900d3defeac27e3ef5d300d06092a864886f70d010105050030819d310b3009060355040613025553310b30090603550408130254583112301006035504071309536f7574686c616b6531143012060355040a130b54726176656c6f6369747931153013060355040b130c41726368697465637475726531123010060355040313096c6f63616c686f7374312c302a06092a864886f70d010901161d6a6f736875612e6461766965734074726176656c6f636974792e636f6d301e170d3130303830363230333732325a170d3130303930353230333732325a30819d310b3009060355040613025553310b30090603550408130254583112301006035504071309536f7574686c616b6531143012060355040a130b54726176656c6f6369747931153013060355040b130c41726368697465637475726531123010060355040313096c6f63616c686f7374312c302a06092a864886f70d010901161d6a6f736875612e6461766965734074726176656c6f636974792e636f6d305c300d06092a864886f70d0101010500034b003048024100b216d03a572ffe992857f57447162b1cad2ac8048450cca85b53aac2bdca1e8ae89b9477b4047e17189be7c7f93823c84083756f44376a99d48104d6b16eb22f0203010001a382010630820102301d0603551d0e0416041467900edcfed5c87f18c21e42cf97a32e5ae86aec3081d20603551d230481ca3081c7801467900edcfed5c87f18c21e42cf97a32e5ae86aeca181a3a481a030819d310b3009060355040613025553310b30090603550408130254583112301006035504071309536f7574686c616b6531143012060355040a130b54726176656c6f6369747931153013060355040b130c41726368697465637475726531123010060355040313096c6f63616c686f7374312c302a06092a864886f70d010901161d6a6f736875612e6461766965734074726176656c6f636974792e636f6d820900d3defeac27e3ef5d300c0603551d13040530030101ff300d06092a864886f70d01010505000341002e02f919d19067aabcadf39930f8d78b2dc57029a92dd9498f760635419f65bd39f874eb96d0c763d8cd71d7421392a13261a43802e5be64c3b91f4568bf38a8", &input);
    update_digest(&ctx, input, input_len);
    show_hex(ctx.hash, ctx.result_size, 1);

    input_len = hex_decode("0x0e000000", &input);
    update_digest(&ctx, input, input_len);
    show_hex(ctx.hash, ctx.result_size, 1);

    input_len = hex_decode("0x1000004200409a7b1cb63fdd2ae70b4fbddcaba21cec391453ab018b3c01ed7be0b8a4ee15d8bf1bd998ff8534b7e7d3f7c682e6f3bed4fe9ec621f8f0bd94da4416d82e3e01", &input);
    update_digest(&ctx, input, input_len);
    show_hex(ctx.hash, ctx.result_size, 1);

    input_len = hex_decode("0x1400000cf67d7aa0ed8dd19c7ddfe48d", &input);
    update_digest(&ctx, input, input_len);
    show_hex(ctx.hash, ctx.result_size, 1);

    return 0;
}
#endif
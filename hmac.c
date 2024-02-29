#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "hmac.h"
#include "md5.h"
#include "sha.h"
#include "hex.h"

void hmac(
    digest_ctx* digest,
    u8* key,
    int key_length,
    u8* text,
    int text_length
) {
    int block_size = digest->digest_block_size;
    u8* tmp;
    u8* key_block = (u8*)malloc(block_size);
    u8* opad = (u8*)malloc(block_size);
    u8* ipad = (u8*)malloc(block_size);
    digest_ctx* ctx = (digest_ctx*)malloc(sizeof(digest_ctx));

    memset(key_block, 0, block_size);
    memset(opad, 0, block_size);
    memset(ipad, 0, block_size);

    if (key_length > block_size) {
        copy_digest(ctx, digest);
        digest_hash(ctx, key, key_length);
        memcpy(key_block, (u8*)ctx->hash, digest->result_size);

        free(ctx->hash);
        free(ctx->block);
    } else {
        memcpy(key_block, key, key_length);
    }

    for (int i = 0; i < block_size; i++) {
        opad[i] = key_block[i] ^ 0x5c;
        ipad[i] = key_block[i] ^ 0x36;
    }

    copy_digest(ctx, digest);

    // hash(i_key_pad ∥ message)
    tmp = (u8*)malloc(block_size + text_length);
    memcpy(tmp, ipad, block_size);
    memcpy(tmp + block_size, text, text_length);
    digest_hash(ctx, tmp, block_size + text_length);
    free(tmp);

    // hash(o_key_pad ∥ hash(i_key_pad ∥ message))
    tmp = (u8*)malloc(block_size + digest->result_size);
    memcpy(tmp, opad, block_size);
    memcpy(tmp + block_size, (u8*)ctx->hash, digest->result_size);
    digest_hash(digest, tmp, block_size + digest->result_size);

    free(ctx->hash);
    free(ctx->block);
    free(tmp);
}

// #define TEST_HMAC
#ifdef TEST_HMAC
int main() {
    digest_ctx digest;

    new_md5_digest(&digest);
    hmac(&digest, (u8*)"abc", 3, (u8*)"what do ya want for nothing?", 28);
    // ced92d99bf2861dce9f56f7354824832
    show_hash(digest.hash, digest.result_size);

    new_md5_digest(&digest);
    hmac(&digest, (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca123", 131, (u8*)"what do ya want for nothing?", 28);
    // 486cdce44b0cda3446be1f76fdb8d192
    show_hash(digest.hash, digest.result_size);

    new_sha1_digest(&digest);
    hmac(&digest, (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca123", 131, (u8*)"what do ya want for nothing?", 28);
    // a0ba15a9c8627ecadaa625354c2349e52fcf9c60
    show_hash(digest.hash, digest.result_size);

    new_sha256_digest(&digest);
    hmac(&digest, (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca123", 131, (u8*)"what do ya want for nothing?", 28);
    // 8e0b82b6b38d4bede5803251ec4459a9b73cb4323b1be130d1eb966a9289ee76
    show_hash(digest.hash, digest.result_size);

    new_sha512_digest(&digest);
    hmac(&digest, (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca123", 131, (u8*)"what do ya want for nothing?", 28);
    // 61245a4b6c907145ab65a0eee63b90e2d31ffb766b848db876ca12bdbd068e0ff6313faf2ed6c18418dcd8d8da672799b33a77d57644a0db92c1b8d825928f56
    show_hash(digest.hash, digest.result_size);

    new_sha384_digest(&digest);
    unsigned char *key;
    unsigned char *input;
    int key_len = hex_decode((unsigned char*)"0x7ee8206f5570023e6dc7519eb1073bc4e791ad37b5c382aa10ba18e2357e716971f9362f2c2fe2a76bfd78dfec4ea9b5", &key);
    int input_len = hex_decode((unsigned char*)"0x00300d746c73313320646572697665643038b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b01", &input);
    hmac(&digest, key, key_len, input, input_len);
    // 1591dac5cbbf0330a4a84de9c753330e92d01f0a88214b4464972fd668049e93e52f2b16fad922fdc0584478428f282b
    show_hash(digest.hash, digest.result_size);


    return 0;
}
#endif
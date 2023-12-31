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
        // copy digest
        memcpy(ctx, digest, sizeof(digest_ctx));
        ctx->hash = (void*)malloc(digest->hash_size * digest->word_size);
        ctx->block = (u8*)malloc(block_size);
        memcpy(ctx->hash, digest->hash, digest->hash_size * digest->word_size);
        memset(ctx->block, 0, block_size);

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

    // copy digest
    memcpy(ctx, digest, sizeof(digest_ctx));
    ctx->hash = (void*)malloc(digest->hash_size * digest->word_size);
    ctx->block = (u8*)malloc(block_size);
    memcpy(ctx->hash, digest->hash, digest->hash_size * digest->word_size);
    memset(ctx->block, 0, block_size);

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
    show_hash(digest.hash, digest.result_size);

    new_md5_digest(&digest);
    hmac(&digest, (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca123", 131, (u8*)"what do ya want for nothing?", 28);
    show_hash(digest.hash, digest.result_size);

    new_sha1_digest(&digest);
    hmac(&digest, (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca123", 131, (u8*)"what do ya want for nothing?", 28);
    show_hash(digest.hash, digest.result_size);

    new_sha256_digest(&digest);
    hmac(&digest, (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca123", 131, (u8*)"what do ya want for nothing?", 28);
    show_hash(digest.hash, digest.result_size);

    new_sha512_digest(&digest);
    hmac(&digest, (u8*)"abcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabcaabcabcabcabcabca123", 131, (u8*)"what do ya want for nothing?", 28);
    show_hash(digest.hash, digest.result_size);

    return 0;
}
#endif
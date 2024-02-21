#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "hkdf.h"
#include "sha.h"
#include "hmac.h"
#include "hex.h"

void HKDF_extract(
    unsigned char* salt, int salt_len,
    unsigned char* key, int key_len,
    unsigned char* PRK
) {
    digest_ctx ctx;
    new_sha256_digest(&ctx);
    hmac(&ctx, salt, salt_len, key, key_len);
    memcpy(PRK, ctx.hash, ctx.result_size);
    free_digest(&ctx);

    printf("PRK:");
    show_hex(PRK, ctx.result_size, 1);
}

void HKDF_expand(
    unsigned char* key, int key_len,
    unsigned char* info, int info_len,
    unsigned char* out, int out_len
) {
    digest_ctx ctx, tmp;
    new_sha256_digest(&ctx);
    new_sha256_digest(&tmp);

    unsigned char T[ctx.result_size];
    unsigned char data[ctx.result_size + info_len + 1];
    unsigned char* buffer;

    memset(T, 0, ctx.result_size);
    memset(data, 0, ctx.result_size + info_len + 1);

    int i = 1;
    while (out_len > 0) {
        copy_digest(&ctx, &tmp);
        buffer = data;
        if (i > 1) {
            memcpy(data, T, ctx.result_size);
            buffer += ctx.result_size;
        }
        memcpy(buffer, info, info_len);
        buffer += info_len;
        buffer[0] = i;
        buffer += 1;

        hmac(&ctx, key, key_len, data, (int)(buffer - data));
        memcpy(T, ctx.hash, ctx.result_size);
        memcpy(out, T, out_len > ctx.result_size ? ctx.result_size : out_len);
        out += ctx.result_size;
        out_len -= ctx.result_size;
        i++;
    }

    free_digest(&ctx);
    free_digest(&tmp);
}

// HKDF-Expand-Label(Secret, Label, Context, Length) = HKDF-Expand(Secret, HkdfLabel, Length)
// Where HkdfLabel is specified as:
// struct {
//     uint16 length = Length;
//     opaque label<7..255> = "tls13 " + Label;
//     opaque context<0..255> = Context;
// } HkdfLabel;
void HKDF_expand_label(
    unsigned char* secret, int secret_len,
    unsigned char* label, int label_len,
    unsigned char* context, int context_len,
    unsigned char* out, int out_len
) {
    int hkdf_label_len = 2 + 1 + 6 + label_len + 1 + context_len;
    unsigned char hkdf_Label[hkdf_label_len];
    unsigned char* buffer = hkdf_Label;
    int s_len = htons(out_len);

    memcpy(buffer, &s_len, 2);
    buffer += 2;
    buffer[0] = 6 + label_len;
    buffer += 1;
    memcpy(buffer, (void*)"tls13 ", 6);
    buffer += 6;
    memcpy(buffer, label, label_len);
    buffer += label_len;
    buffer[0] = context_len;
    buffer += 1;
    memcpy(buffer, context, context_len);

    HKDF_expand(secret, secret_len, hkdf_Label, hkdf_label_len, out, out_len);
}

void derive_secret(
    unsigned char* secret, int secret_len,
    unsigned char* label, int label_len,
    unsigned char* message, int message_len,
    unsigned char* out, int out_len,
    digest_ctx* ctx
) {
    digest_hash(ctx, message, message_len);
    HKDF_expand_label(secret, secret_len, label, label_len, ctx->hash, ctx->result_size, out, out_len);
}

void HKDF(
    unsigned char* key, int key_len,
    unsigned char* salt, int salt_len,
    unsigned char* info, int info_len,
    unsigned char* out, int out_len
) {
    unsigned char PRK[SHA256_BYTE_SIZE];

    HKDF_extract(salt, salt_len, key, key_len, PRK);
    HKDF_expand(PRK, sizeof(PRK), info, info_len, out, out_len);
}

// #define TEST_HKDF
#ifdef TEST_HKDF
int main() {
    unsigned char* key, * salt, * info;
    unsigned char out[1000];
    int key_len, salt_len, info_len;

    key_len = hex_decode((unsigned char*)"0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", &key);
    salt_len = hex_decode((unsigned char*)"0x000102030405060708090a0b0c", &salt);
    info_len = hex_decode((unsigned char*)"0xf0f1f2f3f4f5f6f7f8f9", &info);

    HKDF(key, key_len, salt, salt_len, info, info_len, out, 42);
    // 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
    show_hex(out, 42, 1);

    key_len = hex_decode((unsigned char*)"0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f", &key);
    salt_len = hex_decode((unsigned char*)"0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf", &salt);
    info_len = hex_decode((unsigned char*)"0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", &info);

    HKDF(key, key_len, salt, salt_len, info, info_len, out, 82);
    // b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87
    show_hex(out, 82, 1);

    key_len = hex_decode((unsigned char*)"0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", &key);

    HKDF(key, key_len, NULL, 0, NULL, 0, out, 42);
    // 8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8
    show_hex(out, 42, 1);

    return 0;
}
#endif
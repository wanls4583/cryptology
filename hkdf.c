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
    unsigned char* PRK,
    digest_ctx ctx
) {
    digest_ctx tmp;
    copy_digest(&tmp, &ctx);

    hmac(&tmp, salt, salt_len, key, key_len);
    memcpy(PRK, tmp.hash, tmp.result_size);
    free_digest(&tmp);

    // printf("PRK:");
    // show_hex(PRK, tmp.result_size, 1);
}

void HKDF_expand(
    unsigned char* key, int key_len,
    unsigned char* info, int info_len,
    unsigned char* out, int out_len,
    digest_ctx ctx
) {
    digest_ctx tmp;

    unsigned char T[ctx.result_size];
    unsigned char data[ctx.result_size + info_len + 1];
    unsigned char* buffer;

    memset(T, 0, ctx.result_size);
    memset(data, 0, ctx.result_size + info_len + 1);

    int i = 1;
    while (out_len > 0) {
        copy_digest(&tmp, &ctx);
        buffer = data;
        if (i > 1) {
            memcpy(data, T, ctx.result_size);
            buffer += ctx.result_size;
        }
        memcpy(buffer, info, info_len);
        buffer += info_len;
        buffer[0] = i;
        buffer += 1;

        hmac(&tmp, key, key_len, data, (int)(buffer - data));
        memcpy(T, tmp.hash, ctx.result_size);
        memcpy(out, T, out_len > ctx.result_size ? ctx.result_size : out_len);
        out += ctx.result_size;
        out_len -= ctx.result_size;
        i++;
    }

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
    unsigned char* out, int out_len,
    digest_ctx ctx
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

    HKDF_expand(secret, secret_len, hkdf_Label, hkdf_label_len, out, out_len, ctx);
}

void derive_secret(
    unsigned char* secret, int secret_len,
    unsigned char* label, int label_len,
    unsigned char* message, int message_len,
    unsigned char* out, int out_len,
    digest_ctx ctx
) {
    digest_ctx tmp;
    copy_digest(&tmp, &ctx);

    digest_hash(&tmp, message, message_len);
    HKDF_expand_label(secret, secret_len, label, label_len, tmp.hash, tmp.result_size, out, out_len, tmp);

    free_digest(&tmp);
}

void HKDF(
    unsigned char* key, int key_len,
    unsigned char* salt, int salt_len,
    unsigned char* info, int info_len,
    unsigned char* out, int out_len,
    digest_ctx ctx
) {
    unsigned char PRK[ctx.result_size];

    HKDF_extract(salt, salt_len, key, key_len, PRK, ctx);
    HKDF_expand(PRK, sizeof(PRK), info, info_len, out, out_len, ctx);
}

#define TEST_HKDF
#ifdef TEST_HKDF
#include "digest.h"
#include "sha.h"

void test1() {
    unsigned char* key, * salt, * info;
    unsigned char out[1000];
    int key_len, salt_len, info_len;
    digest_ctx ctx;
    new_sha256_digest(&ctx);

    key_len = hex_decode((unsigned char*)"0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", &key);
    salt_len = hex_decode((unsigned char*)"0x000102030405060708090a0b0c", &salt);
    info_len = hex_decode((unsigned char*)"0xf0f1f2f3f4f5f6f7f8f9", &info);

    HKDF(key, key_len, salt, salt_len, info, info_len, out, 42, ctx);
    // 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
    show_hex(out, 42, 1);

    key_len = hex_decode((unsigned char*)"0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f", &key);
    salt_len = hex_decode((unsigned char*)"0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf", &salt);
    info_len = hex_decode((unsigned char*)"0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", &info);

    HKDF(key, key_len, salt, salt_len, info, info_len, out, 82, ctx);
    // b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87
    show_hex(out, 82, 1);

    key_len = hex_decode((unsigned char*)"0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", &key);

    HKDF(key, key_len, NULL, 0, NULL, 0, out, 42, ctx);
    // 8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8
    show_hex(out, 42, 1);
}

void test2() {
    int len = 0;
    unsigned char* tmp;
    digest_ctx ctx;

    new_sha384_digest(&ctx);

    len = hex_decode((unsigned char*)"0x010000f40303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000813021303130100ff010000a30000001800160000136578616d706c652e756c666865696d2e6e6574000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000016000000170000000d001e001c040305030603080708080809080a080b080408050806040105010601002b0003020304002d00020101003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254", &tmp);
    update_digest(&ctx, tmp, len);
    len = hex_decode((unsigned char*)"0x020000760303707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff130200002e002b0002030400330024001d00209fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615", &tmp);
    update_digest(&ctx, tmp, len);
    finalize_digest(&ctx);
    // e05f64fcd082bdb0dce473adf669c2769f257a1c75a51b7887468b5e0e7a7de4f4d34555112077f16e079019d5a845bd
    // show_hex(ctx.hash, ctx.result_size, 1);


    unsigned char* shared_secret;
    unsigned char zero_key[ctx.result_size];
    unsigned char early_secret[ctx.result_size];
    unsigned char empty_hash[ctx.result_size];
    unsigned char derived_secret[48];
    unsigned char handshake_secret[ctx.result_size];

    len = hex_decode((unsigned char*)"0xdf4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624", &shared_secret);
    memset(zero_key, 0, ctx.result_size);

    new_sha384_digest(&ctx);
    HKDF_extract(NULL, 0, zero_key, ctx.result_size, early_secret, ctx);
    printf("early_secret:");
    show_hex(early_secret, ctx.result_size, 1);

    digest_hash(&ctx, NULL, 0);
    memcpy(empty_hash, ctx.hash, ctx.result_size);
    printf("empty_hash:");
    show_hex(empty_hash, ctx.result_size, 1);

    HKDF_expand_label(early_secret, sizeof(early_secret), (unsigned char*)"derived", 7, empty_hash, sizeof(empty_hash), derived_secret, sizeof(derived_secret), ctx);
    // 1591dac5cbbf0330a4a84de9c753330e92d01f0a88214b4464972fd668049e93e52f2b16fad922fdc0584478428f282b
    printf("derived_secret:");
    show_hex(derived_secret, 48, 1);

    HKDF_extract(derived_secret, sizeof(derived_secret), shared_secret, len, handshake_secret, ctx);
    printf("handshake_secret:");
    show_hex(handshake_secret, ctx.result_size, 1);

}

int main() {
    // test1();
    test2();

    return 0;
}
#endif
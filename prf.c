#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "digest.h"
#include "hex.h"
#include "hmac.h"
#include "md5.h"
#include "sha.h"
#include "prf.h"

/**
 * P_MD5 or P_SHA, depending on the value of the �new_digest� function
 * pointer.
 * HMAC_hash( secret, A(1) + seed ) + HMAC_hash( secret, A(2) + seed ) + ...
 * where + indicates concatenation and A(0) = seed, A(i) =
 * HMAC_hash( secret, A(i - 1) )
 */
static void P_hash(
    unsigned char* secret,
    int secret_len,
    unsigned char* seed,
    int seed_len,
    unsigned char* output,
    int out_len,
    void (*new_digest)(digest_ctx* context)
) {
    digest_ctx A_ctx, h;
    unsigned char* A;
    int hash_len = 0;
    new_digest(&A_ctx);
    hmac(&A_ctx, secret, secret_len, seed, seed_len);

    A = (unsigned char*)malloc(A_ctx.result_size + seed_len);
    memcpy(A, (unsigned char*)A_ctx.hash, A_ctx.result_size);
    memcpy(A + A_ctx.result_size, seed, seed_len);

    while (out_len > 0) {
        new_digest(&h);
        hmac(&h, secret, secret_len, A, h.result_size + seed_len);

        int size = h.result_size > out_len ? out_len : h.result_size;
        memcpy(output, (unsigned char*)h.hash, size);
        output += size;
        out_len -= size;

        new_digest(&A_ctx);
        hmac(&A_ctx, secret, secret_len, A, A_ctx.result_size);
        memcpy(A, (unsigned char*)A_ctx.hash, A_ctx.result_size);
    }

    free(A);
}

/**
 * P_MD5( S1, label + seed ) XOR P_SHA1(S2, label + seed );
 * where S1 & S2 are the first & last half of secret
 * and label is an ASCII string.  Ignore the null terminator.
 *
 * output must already be allocated.
 */
void PRF(
    unsigned char* secret,
    int secret_len,
    unsigned char* label,
    int label_len,
    unsigned char* seed,
    int seed_len,
    unsigned char* output,
    int out_len
) {
    int half_secret_len = secret_len / 2 + secret_len % 2;
    unsigned char concat[label_len + seed_len];
    unsigned char sha1[out_len];

    memcpy(concat, label, label_len);
    memcpy(concat + label_len, seed, seed_len);

    P_hash(secret, half_secret_len, concat, label_len + seed_len, output, out_len, new_md5_digest);
    P_hash(secret + secret_len / 2, half_secret_len, concat, label_len + seed_len, sha1, out_len, new_sha1_digest);

    for (int i = 0; i < out_len; i++) {
        output[i] ^= sha1[i];
    }
}

// #define TEST_PRF
#ifdef TEST_PRF
int main() {
    int out_len = 20;
    unsigned char output[out_len];

    PRF((unsigned char*)"secret", 6, (unsigned char*)"label", 5, (unsigned char*)"seed", 4, output, out_len);
    show_hex(output, out_len, 1);
}
#endif
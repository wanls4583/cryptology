#include <stdlib.h>
#include <stdio.h>
#include "sha.h"
#include "ecdsa.h"
#include "hex.h"

static void generate_message_secret(elliptic_curve* params, huge* k) {
    huge n, one;

    n.rep = NULL;
    huge_copy(&n, &params->n);
    huge_set(&one, 1);
    huge_subtract(&n, &one);

    k->size = n.size;
    k->sign = 0;
    k->rep = (huge_word*)malloc(n.size * HUGE_WORD_BYTES);
    // 此处应为随机数
    for (int i = 0; i < k->size; i++) {
        k->rep[i] = i + 1;
    }
    huge_divide(k, &n, NULL);
}

void ecdsa_sign(
    elliptic_curve* params,
    ecc_key* private_key,
    digest_ctx* ctx,
    ecdsa_signature* signature
) {
    unsigned char* hash;
    int hash_size = 0;
    point p1;
    huge r, s, k, z;
    r.rep = NULL;
    s.rep = NULL;
    p1.x.rep = NULL;
    p1.y.rep = NULL;

    generate_message_secret(params, &k);
    // unsigned char K[] = {
    //     0x9E, 0x56, 0xF5, 0x09, 0x19, 0x67, 0x84, 0xD9, 0x63, 0xD1, 0xC0,
    //     0xA4, 0x01, 0x51, 0x0E, 0xE7, 0xAD, 0xA3, 0xDC, 0xC5, 0xDE, 0xE0,
    //     0x4B, 0x15, 0x4B, 0xF6, 0x1A, 0xF1, 0xD5, 0xA6, 0xDE, 0xCE
    // };
    // huge_load(&k, (unsigned char*)K, sizeof(K));

    huge_copy(&p1.x, &params->G.x);
    huge_copy(&p1.y, &params->G.y);
    multiply_point(&p1, &k, &params->a, &params->p);

    // r = x1 % n
    huge_copy(&r, &p1.x);
    huge_divide(&r, &params->n, NULL);

    // s = (inv(k)*(z+r*da)) mod n
    hash = (unsigned char*)ctx->hash;
    hash_size = ctx->result_size * ctx->word_size;
    hash_size = hash_size > params->n.size * HUGE_WORD_BYTES ? params->n.size * HUGE_WORD_BYTES : hash_size;
    huge_load(&z, hash, hash_size);
    huge_inverse_mul(&k, &params->n);
    huge_copy(&s, &private_key->d);
    huge_multiply(&s, &r);
    huge_add(&s, &z);
    huge_multiply(&s, &k);
    huge_divide(&s, &params->n, NULL);

    huge_copy(&signature->r, &r);
    huge_copy(&signature->s, &s);

    free(r.rep);
    free(s.rep);
    free(k.rep);
    free(z.rep);
    free(p1.x.rep);
    free(p1.y.rep);
}

int ecdsa_verify(
    elliptic_curve* params,
    ecc_key* public_key,
    digest_ctx* ctx,
    ecdsa_signature* signature
) {
    unsigned char* hash;
    int hash_size = 0, result = -1;
    point p1, p2;
    huge u1, u2, z, invs;
    u1.rep = NULL;
    u2.rep = NULL;
    invs.rep = NULL;
    p1.x.rep = NULL;
    p1.y.rep = NULL;
    p2.x.rep = NULL;
    p2.y.rep = NULL;

    huge_copy(&invs, &signature->s);
    huge_inverse_mul(&invs, &params->n);

    // u1 = (z * inv(s)) % n
    hash = (unsigned char*)ctx->hash;
    hash_size = ctx->result_size * ctx->word_size;
    hash_size = hash_size > params->n.size * HUGE_WORD_BYTES ? params->n.size * HUGE_WORD_BYTES : hash_size;
    huge_load(&z, ctx->hash, hash_size);
    huge_copy(&u1, &invs);
    huge_multiply(&u1, &z);
    huge_divide(&u1, &params->n, NULL);

    // u2 = (r * inv(s)) % n
    huge_copy(&u2, &signature->r);
    huge_multiply(&u2, &invs);
    huge_divide(&u2, &params->n, NULL);

    // p1 = u1 * G + u2 * Qa
    huge_copy(&p1.x, &params->G.x);
    huge_copy(&p1.y, &params->G.y);
    huge_copy(&p2.x, &public_key->Q.x);
    huge_copy(&p2.y, &public_key->Q.y);
    multiply_point(&p1, &u1, &params->a, &params->p);
    multiply_point(&p2, &u2, &params->a, &params->p);
    add_points(&p1, &p2, &params->p);
    huge_divide(&p1.x, &params->n, NULL);

    result = huge_compare(&signature->r, &p1.x);
    free(u1.rep);
    free(u2.rep);
    free(z.rep);
    free(invs.rep);
    free(p1.x.rep);
    free(p1.y.rep);
    free(p2.x.rep);
    free(p2.y.rep);

    return result;
}

#define TEST_ECDSA
#ifdef TEST_ECDSA
#include <string.h>
int main() {
    // ECC parameters
    unsigned char P[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };
    unsigned char b[] = {
        0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, 0xB3, 0xEB, 0xBD, 0x55, 0x76,
        0x98, 0x86, 0xBC, 0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6, 0x3B, 0xCE,
        0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B
    };
    unsigned char q[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9,
        0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
    };
    unsigned char gx[] = {
        0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63,
        0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1,
        0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96
    };
    unsigned char gy[] = {
        0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C,
        0x0F, 0x9E, 0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6,
        0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5
    };

    // key
    unsigned char w[] = { 0xDC, 0x51, 0xD3, 0x86, 0x6A, 0x15, 0xBA, 0xCD, 0xE3,
        0x3D, 0x96, 0xF9, 0x92, 0xFC, 0xA9, 0x9D, 0xA7, 0xE6, 0xEF, 0x09, 0x34, 0xE7,
        0x09, 0x75, 0x59, 0xC2, 0x7F, 0x16, 0x14, 0xC8, 0x8A, 0x7F
    };

    elliptic_curve curve;
    ecc_key key;
    ecdsa_signature signature;

    digest_ctx ctx;

    huge_load(&curve.p, (unsigned char*)P, sizeof(P));
    huge_set(&curve.a, 3);
    curve.a.sign = 1;
    huge_load(&curve.b, b, sizeof(b));
    huge_load(&curve.G.x, gx, sizeof(gx));
    huge_load(&curve.G.y, gy, sizeof(gy));
    huge_load(&curve.n, q, sizeof(q));

    // Generate new public key from private key �w� and point �G�
    huge_load(&key.d, w, sizeof(w));
    huge_set(&key.Q.x, 0);
    huge_set(&key.Q.y, 0);
    huge_copy(&key.Q.x, &curve.G.x);
    huge_copy(&key.Q.y, &curve.G.y);
    multiply_point(&key.Q, &key.d, &curve.a, &curve.p);

    new_sha256_digest(&ctx);
    update_digest(&ctx, (unsigned char*)"abc", 3);
    finalize_digest(&ctx);

    ecdsa_sign(&curve, &key, &ctx, &signature);
    printf("r:");
    show_hex(signature.r.rep, signature.r.size, HUGE_WORD_BYTES);
    printf("s:");
    show_hex(signature.s.rep, signature.s.size, HUGE_WORD_BYTES);

    int result = ecdsa_verify(&curve, &key, &ctx, &signature);
    printf("dsa_verify: %s\n", result == 0 ? "success" : "failed");
}
#endif
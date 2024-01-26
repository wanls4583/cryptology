#include <stdlib.h>
#include <stdio.h>
#include "sha.h"
#include "dsa.h"
#include "hex.h"

static void generate_message_secret(dsa_params* params, huge* k) {
    huge q, one;

    q.rep = NULL;
    huge_copy(&q, &params->q);
    huge_set(&one, 1);
    huge_subtract(&q, &one);

    k->size = q.size;
    k->sign = 0;
    k->rep = (huge_word*)malloc(q.size * HUGE_WORD_BYTES);
    // 此处应为随机数
    for (int i = 0; i < k->size; i++) {
        k->rep[i] = i + 1;
    }
    huge_divide(k, &q, NULL);
}

void dsa_sign(
    dsa_params* params,
    huge* private_key,
    digest_ctx* ctx,
    dsa_signature* signature
) {
    unsigned char* hash;
    int hash_byte_size = 0;
    huge r, s, k, m;
    r.rep = NULL;
    s.rep = NULL;

    generate_message_secret(params, &k);

    // r = (g^k mode p) mod q
    huge_copy(&r, &params->g);
    huge_mod_pow(&r, &k, &params->p);
    huge_divide(&r, &params->q, NULL);

    // s = (inv(k)*(h(m)+xr)) mod q
    hash = (unsigned char*)ctx->hash;
    hash_byte_size = ctx->result_size;
    hash_byte_size = hash_byte_size > huge_bytes(&params->q) ? huge_bytes(&params->q) : hash_byte_size;
    huge_load(&m, hash, hash_byte_size);
    huge_inverse_mul(&k, &params->q);
    huge_copy(&s, private_key);
    huge_multiply(&s, &r);
    huge_add(&s, &m);
    huge_multiply(&s, &k);
    huge_divide(&s, &params->q, NULL);

    huge_copy(&signature->r, &r);
    huge_copy(&signature->s, &s);

    free(r.rep);
    free(s.rep);
    free(k.rep);
    free(m.rep);
}

int dsa_verify(
    dsa_params* params,
    huge* public_key,
    digest_ctx* ctx,
    dsa_signature* signature
) {
    unsigned char* hash;
    int hash_byte_size = 0, result = -1;
    huge w, u1, u2, v, m, g, y;
    w.rep = NULL;
    u1.rep = NULL;
    u2.rep = NULL;
    v.rep = NULL;
    g.rep = NULL;
    y.rep = NULL;

    // w = inv(s) % q
    huge_copy(&w, &signature->s);
    huge_inverse_mul(&w, &params->q);

    // u1 = (h(m) * w) % q
    hash = (unsigned char*)ctx->hash;
    hash_byte_size = ctx->result_size;
    hash_byte_size = hash_byte_size > huge_bytes(&params->q) ? huge_bytes(&params->q) : hash_byte_size;
    huge_load(&m, ctx->hash, hash_byte_size);
    huge_copy(&u1, &w);
    huge_multiply(&u1, &m);
    huge_divide(&u1, &params->q, NULL);

    // u2 = (r * w) % q
    huge_copy(&u2, &w);
    huge_multiply(&u2, &signature->r);
    huge_divide(&u2, &params->q, NULL);

    // v = ((g^u1 * g^u2) % p) % q
    huge_copy(&g, &params->g);
    huge_mod_pow(&g, &u1, &params->p);
    huge_copy(&y, public_key);
    huge_mod_pow(&y, &u2, &params->p);
    huge_copy(&v, &g);
    huge_multiply(&v, &y);
    huge_divide(&v, &params->p, NULL);
    huge_divide(&v, &params->q, NULL);

    result = huge_compare(&signature->r, &v);
    free(w.rep);
    free(u1.rep);
    free(u2.rep);
    free(v.rep);
    free(m.rep);
    free(g.rep);
    free(y.rep);

    return result;
}

// #define TEST_DSA
#ifdef TEST_DSA
#include <string.h>
void test1() {
    unsigned char priv[] = {
        0x53, 0x61, 0xae, 0x4f, 0x6f, 0x25, 0x98, 0xde, 0xc4, 0xbf, 0x0b, 0xbe, 0x09,
        0x5f, 0xdf, 0x90, 0x2f, 0x4c, 0x8e, 0x09
    };
    unsigned char pub[] = {
        0x1b, 0x91, 0x4c, 0xa9, 0x73, 0xdc, 0x06, 0x0d, 0x21, 0xc6, 0xff, 0xab, 0xf6,
        0xad, 0xf4, 0x11, 0x97, 0xaf, 0x23, 0x48, 0x50, 0xa8, 0xf3, 0xdb, 0x2e, 0xe6,
        0x27, 0x8c, 0x40, 0x4c, 0xb3, 0xc8, 0xfe, 0x79, 0x7e, 0x89, 0x48, 0x90, 0x27,
        0x92, 0x6f, 0x5b, 0xc5, 0xe6, 0x8f, 0x91, 0x4c, 0xe9, 0x4f, 0xed, 0x0d, 0x3c,
        0x17, 0x09, 0xeb, 0x97, 0xac, 0x29, 0x77, 0xd5, 0x19, 0xe7, 0x4d, 0x17
    };
    unsigned char P[] = {
        0x9c, 0x4c, 0xaa, 0x76, 0x31, 0x2e, 0x71, 0x4d, 0x31, 0xd6, 0xe4, 0xd7,
        0xe9, 0xa7, 0x29, 0x7b, 0x7f, 0x05, 0xee, 0xfd, 0xca, 0x35, 0x14, 0x1e, 0x9f,
        0xe5, 0xc0, 0x2a, 0xe0, 0x12, 0xd9, 0xc4, 0xc0, 0xde, 0xcc, 0x66, 0x96, 0x2f,
        0xf1, 0x8f, 0x1a, 0xe1, 0xe8, 0xbf, 0xc2, 0x29, 0x0d, 0x27, 0x07, 0x48, 0xb9,
        0x71, 0x04, 0xec, 0xc7, 0xf4, 0x16, 0x2e, 0x50, 0x8d, 0x67, 0x14, 0x84, 0x7b
    };
    unsigned char Q[] = {
        0x00, 0xac, 0x6f, 0xc1, 0x37, 0xef, 0x16, 0x74, 0x52, 0x6a, 0xeb, 0xc5, 0xf8,
        0xf2, 0x1f, 0x53, 0xf4, 0x0f, 0xe0, 0x51, 0x5f
    };
    unsigned char G[] = {
        0x7d, 0xcd, 0x66, 0x81, 0x61, 0x52, 0x21, 0x10, 0xf7, 0xa0, 0x83, 0x4c, 0x5f,
        0xc8, 0x84, 0xca, 0xe8, 0x8a, 0x9b, 0x9f, 0x19, 0x14, 0x8c, 0x7d, 0xd0, 0xee,
        0x33, 0xce, 0xb4, 0x57, 0x2d, 0x5e, 0x78, 0x3f, 0x06, 0xd7, 0xb3, 0xd6, 0x40,
        0x70, 0x2e, 0xb6, 0x12, 0x3f, 0x4a, 0x61, 0x38, 0xae, 0x72, 0x12, 0xfb, 0x77,
        0xde, 0x53, 0xb3, 0xa1, 0x99, 0xd8, 0xa8, 0x19, 0x96, 0xf7, 0x7f, 0x99
    };
    dsa_params params;
    dsa_signature signature;
    huge x, y;
    unsigned char msg[] = "abc123";
    digest_ctx ctx;

    // TODO load these from a DSA private key file instead
    huge_load(&params.g, G, sizeof(G));
    huge_load(&params.p, P, sizeof(P));
    huge_load(&params.q, Q, sizeof(Q));
    huge_load(&x, priv, sizeof(priv));
    huge_load(&y, pub, sizeof(pub));

    // huge g;
    // huge_load(&g, G, sizeof(G));
    // huge_mod_pow(&g, &x, &params.p);
    // show_hex(g.rep, g.size, HUGE_WORD_BYTES);

    new_sha1_digest(&ctx);
    update_digest(&ctx, msg, strlen((char*)msg));
    finalize_digest(&ctx);

    dsa_sign(&params, &x, &ctx, &signature);
    printf("r:");
    show_hex(signature.r.rep, signature.r.size, HUGE_WORD_BYTES);
    printf("s:");
    show_hex(signature.s.rep, signature.s.size, HUGE_WORD_BYTES);

    int result = dsa_verify(&params, &y, &ctx, &signature);
    printf("dsa_verify: %s\n", result == 0 ? "success" : "failed");
}

#include "file.h"
#include "asn1.h"
#include "privkey.h"
void test2() {
    dsa_signature signature;
    dsa_key private_dsa_key;
    digest_ctx ctx;
    unsigned char* pem_buffer;
    unsigned char* buffer;
    unsigned char* msg;
    int buffer_length;

    huge_set(&signature.r, 0);
    huge_set(&signature.s, 0);

    if (!(pem_buffer = load_file("./res/dsa_key.pem", &buffer_length))) {
        perror("Unable to load file");
        return;
    }
    buffer = (unsigned char*)malloc(buffer_length);
    buffer_length = pem_decode(pem_buffer, buffer, NULL, NULL);

    parse_private_dsa_key(&private_dsa_key, buffer, buffer_length);
    free(buffer);

    int len = hex_decode((unsigned char*)"0x7b90f26a4b8f717a62a2434cb3c8e04dd0728ba8872784abea2435c0854fbb0f9571ab650000000000000000000000000000000000000000000000000000000000809c4caa76312e714d31d6e4d7e9a7297b7f05eefdca35141e9fe5c02ae012d9c4c0decc66962ff18f1ae1e8bfc2290d270748b97104ecc7f4162e508d6714847b9c4caa76312e714d31d6e4d7e9a7297b7f05eefdca35141e9fe5c02ae012d9c4c0decc66962ff18f1ae1e8bfc2290d270748b97104ecc7f4162e508d6714847b00807dcd668161522110f7a0834c5fc884cae88a9b9f19148c7dd0ee33ceb4572d5e783f06d7b3d640702eb6123f4a6138ae7212fb77de53b3a199d8a81996f77f997dcd668161522110f7a0834c5fc884cae88a9b9f19148c7dd0ee33ceb4572d5e783f06d7b3d640702eb6123f4a6138ae7212fb77de53b3a199d8a81996f77f9900804093f447fbba760dffddf29ce864027192b3b950b4087f220b849a06de105c02f56e59f0830e2109e0d0eb7c873db6aff8555a2c517217ef44f387ab1846c2a34093f447fbba760dffddf29ce864027192b3b950b4087f220b849a06de105c02f56e59f0830e2109e0d0eb7c873db6aff8555a2c517217ef44f387ab1846c2a3", &msg);
    // int len = hex_decode((unsigned char*)"0xe2ab0af912826f0833d2e7499e52cfe9fb6577ef7c02e139e1bc9efd26035b669571ab650000000000000000000000000000000000000000000000000000000000809c4caa76312e714d31d6e4d7e9a7297b7f05eefdca35141e9fe5c02ae012d9c4c0decc66962ff18f1ae1e8bfc2290d270748b97104ecc7f4162e508d6714847b9c4caa76312e714d31d6e4d7e9a7297b7f05eefdca35141e9fe5c02ae012d9c4c0decc66962ff18f1ae1e8bfc2290d270748b97104ecc7f4162e508d6714847b00807dcd668161522110f7a0834c5fc884cae88a9b9f19148c7dd0ee33ceb4572d5e783f06d7b3d640702eb6123f4a6138ae7212fb77de53b3a199d8a81996f77f997dcd668161522110f7a0834c5fc884cae88a9b9f19148c7dd0ee33ceb4572d5e783f06d7b3d640702eb6123f4a6138ae7212fb77de53b3a199d8a81996f77f9900804093f447fbba760dffddf29ce864027192b3b950b4087f220b849a06de105c02f56e59f0830e2109e0d0eb7c873db6aff8555a2c517217ef44f387ab1846c2a34093f447fbba760dffddf29ce864027192b3b950b4087f220b849a06de105c02f56e59f0830e2109e0d0eb7c873db6aff8555a2c517217ef44f387ab1846c2a3", &msg);

    new_sha1_digest(&ctx);
    update_digest(&ctx, msg, len);
    finalize_digest(&ctx);

    dsa_sign(&private_dsa_key.params, &private_dsa_key.key, &ctx, &signature);
    printf("r:");
    show_hex(signature.r.rep, signature.r.size, HUGE_WORD_BYTES);
    printf("s:");
    show_hex(signature.s.rep, signature.s.size, HUGE_WORD_BYTES);

    int result = dsa_verify(&private_dsa_key.params, &private_dsa_key.pub, &ctx, &signature);
    printf("dsa_verify: %s\n", result == 0 ? "success" : "failed");
}

int main() {
    // test1();
    test2();

    return 0;
}
#endif
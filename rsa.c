#include <stdlib.h>
#include <string.h>
#include "rsa.h"
#include "hex.h"

int rsa_encrypt(
    unsigned char* input,
    unsigned int len,
    unsigned char** output,
    rsa_key* public_key
) {
    int p_size = public_key->p->size;
    int max_block_size = p_size - 11;
    int encrypted_size = 0;
    unsigned char padded_block[p_size];

    huge a, e, p;
    set_huge(&e, 0);
    set_huge(&p, 0);
    copy_huge(&e, public_key->key);
    copy_huge(&p, public_key->p);

    *output = NULL;

    while (len > 0) {
        int block_size = len > max_block_size ? max_block_size : len;
        encrypted_size += p_size;

        memset(padded_block, 0, p_size);
        memcpy(padded_block + p_size - block_size, input, block_size);
        padded_block[1] = 0x02;
        // 填充随机数
        for (int i = 2; i < p_size - block_size - 1; i++) {
            padded_block[i] = i;
        }

        load_huge(&a, padded_block, p_size);
        // show_hex(a.rep, a.size);
        // show_hex(e.rep, e.size);
        // show_hex(p.rep, p.size);
        mod_pow(&a, &e, &p);
        // show_hex(a.rep, a.size);

        *output = (unsigned char*)realloc(*output, encrypted_size);
        unload_huge(&a, *output + (encrypted_size - p_size), p_size);

        len -= block_size;
        input += block_size;
    }

    free(a.rep);
    free(e.rep);
    free(p.rep);

    return encrypted_size;
}

int rsa_decrypt(
    unsigned char* input,
    unsigned int len,
    unsigned char** output,
    rsa_key* private_key
) {
    return 0;
}

#define TEST_RSA
#ifdef TEST_RSA
#include <time.h>
#include <stdio.h>

unsigned char TestModulus[] = {
0xC4, 0xF8, 0xE9, 0xE1, 0x5D, 0xCA, 0xDF, 0x2B,
0x96, 0xC7, 0x63, 0xD9, 0x81, 0x00, 0x6A, 0x64,
0x4F, 0xFB, 0x44, 0x15, 0x03, 0x0A, 0x16, 0xED,
0x12, 0x83, 0x88, 0x33, 0x40, 0xF2, 0xAA, 0x0E,
0x2B, 0xE2, 0xBE, 0x8F, 0xA6, 0x01, 0x50, 0xB9,
0x04, 0x69, 0x65, 0x83, 0x7C, 0x3E, 0x7D, 0x15,
0x1B, 0x7D, 0xE2, 0x37, 0xEB, 0xB9, 0x57, 0xC2,
0x06, 0x63, 0x89, 0x82, 0x50, 0x70, 0x3B, 0x3F
};

unsigned char TestPrivateKey[] = {
0x8a, 0x7e, 0x79, 0xf3, 0xfb, 0xfe, 0xa8, 0xeb,
0xfd, 0x18, 0x35, 0x1c, 0xb9, 0x97, 0x91, 0x36,
0xf7, 0x05, 0xb4, 0xd9, 0x11, 0x4a, 0x06, 0xd4,
0xaa, 0x2f, 0xd1, 0x94, 0x38, 0x16, 0x67, 0x7a,
0x53, 0x74, 0x66, 0x18, 0x46, 0xa3, 0x0c, 0x45,
0xb3, 0x0a, 0x02, 0x4b, 0x4d, 0x22, 0xb1, 0x5a,
0xb3, 0x23, 0x62, 0x2b, 0x2d, 0xe4, 0x7b, 0xa2,
0x91, 0x15, 0xf0, 0x6e, 0xe4, 0x2c, 0x41
};

unsigned char TestPublicKey[] = { 0x01, 0x00, 0x01 };

int main() {
    time_t start, end;
    rsa_key rsa;
    unsigned char* out;
    int len;

    rsa.p = (huge*)malloc(sizeof(huge));
    rsa.key = (huge*)malloc(sizeof(huge));
    load_huge(rsa.p, TestModulus, sizeof(TestModulus));
    load_huge(rsa.key, TestPrivateKey, sizeof(TestPrivateKey));

    start = clock();
    len = rsa_encrypt((unsigned char*)"abc", 3, &out, &rsa);
    show_hex(out, len);
    end = clock();
    printf("duration: %fs", (double)(end - start) / CLOCKS_PER_SEC);
}
#endif
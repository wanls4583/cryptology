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
    int p_size = public_key->p->size * HUGE_WORD_BYTES;
    int max_block_size = p_size - 11;
    int encrypted_size = 0;
    unsigned char padded_block[p_size];

    huge a, e, p;
    huge_set(&e, 0);
    huge_set(&p, 0);
    huge_copy(&e, public_key->key);
    huge_copy(&p, public_key->p);

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

        huge_load(&a, padded_block, p_size);
        huge_mod_pow(&a, &e, &p);

        *output = (unsigned char*)realloc(*output, encrypted_size);
        huge_unload(&a, *output + (encrypted_size - p_size), p_size);

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
    int p_size = private_key->p->size * HUGE_WORD_BYTES;
    int decrypted_size = 0;
    unsigned char padded_block[p_size];

    huge a, e, p;
    huge_set(&a, 0);
    huge_set(&e, 0);
    huge_set(&p, 0);
    huge_copy(&e, private_key->key);
    huge_copy(&p, private_key->p);

    *output = NULL;

    while (len >= p_size) {
        int data_szie = 0;
        memcpy(padded_block, input, p_size);
        huge_load(&a, padded_block, p_size);
        huge_mod_pow(&a, &e, &p);
        memset(padded_block, 0, p_size);
        huge_unload(&a, padded_block, p_size);

        int i = 1;
        if (padded_block[1] != 0x02) { //数据错误
            return 0;
        }
        while (padded_block[i++]) {} //找到填充后的真实数据
        data_szie = p_size - i;
        if (data_szie <= 0) { //数据错误
            return 0;
        }

        *output = (unsigned char*)realloc(*output, decrypted_size + data_szie);
        memcpy(*output + decrypted_size, &padded_block[i], data_szie);
        decrypted_size += data_szie;

        len -= p_size;
        input += p_size;
    }

    free(a.rep);
    free(e.rep);
    free(p.rep);

    return decrypted_size;
}

// #define TEST_RSA
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
    unsigned char* encData;
    unsigned char* decData;
    unsigned char* data;
    int len;

    rsa.p = (huge*)malloc(sizeof(huge));
    rsa.key = (huge*)malloc(sizeof(huge));
    huge_load(rsa.p, TestModulus, sizeof(TestModulus));

    data = (unsigned char*)"abcd123abcd123abcd123abcd123abcd123abcd123abcd123abc1";
    huge_load(rsa.key, TestPublicKey, sizeof(TestPublicKey));
    start = clock();
    len = rsa_encrypt(data, strlen((const char*)data), &encData, &rsa);
    show_hex(encData, len, 1);
    end = clock();
    printf("enc-time: %fs\n", (double)(end - start) / CLOCKS_PER_SEC);

    huge_load(rsa.key, TestPrivateKey, sizeof(TestPrivateKey));
    start = clock();
    for(int i = 0; i < 10; i++) {
        rsa_decrypt(encData, len, &decData, &rsa);
    }
    end = clock();
    printf("%s\n", decData);
    printf("dec-time: %fs\n", (double)(end - start) / CLOCKS_PER_SEC);

}
#endif
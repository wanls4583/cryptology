#include "rc4.h"

void swap(unsigned char* S, int i, int j) {
    unsigned char c = S[i];
    S[i] = S[j];
    S[j] = c;
}

void rc4_process(
    unsigned char* text,
    int text_len,
    unsigned char* key,
    int key_len,
    unsigned char output[]
) {
    unsigned char S[256];
    unsigned char T[256];
    int i = 0, j = 0, t = 0;

    for (i = 0; i < 256; i++) {
        S[i] = i;
        T[i] = key[i % key_len];
    }

    for (i = 0, j = 0; i < 256; i++) {
        j = (j + S[i] + T[i]) % 256;
        swap(S, i, j);
    }

    i = 0, j = 0;
    for (int n = 0; n < text_len; n++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        swap(S, i, j);
        t = (S[i] + S[j]) % 256;
        output[n] = output[n] ^ S[t];
    }

}

void rc4_40_encrypt(
    unsigned char* plaintext,
    int plaintext_len,
    unsigned char ciphertext[],
    void* state,
    unsigned char* key
) {

}

void rc4_40_decrypt(
    unsigned char* ciphertext,
    int ciphertext_len,
    unsigned char plaintext[],
    void* state,
    unsigned char* key
) {

}

void rc4_128_encrypt(
    unsigned char* plaintext,
    int plaintext_len,
    unsigned char ciphertext[],
    void* state,
    unsigned char* key
) {

}

void rc4_128_decrypt(
    unsigned char* ciphertext,
    int ciphertext_len,
    unsigned char plaintext[],
    void* state,
    unsigned char* key
) {

}

#define TEST_RC4
#ifdef TEST_RC4
#include <string.h>
#include "hex.h"
int main() {
    unsigned char text[] = "abcdefghijklmnop";
    unsigned char key[] = "abcdef";
    int text_len = strlen((char*)text);
    int key_len = strlen((char*)key);
    unsigned char out[text_len];

    rc4_process(text, text_len, key, key_len, out);
    show_hex(out, text_len, 1);
}
#endif
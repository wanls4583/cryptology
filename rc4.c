#include "rc4.h"
#include "hex.h"

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
    rc4_state* state,
    unsigned char output[]
) {
    int i = 0, j = 0, t = 0;
    unsigned char* S = state->S;

    if (state->S[0] == 0 && state->S[1] == 0) {
        unsigned char T[RC4_STATE_ARRAY_LEN];

        for (i = 0; i < RC4_STATE_ARRAY_LEN; i++) {
            S[i] = i;
            T[i] = key[i % key_len];
        }

        for (i = 0, j = 0; i < RC4_STATE_ARRAY_LEN; i++) {
            j = (j + S[i] + T[i]) % RC4_STATE_ARRAY_LEN;
            swap(S, i, j);
        }

        i = 0, j = 0;
    } else {
        i = state->i;
        j = state->j;
    }

    for (int n = 0; n < text_len; n++) {
        i = (i + 1) % RC4_STATE_ARRAY_LEN;
        j = (j + S[i]) % RC4_STATE_ARRAY_LEN;
        swap(S, i, j);
        t = (S[i] + S[j]) % RC4_STATE_ARRAY_LEN;
        output[n] = text[n] ^ S[t];
    }

    state->i = i;
    state->j = j;
}

void rc4_40_encrypt(
    unsigned char* plaintext,
    int plaintext_len,
    unsigned char* key,
    void* state,
    unsigned char ciphertext[]
) {
    rc4_process(plaintext, plaintext_len, key, 5, state, ciphertext);
}

void rc4_40_decrypt(
    unsigned char* ciphertext,
    int ciphertext_len,
    unsigned char* key,
    void* state,
    unsigned char plaintext[]
) {
    rc4_process(ciphertext, ciphertext_len, key, 5, state, plaintext);
}

void rc4_128_encrypt(
    unsigned char* plaintext,
    int plaintext_len,
    unsigned char* key,
    void* state,
    unsigned char ciphertext[]
) {
    rc4_process(plaintext, plaintext_len, key, 16, state, ciphertext);
}

void rc4_128_decrypt(
    unsigned char* ciphertext,
    int ciphertext_len,
    unsigned char* key,
    void* state,
    unsigned char plaintext[]
) {
    rc4_process(ciphertext, ciphertext_len, key, 16, state, plaintext);
}

#define TEST_RC4
#ifdef TEST_RC4
#include <string.h>
#include <stdio.h>
int main() {
    unsigned char enc[100];
    unsigned char dec[100];
    rc4_state state;

    state.S[0] = 0;
    state.S[1] = 0;
    rc4_process((unsigned char*)"abcdefghijklmnop", 16, (unsigned char*)"abcdef", 6, &state, enc);
    show_hex(enc, 16, 1);

    state.S[0] = 0;
    state.S[1] = 0;
    rc4_process(enc, 16, (unsigned char*)"abcdef", 6, &state, dec);
    printf("%s\n", dec);

    state.S[0] = 0;
    state.S[1] = 0;
    rc4_40_encrypt((unsigned char*)"abcdefghijklmnop", 16, (unsigned char*)"abcdef", &state, enc);
    show_hex(enc, 16, 1);

    state.S[0] = 0;
    state.S[1] = 0;
    rc4_40_decrypt(enc, 16, (unsigned char*)"abcdef", &state, dec);
    printf("%s\n", dec);

    state.S[0] = 0;
    state.S[1] = 0;
    rc4_128_encrypt((unsigned char*)"abcdefghijklmnop", 16, (unsigned char*)"abcdefghijk12345", &state, enc);
    show_hex(enc, 16, 1);

    state.S[0] = 0;
    state.S[1] = 0;
    rc4_128_decrypt(enc, 16, (unsigned char*)"abcdefghijk12345", &state, dec);
    printf("%s\n", dec);
}
#endif
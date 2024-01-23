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
    unsigned char output[],
    rc4_state* state,
    unsigned char* key,
    int key_len
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
    unsigned char ciphertext[],
    void* state,
    unsigned char* key
) {
    rc4_process(plaintext, plaintext_len, ciphertext, state, key, 5);
}

void rc4_40_decrypt(
    unsigned char* ciphertext,
    int ciphertext_len,
    unsigned char plaintext[],
    void* state,
    unsigned char* key
) {
    rc4_process(ciphertext, ciphertext_len, plaintext, state, key, 5);
}

void rc4_128_encrypt(
    unsigned char* plaintext,
    int plaintext_len,
    unsigned char ciphertext[],
    void* state,
    unsigned char* key
) {
    rc4_process(plaintext, plaintext_len, ciphertext, state, key, 16);
}

void rc4_128_decrypt(
    unsigned char* ciphertext,
    int ciphertext_len,
    unsigned char plaintext[],
    void* state,
    unsigned char* key
) {
    rc4_process(ciphertext, ciphertext_len, plaintext, state, key, 16);
}

// #define TEST_RC4
#ifdef TEST_RC4
#include <string.h>
#include <stdio.h>
int main() {
    unsigned char enc[100];
    unsigned char dec[100];
    rc4_state state;

    state.S[0] = 0;
    state.S[1] = 0;
    rc4_process((unsigned char*)"abcdefghijklmnop", 16, enc, &state, (unsigned char*)"abcdef", 6);
    show_hex(enc, 16, 1);

    state.S[0] = 0;
    state.S[1] = 0;
    rc4_process(enc, 16, dec, &state, (unsigned char*)"abcdef", 6);
    printf("%s\n", dec);

    state.S[0] = 0;
    state.S[1] = 0;
    rc4_40_encrypt((unsigned char*)"abcdefghijklmnop", 16, enc, &state, (unsigned char*)"abcdef");
    show_hex(enc, 16, 1);

    state.S[0] = 0;
    state.S[1] = 0;
    rc4_40_decrypt(enc, 16, dec, &state, (unsigned char*)"abcdef");
    printf("%s\n", dec);

    state.S[0] = 0;
    state.S[1] = 0;
    rc4_128_encrypt((unsigned char*)"abcdefghijklmnop", 16, enc, &state, (unsigned char*)"abcdefghijk12345");
    show_hex(enc, 16, 1);

    state.S[0] = 0;
    state.S[1] = 0;
    rc4_128_decrypt(enc, 16, dec, &state, (unsigned char*)"abcdefghijk12345");
    printf("%s\n", dec);
}
#endif
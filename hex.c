#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "hex.h"

int hex_decode(unsigned char* input, unsigned char** decoded) {
    long size;
    if (strncmp("0x", (const char*)input, 2)) {
        size = strlen((const char*)input);
        *decoded = malloc(size + 1);
        memcpy(*decoded, input, size);
        return size;
    }
    size = strlen((const char*)input) / 2 - 1;
    *decoded = (unsigned char*)malloc(size + 1);
    for (long i = 0; i < size; i++) {
        unsigned char c = input[i * 2 + 2];
        (*decoded)[i] = (c <= '9' ? c - '0' : tolower(c) - 'a' + 10) << 4;
        c = input[i * 2 + 3];
        c = c <= '9' ? c - '0' : tolower(c) - 'a' + 10;
        (*decoded)[i] |= c;
    }
    return size;
}

void show_hex_1(unsigned char* array, int length) {
    for (int i = 0; i < length; i++) {
        printf("%.02x", array[i]);
    }
    printf("\n");
}

void show_hex_4(unsigned int* array, int length) {
    for (int i = 0; i < length; i++) {
        unsigned int num = htonl(array[i]);
        unsigned char* s = (unsigned char*)(&num);
        int j = 0;
        if (i == 0) {
            while (!s[j] && j < 3) {
                j++;
            }
        }
        for (; j < 4; j++) {
            printf("%.02x", s[j]);
        }
    }
    printf("\n");
}

void show_hex(void* array, int length, int word_bytes) {
    if (word_bytes == 1) {
        show_hex_1(array, length);
    } else if (word_bytes == 4) {
        show_hex_4(array, length);
    }
}
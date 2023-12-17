#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "hex.h"

int hex_decode(const unsigned char* input, unsigned char** decoded) {
    long size = strlen((const char*)input) / 2;
    *decoded = (unsigned char*)malloc(size + 1);
    for (long i = 0; i < size; i++) {
        unsigned char c = input[i * 2];
        (*decoded)[i] = (c <= '9' ? c - '0' : tolower(c) - 'a' + 10) << 4;
        c = input[i * 2 + 1];
        c = c <= '9' ? c - '0' : tolower(c) - 'a' + 10;
        (*decoded)[i] |= c;
    }
    return size;
}

void show_hex(const unsigned char* array, int length) {
    for (int i = 0; i < length; i++) {
        printf("%.02x", array[i]);
    }
    printf("\n");
}
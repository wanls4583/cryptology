#include <stdio.h>
#include "hex.h"

int _main() {
    const unsigned char s[] = "0123456789abcdef";
    unsigned char* res;
    long size = 0;

    printf("%s\n", s);

    size = hex_decode(s, &res);
    show_hex(res, size);

    return 0;
}
#include <stdlib.h>
#include "huge.h"
#include "asn1.h"
#include "privkey.h"

int parse_private_key(
    rsa_key* privkey,
    unsigned char* buffer,
    int buffer_length
) {
    struct asn1struct private_key;
    struct asn1struct* version;
    struct asn1struct* p;
    struct asn1struct* public_exponent;
    struct asn1struct* private_exponent;

    asn1parse(buffer, buffer_length, &private_key);

    version = (struct asn1struct*)private_key.children;
    p = (struct asn1struct*)version->next;
    // Just read this to skip over it
    public_exponent = (struct asn1struct*)p->next;
    private_exponent = (struct asn1struct*)public_exponent->next;

    privkey->p = (huge*)malloc(sizeof(huge));
    privkey->key = (huge*)malloc(sizeof(huge));
    huge_load(privkey->p, p->data, p->length);
    huge_load(privkey->key, private_exponent->data, private_exponent->length);

    asn1free(&private_key);

    return 0;
}

// #define TEST_PRIVKEY
#ifdef TEST_PRIVKEY
#include "file.h"
#include "hex.h"
#include <stdio.h>
int main() {
    rsa_key privkey;
    int buffer_length;
    unsigned char* buffer = load_file("./res/key.der", &buffer_length);

    parse_private_key(&privkey, buffer, buffer_length);
    printf("Modulus:");
    show_hex(privkey.p->rep, privkey.p->size, HUGE_WORD_BYTES);
    printf("Private Exponent:");
    show_hex(privkey.key->rep, privkey.key->size, HUGE_WORD_BYTES);

    return 0;
}
#endif
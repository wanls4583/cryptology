#include <stdlib.h>
#include "huge.h"
#include "asn1.h"
#include "privkey.h"

/**
 * Parse the modulus and private exponent from the buffer, which
 * should contain a DER-encoded RSA private key file.  There's a
 * lot more information in the private key file format, but this
 * app isn't set up to use any of it.
 * This, according to PKCS #1 (note that this is not in pkcs #8 format), is:
 * Version
 * modulus (n)
 * public exponent (e)
 * private exponent (d)
 * prime1 (p)
 * prime2 (q)
 * exponent1 (d mod p-1)
 * exponent2 (d mod q-1)
 * coefficient (inverse of q % p)
 * Here, all we care about is n & d.
 */
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

    if (p->tag == ASN1_SEQUENCE) {
        struct asn1struct* key_info = (struct asn1struct*)p->next;
        asn1parse(key_info->data, key_info->length, &private_key);
        version = (struct asn1struct*)private_key.children;
        p = (struct asn1struct*)version->next;
    }

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
    int pem_buffer_length;
    unsigned char* buffer;
    unsigned char* pem_buffer;

    // buffer = load_file("./res/key.der", &buffer_length);

    pem_buffer = load_file("./res/rootCA.key", &pem_buffer_length);
    buffer = (unsigned char*)malloc(pem_buffer_length);
    buffer_length = pem_decode(pem_buffer, buffer);

    parse_private_key(&privkey, buffer, buffer_length);

    printf("Modulus:");
    show_hex(privkey.p->rep, privkey.p->size, HUGE_WORD_BYTES);
    printf("Private Exponent:");
    show_hex(privkey.key->rep, privkey.key->size, HUGE_WORD_BYTES);

    return 0;
}
#endif
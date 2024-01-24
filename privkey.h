#ifndef PRIVKEY_H
#define PRIVKEY_H

#include "rsa.h"
#include "dh.h"
#include "dsa.h"

int parse_private_key(
    rsa_key* privkey,
    unsigned char* buffer,
    int buffer_length
);
int parse_pkcs8_private_key(
    rsa_key* privkey,
    unsigned char* buffer,
    int buffer_length,
    unsigned char* passphrase
);
int parse_private_dh_key(
    dh_key* privkey,
    unsigned char* buffer,
    int buffer_length
);
int parse_private_dsa_key(
    dsa_key* privkey,
    unsigned char* buffer,
    int buffer_length
);
#endif

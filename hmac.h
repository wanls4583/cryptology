#ifndef HMAC_H
#define HMAC_H

#include "digest.h"

void hmac(
    digest_ctx* digest,
    u8* key,
    int key_length,
    u8* text,
    int text_length
);

#endif
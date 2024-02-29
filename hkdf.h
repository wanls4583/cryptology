#ifndef HKDF_H
#define HKDF_H

#include "digest.h"

void HKDF_extract(
    unsigned char* salt, int salt_len,
    unsigned char* key, int key_len,
    unsigned char* PRK,
    digest_ctx ctx
);
void HKDF_expand(
    unsigned char* key, int key_len,
    unsigned char* info, int info_len,
    unsigned char* out, int out_len,
    digest_ctx ctx
);
void HKDF_expand_label(
    unsigned char* secret, int secret_len,
    unsigned char* label, int label_len,
    unsigned char* context, int context_len,
    unsigned char* out, int out_len,
    digest_ctx ctx
);
void derive_secret(
    unsigned char* secret, int secret_len,
    unsigned char* label, int label_len,
    unsigned char* message, int message_len,
    unsigned char* out, int out_len,
    digest_ctx ctx
);
void HKDF(
    unsigned char* key, int key_len,
    unsigned char* salt, int salt_len,
    unsigned char* info, int info_len,
    unsigned char* out, int out_len,
    digest_ctx ctx
);

#endif
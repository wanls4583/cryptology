#ifndef HKDF_H
#define HKDF_H

void HKDF_extract(
    unsigned char* salt, int salt_len,
    unsigned char* key, int key_len,
    unsigned char* PRK
);
void HKDF_expand(
    unsigned char* key, int key_len,
    unsigned char* info, int info_len,
    unsigned char* out, int out_len
);
void HKDF(
    unsigned char* key, int key_len,
    unsigned char* salt, int salt_len,
    unsigned char* info, int info_len,
    unsigned char* out, int out_len
);

#endif
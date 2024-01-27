#ifndef PRF_H
#define PRF_H

void PRF(
    unsigned char* secret,
    int secret_len,
    unsigned char* label,
    int label_len,
    unsigned char* seed,
    int seed_len,
    unsigned char* output,
    int out_len
);
void PRF2(
    unsigned char* secret,
    int secret_len,
    unsigned char* label,
    int label_len,
    unsigned char* seed,
    int seed_len,
    unsigned char* output,
    int out_len
);

#endif

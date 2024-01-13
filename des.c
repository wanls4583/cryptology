#include "des.h"
#include "hex.h"
#include <stdio.h>
#include <string.h>

static int ip_table[] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

static int ip_table_inverse[] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
};

static int pc1_table[] = {
    57, 49, 41, 33, 25, 17, 9, 1,
    58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3,
    60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7,
    62, 54, 46, 38, 30, 22, 14, 6,
    61, 53, 45, 37, 29, 21, 13, 5,
    28, 20, 12, 4
};

static int pc2_table[] = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

static int expansion_table[] = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
};

static int sbox[8][64] = {
    {
        14, 0, 4, 15, 13, 7, 1, 4, 2, 14, 15, 2, 11, 13, 8, 1,
        3, 10, 10, 6, 6, 12, 12, 11, 5, 9, 9, 5, 0, 3, 7, 8,
        4, 15, 1, 12, 14, 8, 8, 2, 13, 4, 6, 9, 2, 1, 11, 7,
        15, 5, 12, 11, 9, 3, 7, 14, 3, 10, 10, 0, 5, 6, 0, 13
    },
    {
        15, 3, 1, 13, 8, 4, 14, 7, 6, 15, 11, 2, 3, 8, 4, 14,
        9, 12, 7, 0, 2, 1, 13, 10, 12, 6, 0, 9, 5, 11, 10, 5,
        0, 13, 14, 8, 7, 10, 11, 1, 10, 3, 4, 15, 13, 4, 1, 2,
        5, 11, 8, 6, 12, 7, 6, 12, 9, 0, 3, 5, 2, 14, 15, 9
    },
    {
        10, 13, 0, 7, 9, 0, 14, 9, 6, 3, 3, 4, 15, 6, 5, 10,
        1, 2, 13, 8, 12, 5, 7, 14, 11, 12, 4, 11, 2, 15, 8, 1,
        13, 1, 6, 10, 4, 13, 9, 0, 8, 6, 15, 9, 3, 8, 0, 7,
        11, 4, 1, 15, 2, 14, 12, 3, 5, 11, 10, 5, 14, 2, 7, 12
    },
    {
        7, 13, 13, 8, 14, 11, 3, 5, 0, 6, 6, 15, 9, 0, 10, 3,
        1, 4, 2, 7, 8, 2, 5, 12, 11, 1, 12, 10, 4, 14, 15, 9,
        10, 3, 6, 15, 9, 0, 0, 6, 12, 10, 11, 1, 7, 13, 13, 8,
        15, 9, 1, 4, 3, 5, 14, 11, 5, 12, 2, 7, 8, 2, 4, 14
    },
    {
        2, 14, 12, 11, 4, 2, 1, 12, 7, 4, 10, 7, 11, 13, 6, 1,
        8, 5, 5, 0, 3, 15, 15, 10, 13, 3, 0, 9, 14, 8, 9, 6,
        4, 11, 2, 8, 1, 12, 11, 7, 10, 1, 13, 14, 7, 2, 8, 13,
        15, 6, 9, 15, 12, 0, 5, 9, 6, 10, 3, 4, 0, 5, 14, 3
    },
    {
        12, 10, 1, 15, 10, 4, 15, 2, 9, 7, 2, 12, 6, 9, 8, 5,
        0, 6, 13, 1, 3, 13, 4, 14, 14, 0, 7, 11, 5, 3, 11, 8,
        9, 4, 14, 3, 15, 2, 5, 12, 2, 9, 8, 5, 12, 15, 3, 10,
        7, 11, 0, 14, 4, 1, 10, 7, 1, 6, 13, 0, 11, 8, 6, 13
    },
    {
        4, 13, 11, 0, 2, 11, 14, 7, 15, 4, 0, 9, 8, 1, 13, 10,
        3, 14, 12, 3, 9, 5, 7, 12, 5, 2, 10, 15, 6, 8, 1, 6,
        1, 6, 4, 11, 11, 13, 13, 8, 12, 1, 3, 4, 7, 10, 14, 7,
        10, 9, 15, 5, 6, 0, 8, 15, 0, 14, 5, 2, 9, 3, 2, 12
    },
    {
        13, 1, 2, 15, 8, 13, 4, 8, 6, 10, 15, 3, 11, 7, 1, 4,
        10, 12, 9, 5, 3, 6, 14, 11, 5, 0, 0, 14, 12, 9, 7, 2,
        7, 2, 11, 1, 4, 14, 1, 7, 9, 4, 12, 10, 14, 8, 2, 13,
        0, 15, 6, 12, 10, 9, 13, 0, 15, 3, 3, 5, 5, 6, 8, 11
    }
};

static int p_table[] = {
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
};

void _xor(unsigned char* a, unsigned char* b, int len) {
    for (int i = 0; i < len; i++) {
        a[i] ^= b[i];
    }
}

int get_bit(unsigned char arr[], int bits) {
    int index = --bits / 8;
    return arr[index] & (0x80 >> (bits % 8));
}

void set_bit(unsigned char arr[], int bits) {
    int index = --bits / 8;
    arr[index] |= 0x80 >> (bits % 8);
}

void clear_bit(unsigned char arr[], int bits) {
    int index = --bits / 8;
    arr[index] &= ~(0x80 >> (bits % 8));
}

// 通过table盒替换src为target(以bit为单位进行替换)
void permute(unsigned char* src, unsigned char* target, int table[], int len) {
    int bits = 0;
    for (int i = 1; i <= len; i++) {
        bits = table[i - 1];
        if (get_bit(src, bits)) {
            set_bit(target, i);
        } else {
            clear_bit(target, i);
        }
    }
}

//56位子密钥循环左移
void sub_shift_l(unsigned char arr[7]) {
    int t = arr[0] & 0x80 ? 1 : 0;

    arr[0] = arr[0] << 1 | (arr[1] & 0x80 ? 1 : 0);
    arr[1] = arr[1] << 1 | (arr[2] & 0x80 ? 1 : 0);
    arr[2] = arr[2] << 1 | (arr[3] & 0x80 ? 1 : 0);

    arr[3] = (arr[3] & 0xf0) << 1 | arr[3] & 0x0f;
    arr[3] |= t ? 0x10 : 0x00;

    t = arr[3] & 0x08 ? 1 : 0;
    arr[3] = arr[3] & 0xf0 | (arr[3] & 0x07) << 1 | (arr[4] & 0x80 ? 1 : 0);

    arr[4] = arr[4] << 1 | (arr[5] & 0x80 ? 1 : 0);
    arr[5] = arr[5] << 1 | (arr[6] & 0x80 ? 1 : 0);
    arr[6] = arr[6] << 1 | t;
}

//56位子密钥循环右移
void sub_shift_r(unsigned char arr[7]) {
    int t = arr[3] & 0x10 ? 1 : 0;

    arr[3] = ((arr[3] & 0xe0) >> 1) | (arr[2] & 0x01 ? 0x80 : 0) | arr[3] & 0x0f;

    arr[2] = arr[2] >> 1 | (arr[1] & 0x01 ? 0x80 : 0);
    arr[1] = arr[1] >> 1 | (arr[0] & 0x01 ? 0x80 : 0);
    arr[0] = arr[0] >> 1 | (t ? 0x80 : 0);

    t = arr[6] & 0x01 ? 1 : 0;

    arr[6] = arr[6] >> 1 | (arr[5] & 0x01 ? 0x80 : 0);
    arr[5] = arr[5] >> 1 | (arr[4] & 0x01 ? 0x80 : 0);
    arr[4] = arr[4] >> 1 | (arr[3] & 0x01 ? 0x80 : 0);

    arr[3] = arr[3] & 0xf0 | (arr[3] & 0x0f) >> 1 | (t ? 0x08 : 0);
}

void sbox_permute(unsigned char arr[6], unsigned char target[4]) {
    int num;

    num = (arr[0] & 0xfc) >> 2;
    target[0] = sbox[0][num] << 4;
    num = (arr[0] & 0x03) << 4 | (arr[1] & 0xf0) >> 4;
    target[0] |= sbox[1][num];


    num = (arr[1] & 0x0f) << 2 | (arr[2] & 0xc0) >> 6;
    target[1] = sbox[2][num] << 4;
    num = (arr[2] & 0x3f);
    target[1] |= sbox[3][num];

    num = (arr[3] & 0xfc) >> 2;
    target[2] = sbox[4][num] << 4;
    num = (arr[3] & 0x03) << 4 | (arr[4] & 0xf0) >> 4;
    target[2] |= sbox[5][num];


    num = (arr[4] & 0x0f) << 2 | (arr[5] & 0xc0) >> 6;
    target[3] = sbox[6][num] << 4;
    num = (arr[5] & 0x3f);
    target[3] |= sbox[7][num];
}

void des_block_operate(
    unsigned char* input,
    unsigned char* key,
    unsigned char* out,
    op_type type
) {
    unsigned char L[4];
    unsigned char R[4];
    unsigned char S[4];
    unsigned char P[4];
    unsigned char block[8];
    unsigned char expansion_block[6];
    unsigned char pc1_key[7];
    unsigned char sub_key[6];

    permute(key, pc1_key, pc1_table, 7 * 8);
    permute(input, block, ip_table, 8 * 8);
    memcpy(L, block, 4);
    memcpy(R, block + 4, 4);

    for (int i = 0; i < 16; i++) {
        permute(R, expansion_block, expansion_table, 6 * 8);
        if (type == OP_ENCRYPT) {
            sub_shift_l(pc1_key);
            if (!(i == 0 || i == 1 || i == 8 || i == 15)) {
                sub_shift_l(pc1_key);
            }
        }
        permute(pc1_key, sub_key, pc2_table, 6 * 8);
        if (type == OP_DECRYPT) {
            sub_shift_r(pc1_key);
            if (!(i == 15 || i == 14 || i == 7 || i == 0)) {
                sub_shift_r(pc1_key);
            }
        }
        _xor(expansion_block, sub_key, 6);
        sbox_permute(expansion_block, S);
        permute(S, P, p_table, 4 * 8);
        _xor(P, L, 4);
        memcpy(L, R, 4);
        memcpy(R, P, 4);
    }

    memcpy(block, R, 4);
    memcpy(block + 4, L, 4);
    permute(block, out, ip_table_inverse, 8 * 8);
}

void des_operate(
    unsigned char* input,
    int input_len,
    unsigned char* out,
    unsigned char* iv,
    unsigned char* key,
    op_type type,
    int triplicate
) {
    unsigned char input_block[8];
    unsigned char iv_block[8];
    memcpy(iv_block, iv, 8);
    while (input_len >= 8) {
        memcpy(input_block, input, 8);
        if (type == OP_ENCRYPT) {
            _xor(input_block, iv_block, 8); //CBC模式
            des_block_operate(input_block, key, out, type);
            if (triplicate) { //三重DES
                memcpy(input_block, out, 8);
                des_block_operate(input_block, key + 8, out, OP_DECRYPT);
                memcpy(input_block, out, 8);
                des_block_operate(input_block, key + 16, out, type);
            }
            memcpy(iv_block, out, 8);
        } else {
            if (triplicate) { //三重DES
                des_block_operate(input_block, key + 16, out, type);
                memcpy(input_block, out, 8);
                des_block_operate(input_block, key + 8, out, OP_ENCRYPT);
                memcpy(input_block, out, 8);
                des_block_operate(input_block, key, out, type);
            } else {
                des_block_operate(input_block, key, out, type);
            }
            _xor(out, iv_block, 8); //CBC模式
            memcpy(iv_block, input, 8);
        }
        input += 8;
        out += 8;
        input_len -= 8;
    }

}

void des_encrypt(
    unsigned char* input,
    int input_len,
    unsigned char* out,
    unsigned char* iv,
    unsigned char* key
) {
    des_operate(input, input_len, out, iv, key, OP_ENCRYPT, 0);
}

void des_decrypt(
    unsigned char* input,
    int input_len,
    unsigned char* out,
    unsigned char* iv,
    unsigned char* key
) {
    des_operate(input, input_len, out, iv, key, OP_DECRYPT, 0);
}

void des3_encrypt(
    unsigned char* input,
    int input_len,
    unsigned char* out,
    unsigned char* iv,
    unsigned char* key
) {
    des_operate(input, input_len, out, iv, key, OP_ENCRYPT, 1);
}

void des3_decrypt(
    unsigned char* input,
    int input_len,
    unsigned char* out,
    unsigned char* iv,
    unsigned char* key
) {
    des_operate(input, input_len, out, iv, key, OP_DECRYPT, 1);
}

#define TEST_DES
#ifdef TEST_DES
int main() {
    // unsigned char target[7];
    // unsigned char key[] = "12345678";
    // permute(key, target, pc1_table, 56);
    // show_hex(target, 7, 1);
    // for (int i = 0; i < 28; i++) {
    //     sub_shift_l(target);
    //     show_hex(target, 7, 1);
    // }
    // for (int i = 0; i < 28; i++) {
    //     sub_shift_r(target);
    //     show_hex(target, 7, 1);
    // }

    // unsigned char sub_keys[16][6];
    // sub_key_expand(sub_keys, (unsigned char*)"password");

    unsigned char enc[16];
    unsigned char dec[16];

    // des_block_operate((unsigned char*)"abcdefgh", (unsigned char*)"password", enc, OP_ENCRYPT);
    // show_hex(enc, 8, 1);
    // des_block_operate(enc, (unsigned char*)"password", dec, OP_DECRYPT);
    // show_hex(dec, 8, 1);

    // des_operate((unsigned char*)"abcdefghabcdefgh", 16, enc, (unsigned char*)"initialz", (unsigned char*)"password", OP_ENCRYPT, 0);
    // show_hex(enc, 16, 1);
    // des_operate(enc, 16, dec, (unsigned char*)"initialz", (unsigned char*)"password", OP_DECRYPT, 0);
    // show_hex(dec, 16, 1);

    unsigned char iv[8] = "initialz";
    des3_encrypt((unsigned char*)"abcdefghabcdefgh", 16, enc, iv, (unsigned char*)"password12345678abcd1234");
    show_hex(enc, 16, 1);
    des3_decrypt(enc, 16, dec, iv, (unsigned char*)"password12345678abcd1234");
    show_hex(dec, 16, 1);
}
#endif
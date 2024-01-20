#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hex.h"
#include "aes.h"

#define AES_BLOCK_SIZE 16
#define MAC_LENGTH     8

static unsigned char sbox[16][16] = {
    {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
    },
    {
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0
    },
    {
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
        0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15
    },
    {
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
        0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75
    },
    {
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
        0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84
    },
    {
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf
    },
    {
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
        0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8
    },
    {
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2
    },
    {
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
        0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73
    },
    {
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
        0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb
    },
    {
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
        0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79
    },
    {
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
        0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08
    },
    {
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
        0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a
    },
    {
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
        0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e
    },
    {
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
        0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf
    },
    {
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
        0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    },
};

static unsigned char inv_sbox[16][16] = {
    {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
        0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb
    },
    {
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
        0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb
    },
    {
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
        0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e
    },
    {
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
        0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25
    },
    {
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
        0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92
    },
    {
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
        0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84
    },
    {
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
        0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06
    },
    {
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
        0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b
    },
    {
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
        0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73
    },
    {
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
        0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e
    },
    {
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
        0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b
    },
    {
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
        0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4
    },
    {
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
        0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f
    },
    {
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
        0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef
    },
    {
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
        0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61
    },
    {
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
        0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    },
};

static unsigned char mix_box[4][4] = {
    {
        0x02, 0x03, 0x01, 0x01
    },
    {
        0x01, 0x02, 0x03, 0x01
    },
    {
        0x01, 0x01, 0x02, 0x03
    },
    {
        0x03, 0x01, 0x01, 0x02
    },
};

static unsigned char mix_inv_box[4][4] = {
    {
        0x0e, 0x0b, 0x0d, 0x09
    },
    {
        0x09, 0x0e, 0x0b, 0x0d
    },
    {
        0x0d, 0x09, 0x0e, 0x0b
    },
    {
        0x0b, 0x0d, 0x09, 0x0e
    },
};

void xor (unsigned char* target, unsigned char* x, int len) {
    while (len > 0) {
        *target++ ^= *x++;
        len--;
    }

}

unsigned char gf_mul2(unsigned char x) {
    return (x << 1) ^ ((x & 0x80) ? 0x1b : 0x00);
}

// gf(2^8)域上的乘法
unsigned char gf_mul(unsigned char x, unsigned char y) {
    unsigned char mask = 0x01;
    unsigned char res = 0;
    for (int i = 0; i < 8; i++) {
        if (mask & y) {
            res ^= x;
        }
        mask <<= 1;
        x = gf_mul2(x);
    }
    return res;
}

// gf(2^128)上的乘法
void gf_128_mul(unsigned char* A, unsigned char* B, unsigned char* Z) {
    int lsb = 0;
    unsigned char V[AES_BLOCK_SIZE];
    unsigned char R[AES_BLOCK_SIZE];

    memset(Z, 0, AES_BLOCK_SIZE);
    memset(R, 0, AES_BLOCK_SIZE);
    memcpy(V, B, AES_BLOCK_SIZE);

    R[0] = 0xE1;

    for (int i = 0; i < 16; i++) {
        for (int mask = 0x80; mask; mask >>= 1) {
            if (A[i] & mask) {
                xor (Z, V, AES_BLOCK_SIZE);
            }
            lsb = V[AES_BLOCK_SIZE - 1] & 0x01;
            for (int j = AES_BLOCK_SIZE - 1; j > 0; j--) {
                V[j] = (V[j] >> 1) | (V[j - 1] & 0x01 ? 0x80 : 0x00);
            }
            V[0] >>= 1;
            if (lsb) {
                xor (V, R, AES_BLOCK_SIZE);
            }
        }
    }
}

void g_hash(unsigned char* input, int inputLen, unsigned char* H, unsigned char* macBlock) {
    unsigned char inputBlock[AES_BLOCK_SIZE] = { 0 };
    memset(macBlock, 0, AES_BLOCK_SIZE);
    while (inputLen > 0) {
        memset(inputBlock, 0, AES_BLOCK_SIZE);
        memcpy(inputBlock, input, inputLen >= AES_BLOCK_SIZE ? AES_BLOCK_SIZE : inputLen);
        xor (inputBlock, macBlock, AES_BLOCK_SIZE);
        gf_128_mul(inputBlock, H, macBlock);
        input += AES_BLOCK_SIZE;
        inputLen -= AES_BLOCK_SIZE;
    }
}

void cbc_mac(unsigned char* input, int inputLen, unsigned char* mac, unsigned char* key, int keyLen) {
    unsigned char inputBlock[AES_BLOCK_SIZE] = { 0 };
    unsigned char macBlock[AES_BLOCK_SIZE] = { 0 };
    while (inputLen >= AES_BLOCK_SIZE) {
        memcpy(inputBlock, input, AES_BLOCK_SIZE);
        xor (inputBlock, macBlock, AES_BLOCK_SIZE);
        aes_block_encrypt(inputBlock, macBlock, key, keyLen);
        input += AES_BLOCK_SIZE;
        inputLen -= AES_BLOCK_SIZE;
    }
    memcpy(mac, macBlock, MAC_LENGTH);
}

void rot_word(unsigned char* w) {
    unsigned char tmp = w[0];
    w[0] = w[1];
    w[1] = w[2];
    w[2] = w[3];
    w[3] = tmp;
}

void sub_word(unsigned char* w) {
    unsigned char tmp;
    for (int i = 0; i < 4; i++) {
        tmp = w[i];
        tmp = sbox[(tmp >> 4) & 0x0f][tmp & 0x0f];
        w[i] = tmp;
    }
}

// 密钥扩展
void sub_key_expand(unsigned char words[][4], unsigned char key[], int keyLen) {
    int keyWords = keyLen >> 2;
    int rounds = (keyLen >> 2) + 6; //加密轮数
    unsigned char rcon = 0x01;
    memcpy(words, key, keyLen);
    for (int i = keyWords; i < 4 * (rounds + 1); i++) {
        memcpy(words[i], words[i - 1], 4);
        if (i % keyWords == 0) {
            rot_word(words[i]);
            sub_word(words[i]);
            if (i % 36 == 0) {
                rcon = 0x1b;
            }
            words[i][0] ^= rcon;
            rcon <<= 1;
        } else if ((keyWords > 6) && ((i % keyWords) == 4)) {
            sub_word(words[i]);
        }
        words[i][0] ^= words[i - keyWords][0];
        words[i][1] ^= words[i - keyWords][1];
        words[i][2] ^= words[i - keyWords][2];
        words[i][3] ^= words[i - keyWords][3];
    }
}

// S盒替换
void sub_state(unsigned char state[][4], unsigned char box[][16]) {
    unsigned char c;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            c = state[i][j];
            c = box[(c >> 4) & 0x0f][c & 0x0f];
            state[i][j] = c;
        }
    }
}

// 行移位
void shift_rows(unsigned char state[][4], int isInvert) {
    unsigned char c;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < i; j++) {
            if (isInvert) { //右移一个字节
                c = state[i][3];
                state[i][3] = state[i][2];
                state[i][2] = state[i][1];
                state[i][1] = state[i][0];
                state[i][0] = c;
            } else { //左移一个字节
                c = state[i][0];
                state[i][0] = state[i][1];
                state[i][1] = state[i][2];
                state[i][2] = state[i][3];
                state[i][3] = c;
            }
        }
    }
}

// 列混合
void mix_colums(unsigned char state[][4], unsigned char mix_box[][4]) {
    unsigned char tmpState[4][4];
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            tmpState[i][j] =
                gf_mul(mix_box[i][0], state[0][j]) ^
                gf_mul(mix_box[i][1], state[1][j]) ^
                gf_mul(mix_box[i][2], state[2][j]) ^
                gf_mul(mix_box[i][3], state[3][j]);
        }
    }
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = tmpState[i][j];
        }
    }
}

// 密钥加
void word_xor(unsigned char state[][4], unsigned char words[][4]) {
    for (int i = 0; i < 4; i++) {
        state[0][i] ^= words[i][0];
        state[1][i] ^= words[i][1];
        state[2][i] ^= words[i][2];
        state[3][i] ^= words[i][3];
    }
}

void aes_block_encrypt(unsigned char* inputBlock, unsigned char* outBlock, unsigned char* key, int keyLen) {
    unsigned char state[4][4]; //状态表
    unsigned char words[60][4];
    int rounds = (keyLen >> 2) + 6; //加密轮数

    for (int r = 0; r < 4; r++) { //分组块
        for (int c = 0; c < 4; c++) {
            state[r][c] = inputBlock[r + (4 * c)];
        }
    }

    sub_key_expand(words, key, keyLen);
    word_xor(state, &words[0]);

    for (int i = 0; i < rounds; i++) {
        sub_state(state, sbox);
        shift_rows(state, 0);
        if (i < rounds - 1) {
            mix_colums(state, mix_box);
        }
        word_xor(state, &words[(i + 1) * 4]);
    }
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            outBlock[r + (4 * c)] = state[r][c];
        }
    }
}

void aes_block_decrypt(unsigned char* inputBlock, unsigned char* outBlock, unsigned char* key, int keyLen) {
    unsigned char state[4][4]; //状态表
    unsigned char words[60][4];
    int rounds = (keyLen >> 2) + 6; //加密轮数

    for (int r = 0; r < 4; r++) { //分组块
        for (int c = 0; c < 4; c++) {
            state[r][c] = inputBlock[r + (4 * c)];
        }
    }

    sub_key_expand(words, key, keyLen);
    word_xor(state, &words[rounds * 4]);

    for (int i = rounds; i > 0; i--) {
        shift_rows(state, 1);
        sub_state(state, inv_sbox);
        word_xor(state, &words[(i - 1) * 4]);
        if (i > 1) {
            mix_colums(state, mix_inv_box);
        }
    }
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            outBlock[r + (4 * c)] = state[r][c];
        }
    }
}

void aes_encrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* key, int keyLen) {
    unsigned char inputBlock[AES_BLOCK_SIZE] = { 0 };

    while (inputLen >= AES_BLOCK_SIZE) { //CBC模式下最后一块数据不满一个分组的情况下需要填充
        memcpy(inputBlock, input, AES_BLOCK_SIZE);
        xor (inputBlock, iv, AES_BLOCK_SIZE);
        aes_block_encrypt(inputBlock, out, key, keyLen);
        memcpy(iv, out, AES_BLOCK_SIZE); //CBC mode
        input += AES_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;
        inputLen -= AES_BLOCK_SIZE;
    }
}

void aes_decrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* key, int keyLen) {
    unsigned char inputBlock[AES_BLOCK_SIZE] = { 0 };

    while (inputLen >= AES_BLOCK_SIZE) { //CBC模式下最后一块数据不满一个分组的情况下需要填充
        memcpy(inputBlock, input, AES_BLOCK_SIZE);
        aes_block_decrypt(inputBlock, out, key, keyLen);
        xor (out, iv, AES_BLOCK_SIZE);
        memcpy(iv, inputBlock, AES_BLOCK_SIZE); //CBC mode
        input += AES_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;
        inputLen -= AES_BLOCK_SIZE;
    }
}

void aes_ctr_process(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* key, int keyLen, int decrypt) {
    unsigned char nonce[AES_BLOCK_SIZE] = { 0 };
    unsigned char inputBlock[AES_BLOCK_SIZE] = { 0 };
    unsigned char macBlock[AES_BLOCK_SIZE] = { 0 };
    int counter = 0;
    int blockSize = 0;
    int ivLen = strlen((const char*)iv);

    memcpy(nonce, iv, ivLen > 12 ? 12 : ivLen);

    while (inputLen) {
        int c = htonl(counter++);
        blockSize = inputLen >= AES_BLOCK_SIZE ? AES_BLOCK_SIZE : inputLen;
        memcpy(nonce + 12, (void*)&c, sizeof(unsigned int));
        aes_block_encrypt(nonce, inputBlock, key, keyLen);
        xor (inputBlock, input, blockSize); //CTR
        memcpy(out, inputBlock, blockSize);

        input += blockSize;
        out += blockSize;
        inputLen -= blockSize;
    }
}

int aes_ccm_process(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* add, int addLen, unsigned char* key, int keyLen, int decrypt) {
    unsigned char nonce[AES_BLOCK_SIZE] = { 0 };
    unsigned char inputBlock[AES_BLOCK_SIZE] = { 0 };
    unsigned char macBlock[AES_BLOCK_SIZE] = { 0 };
    int processLen = inputLen - (decrypt ? MAC_LENGTH : 0);
    int headerLengthDeclaration = htonl(processLen);
    int counter = 0;
    int blockSize = 0;
    int ivLen = strlen((const char*)iv);

    nonce[0] = 0x1f;
    nonce[0] |= addLen ? 0x40 : 0x00;
    memcpy(nonce + 1, iv, ivLen > 8 ? 8 : ivLen);
    memcpy(nonce + AES_BLOCK_SIZE - sizeof(unsigned int), (void*)&headerLengthDeclaration, sizeof(unsigned int));
    xor (nonce, macBlock, AES_BLOCK_SIZE);
    aes_block_encrypt(nonce, macBlock, key, keyLen);

    if (addLen) {
        int addLenDeclaration = ntohs(addLen);
        int addBlockSize = AES_BLOCK_SIZE - sizeof(unsigned short);
        memset(inputBlock, 0, AES_BLOCK_SIZE);
        memcpy(inputBlock, (void*)&addLenDeclaration, sizeof(unsigned short));

        while (addLen) {
            blockSize = addLen > addBlockSize ? addBlockSize : addLen;
            memcpy(inputBlock + (AES_BLOCK_SIZE - addBlockSize), add, blockSize);
            xor (inputBlock, macBlock, AES_BLOCK_SIZE);
            aes_block_encrypt(inputBlock, macBlock, key, keyLen);
            memset(inputBlock, 0, AES_BLOCK_SIZE);

            addBlockSize = AES_BLOCK_SIZE;
            add += blockSize;
            addLen -= blockSize;
        }
    }
    memset(nonce, 0, AES_BLOCK_SIZE);
    nonce[0] = 0x07;
    memcpy(nonce + 1, iv, ivLen > 8 ? 8 : ivLen);
    while (processLen) {
        int c = htonl(++counter);
        blockSize = processLen >= AES_BLOCK_SIZE ? AES_BLOCK_SIZE : processLen;
        memcpy(nonce + 12, (void*)&c, sizeof(unsigned int));
        aes_block_encrypt(nonce, inputBlock, key, keyLen);
        xor (inputBlock, input, blockSize); //CTR
        memcpy(out, inputBlock, blockSize);

        // 计算MAC--begin
        if (!decrypt) { //根据明文来计算的
            memcpy(inputBlock, input, blockSize);
        }
        if (blockSize < AES_BLOCK_SIZE) {
            memset(inputBlock + blockSize, 0, AES_BLOCK_SIZE - blockSize);
        }
        xor (inputBlock, macBlock, AES_BLOCK_SIZE);
        aes_block_encrypt(inputBlock, macBlock, key, keyLen);
        // 计算MAC--end
        input += blockSize;
        out += blockSize;
        processLen -= blockSize;
    }
    memset(nonce, 0, AES_BLOCK_SIZE);
    nonce[0] = 0x07;
    memcpy(nonce + 1, iv, ivLen > 8 ? 8 : ivLen);
    aes_block_encrypt(nonce, inputBlock, key, keyLen);
    if (!decrypt) {
        xor (macBlock, inputBlock, MAC_LENGTH);
        memcpy(out, macBlock, MAC_LENGTH);
    } else {
        xor (inputBlock, input, MAC_LENGTH);
        if (memcmp(inputBlock, macBlock, MAC_LENGTH)) {
            printf("C-MAC is wrong\n");
            return -1;
        }
    }

    return 0;
}

int aes_gcm_process(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* add, int addLen, unsigned char* key, int keyLen, int decrypt) {
    unsigned char nonce[AES_BLOCK_SIZE] = { 0 };
    unsigned char H[AES_BLOCK_SIZE] = { 0 };
    unsigned char zeros[AES_BLOCK_SIZE] = { 0 };
    unsigned char inputBlock[AES_BLOCK_SIZE] = { 0 };
    unsigned char macBlock[AES_BLOCK_SIZE] = { 0 };
    int processLen = inputLen - (decrypt ? AES_BLOCK_SIZE : 0);
    int originLen = htonl(processLen << 3);
    int originAddLen = htonl(addLen << 3);
    int counter = 1;
    int blockSize = 0;
    int ivLen = strlen((const char*)iv);

    aes_block_encrypt(zeros, H, key, keyLen);
    g_hash(add, addLen, H, macBlock);
    memcpy(nonce, iv, ivLen > 12 ? 12 : ivLen);

    while (processLen) {
        int c = htonl(++counter);
        blockSize = processLen >= AES_BLOCK_SIZE ? AES_BLOCK_SIZE : processLen;
        memcpy(nonce + 12, (void*)&c, sizeof(unsigned int));
        aes_block_encrypt(nonce, inputBlock, key, keyLen);
        xor (inputBlock, input, blockSize); //CTR
        memcpy(out, inputBlock, blockSize);

        // 计算MAC--begin
        if (decrypt) { //GMAC是根据密来计算的
            memcpy(inputBlock, input, blockSize);
        }
        if (blockSize < AES_BLOCK_SIZE) {
            memset(inputBlock + blockSize, 0, AES_BLOCK_SIZE - blockSize);
        }
        xor (inputBlock, macBlock, AES_BLOCK_SIZE);
        gf_128_mul(inputBlock, H, macBlock);
        // 计算MAC--end
        input += blockSize;
        out += blockSize;
        processLen -= blockSize;
    }

    memset(inputBlock, 0, AES_BLOCK_SIZE);
    memcpy(inputBlock + 4, (void*)&originAddLen, sizeof(unsigned int));
    memcpy(inputBlock + 12, (void*)&originLen, sizeof(unsigned int));
    xor (inputBlock, macBlock, AES_BLOCK_SIZE);
    memset(nonce + 12, 0, sizeof(unsigned int));
    nonce[15] = 0x01;

    gf_128_mul(inputBlock, H, macBlock);
    aes_block_encrypt(nonce, inputBlock, key, 16);
    if (!decrypt) {
        xor (inputBlock, macBlock, AES_BLOCK_SIZE);
        memcpy(out, inputBlock, AES_BLOCK_SIZE);
    } else {
        xor (inputBlock, input, AES_BLOCK_SIZE);
        if (memcmp(inputBlock, macBlock, AES_BLOCK_SIZE)) {
            printf("G-MAC is wrong\n");
            return -1;
        }
    }

    return 0;
}

void aes_128_encrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* key) {
    aes_encrypt(input, inputLen, out, iv, key, 16);
}

void aes_128_decrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* key) {
    aes_decrypt(input, inputLen, out, iv, key, 16);
}

void aes_256_encrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* key) {
    aes_encrypt(input, inputLen, out, iv, key, 32);
}

void aes_256_decrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* key) {
    aes_decrypt(input, inputLen, out, iv, key, 32);
}

void aes_128_ctr_encrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* key) {
    aes_ctr_process(input, inputLen, out, iv, key, 16, 0);
}

void aes_128_ctr_decrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* key) {
    aes_ctr_process(input, inputLen, out, iv, key, 16, 1);
}

void aes_256_ctr_encrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* key) {
    aes_ctr_process(input, inputLen, out, iv, key, 32, 0);
}

void aes_256_ctr_decrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* key) {
    aes_ctr_process(input, inputLen, out, iv, key, 32, 1);
}

void aes_128_ccm_encrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* add, int addLen, unsigned char* key) {
    aes_ccm_process(input, inputLen, out, iv, add, addLen, key, 16, 0);
}

void aes_128_ccm_decrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* add, int addLen, unsigned char* key) {
    aes_ccm_process(input, inputLen, out, iv, add, addLen, key, 16, 1);
}

void aes_256_ccm_encrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* add, int addLen, unsigned char* key) {
    aes_ccm_process(input, inputLen, out, iv, add, addLen, key, 32, 0);
}

void aes_256_ccm_decrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* add, int addLen, unsigned char* key) {
    aes_ccm_process(input, inputLen, out, iv, add, addLen, key, 32, 1);
}

void aes_128_gcm_encrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* add, int addLen, unsigned char* key) {
    aes_gcm_process(input, inputLen, out, iv, add, addLen, key, 16, 0);
}

void aes_128_gcm_decrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* add, int addLen, unsigned char* key) {
    aes_gcm_process(input, inputLen, out, iv, add, addLen, key, 16, 1);
}

void aes_256_gcm_encrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* add, int addLen, unsigned char* key) {
    aes_gcm_process(input, inputLen, out, iv, add, addLen, key, 32, 0);
}

void aes_256_gcm_decrypt(unsigned char* input, int inputLen, unsigned char* out, unsigned char* iv, unsigned char* add, int addLen, unsigned char* key) {
    aes_gcm_process(input, inputLen, out, iv, add, addLen, key, 32, 1);
}

// #define TEST_AES
#ifdef TEST_AES
void test_cbc_mac() {
    unsigned char key[] = "1234567812345678";
    unsigned char input[] = "this is a text,this is a text,this is a text!";
    unsigned char mac[MAC_LENGTH];
    int keyLen = 16;
    int inputLen = 45;

    printf("---------------test_cbc_mac---------------\n");
    cbc_mac(input, inputLen, mac, key, keyLen);
    show_hex(mac, MAC_LENGTH, 1);
}

void test_aes_128() {
    unsigned char key[] = "1234567812345678";
    unsigned char input[] = "this is a text,this is a text,this is a text!";
    unsigned char iv[] = "9999999999999999";
    int ivLen = 16;
    int inputLen = 45;
    unsigned char* ciphertext = (unsigned char*)malloc(inputLen);
    unsigned char* out = (unsigned char*)malloc(inputLen);

    printf("---------------test_aes_128---------------\n");
    aes_128_encrypt(input, inputLen, ciphertext, iv, key);
    show_hex(ciphertext, inputLen, 1);
    aes_128_decrypt(ciphertext, inputLen, out, iv, key);
    printf("%s\n", out);
}

void test_aes_256() {
    unsigned char key[] = "12345678123456781234567812345678";
    unsigned char input[] = "this is a text,this is a text,this is a text!";
    unsigned char iv[] = "99999999999999999999999999999999";
    int key_len = 32;
    int ivLen = 32;
    int inputLen = 45;
    unsigned char* ciphertext = (unsigned char*)malloc(inputLen);
    unsigned char* out = (unsigned char*)malloc(inputLen);

    printf("---------------test_aes_256---------------\n");
    aes_256_encrypt(input, inputLen, ciphertext, iv, key);
    show_hex(ciphertext, inputLen, 1);
    aes_256_decrypt(ciphertext, inputLen, out, iv, key);
    printf("%s\n", out);
}

void test_aes_128_ctr() {
    unsigned char key[] = "1234567812345678";
    unsigned char input[] = "this is a text,this is a text,this is a text!";
    unsigned char iv[] = "999999999999";
    int ivLen = 12;
    int inputLen = 45;
    unsigned char* ciphertext = (unsigned char*)malloc(inputLen);
    unsigned char* out = (unsigned char*)malloc(inputLen);

    printf("---------------test_aes_128_ctr---------------\n");
    aes_128_ctr_encrypt(input, inputLen, ciphertext, iv, key);
    show_hex(ciphertext, inputLen, 1);
    aes_128_ctr_decrypt(ciphertext, inputLen, out, iv, key);
    printf("%s\n", out);
}

void test_aes_256_ctr() {
    unsigned char key[] = "12345678123456781234567812345678";
    unsigned char input[] = "this is a text,this is a text,this is a text!";
    unsigned char iv[] = "999999999999";
    int ivLen = 12;
    int inputLen = 45;
    unsigned char* ciphertext = (unsigned char*)malloc(inputLen);
    unsigned char* out = (unsigned char*)malloc(inputLen);

    printf("---------------test_aes_256_ctr---------------\n");
    aes_256_ctr_encrypt(input, inputLen, ciphertext, iv, key);
    show_hex(ciphertext, inputLen, 1);
    aes_256_ctr_decrypt(ciphertext, inputLen, out, iv, key);
    printf("%s\n", out);
}

void test_aes_128_ccm() {
    unsigned char key[] = "1234567812345678";
    unsigned char input[] = "this is a text,this is a text,this is a text!";
    unsigned char iv[] = "99999999";
    unsigned char add[] = "test";
    int ivLen = 8;
    int inputLen = 45;
    int addLen = 4;
    unsigned char* ciphertext = (unsigned char*)malloc(inputLen + MAC_LENGTH);
    unsigned char* out = (unsigned char*)malloc(inputLen);

    printf("---------------test_aes_128_ccm---------------\n");
    aes_128_ccm_encrypt(input, inputLen, ciphertext, iv, add, addLen, key);
    show_hex(ciphertext, inputLen + MAC_LENGTH, 1);
    aes_128_ccm_decrypt(ciphertext, inputLen + MAC_LENGTH, out, iv, add, addLen, key);
    printf("%s\n", out);
}

void test_aes_256_ccm() {
    unsigned char key[] = "12345678123456781234567812345678";
    unsigned char input[] = "this is a text,this is a text,this is a text!";
    unsigned char iv[] = "99999999";
    unsigned char add[] = "test";
    int ivLen = 8;
    int inputLen = 45;
    int addLen = 4;
    unsigned char* ciphertext = (unsigned char*)malloc(inputLen + MAC_LENGTH);
    unsigned char* out = (unsigned char*)malloc(inputLen);

    printf("---------------test_aes_256_ccm---------------\n");
    aes_256_ccm_encrypt(input, inputLen, ciphertext, iv, add, addLen, key);
    show_hex(ciphertext, inputLen + MAC_LENGTH, 1);
    aes_256_ccm_decrypt(ciphertext, inputLen + MAC_LENGTH, out, iv, add, addLen, key);
    printf("%s\n", out);
}

void test_aes_128_gcm() {
    unsigned char key[] = "1234567812345678";
    unsigned char input[] = "this is a text,this is a text,this is a text!";
    unsigned char iv[] = "999999999999";
    unsigned char add[] = "test";
    int ivLen = 12;
    int inputLen = 45;
    int addLen = 4;
    unsigned char* ciphertext = (unsigned char*)malloc(inputLen + AES_BLOCK_SIZE);
    unsigned char* out = (unsigned char*)malloc(inputLen);

    printf("---------------test_aes_128_gcm---------------\n");
    aes_128_gcm_encrypt(input, inputLen, ciphertext, iv, add, addLen, key);
    show_hex(ciphertext, inputLen + AES_BLOCK_SIZE, 1);
    aes_128_gcm_decrypt(ciphertext, inputLen + AES_BLOCK_SIZE, out, iv, add, addLen, key);
    printf("%s\n", out);
}

void test_aes_256_gcm() {
    unsigned char key[] = "12345678123456781234567812345678";
    unsigned char input[] = "this is a text,this is a text,this is a text!";
    unsigned char iv[] = "999999999999";
    unsigned char add[] = "test";
    int ivLen = 12;
    int inputLen = 45;
    int addLen = 4;
    unsigned char* ciphertext = (unsigned char*)malloc(inputLen + AES_BLOCK_SIZE);
    unsigned char* out = (unsigned char*)malloc(inputLen);

    printf("---------------test_aes_256_gcm---------------\n");
    aes_256_gcm_encrypt(input, inputLen, ciphertext, iv, add, addLen, key);
    show_hex(ciphertext, inputLen + AES_BLOCK_SIZE, 1);
    aes_256_gcm_decrypt(ciphertext, inputLen + AES_BLOCK_SIZE, out, iv, add, addLen, key);
    printf("%s\n", out);
}

int main() {
    test_cbc_mac();
    test_aes_128();
    test_aes_256();
    test_aes_128_ctr();
    test_aes_256_ctr();
    test_aes_128_ccm();
    test_aes_256_ccm();
    test_aes_128_gcm();
    test_aes_256_gcm();
}
#endif
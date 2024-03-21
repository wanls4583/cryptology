#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sha.h"

u32 sha1_initial_hash[] = {
    0x01234567,
    0x89abcdef,
    0xfedcba98,
    0x76543210,
    0xf0e1d2c3
};

u32 sha256_initial_hash[] = {
    0x67e6096a,
    0x85ae67bb,
    0x72f36e3c,
    0x3af54fa5,
    0x7f520e51,
    0x8c68059b,
    0xabd9831f,
    0x19cde05b
};

u32 sha224_initial_hash[] = {
    0xd89e05c1,
    0x07d57c36,
    0x17dd7030,
    0x39590ef7,
    0x310bc0ff,
    0x11155868,
    0xa78ff964,
    0xa44ffabe
};

u64 sha512_initial_hash[] = {
    0x08c9bcf367e6096a,
    0x3ba7ca8485ae67bb,
    0x2bf894fe72f36e3c,
    0xf1361d5f3af54fa5,
    0xd182e6ad7f520e51,
    0x1f6c3e2b8c68059b,
    0x6bbd41fbabd9831f,
    0x79217e1319cde05b
};

u64 sha512_224_initial_hash[] = {
    0xA24D5419C8373D8C,
    0xD6D4DC896699E173,
    0x829CFF32AEB7FA1D,
    0xCF9F2F5814D59D67,
    0xA84DD47B692B6D0F,
    0x4289C404736FE377,
    0xC8361D6AA8859D3F,
    0xA192D691ADE61211
};

u64 sha512_256_initial_hash[] = {
    0x2CF72BFC94213122,
    0xC2644CC8A35F559F,
    0x51B1536F6BB89323,
    0xBDEA405919773896,
    0xE3FF8EA8E23E2896,
    0x92398653251E5EBE,
    0xAAB8852CFC99012B,
    0xA22CC581DC2DB70E
};

u64 sha384_initial_hash[] = {
    0xd89e05c15d9dbbcb,
    0x07d57c362a299a62,
    0x17dd70305a015991,
    0x39590ef7d8ec2f15,
    0x310bc0ff67263367,
    0x11155868874ab48e,
    0xa78ff9640d2e0cdb,
    0xa44ffabe1d48b547
};

static const int sha1_k[] = {
    0x5a827999, // 0 <= t <= 19
    0x6ed9eba1, // 20 <= t <= 39
    0x8f1bbcdc, // 40 <= t <= 59
    0xca62c1d6 // 60 <= t <= 79
};

static const u32 sha256_k[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const u64 sha512_k[] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

u32 ch(u32 x, u32 y, u32 z) {
    return (x & y) ^ (~x & z);
}

u32 maj(u32 x, u32 y, u32 z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

u32 parity(u32 x, u32 y, u32 z) {
    return x ^ y ^ z;
}

void sha1_block_operate(const u8* block, u32 hash[SHA1_RESULT_SIZE]) {
    u32 w[80];
    u32 a, b, c, d, e, tmp;

    for (int t = 0; t < 80; t++) { // 16个字扩展成80个字
        if (t < 16) { // 将以大端排序的明文分组存入w[0..15]
            w[t] = (((u32)block[t * 4]) << 24) | (((u32)block[t * 4 + 1]) << 16) | (((u32)block[t * 4 + 2]) << 8) | ((u32)block[t * 4 + 3]);
        } else {
            w[t] = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
            w[t] = (w[t] << 1) | ((w[t] & 0x80000000) >> 31); // 循环左移一位
        }
    }

    // 大端排序转化成小段排序
    hash[0] = ntohl(hash[0]);
    hash[1] = ntohl(hash[1]);
    hash[2] = ntohl(hash[2]);
    hash[3] = ntohl(hash[3]);
    hash[4] = ntohl(hash[4]);

    a = hash[0];
    b = hash[1];
    c = hash[2];
    d = hash[3];
    e = hash[4];

    for (int t = 0; t < 80; t++) {
        tmp = ((a << 5) | (a >> 27)) + e + w[t] + sha1_k[t / 20];
        if (t < 20) {
            tmp += ch(b, c, d);
        } else if (t < 40) {
            tmp += parity(b, c, d);
        } else if (t < 60) {
            tmp += maj(b, c, d);
        } else {
            tmp += parity(b, c, d);
        }

        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = tmp;
    }

    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;

    // hash最终结果为大端排序
    hash[0] = htonl(hash[0]);
    hash[1] = htonl(hash[1]);
    hash[2] = htonl(hash[2]);
    hash[3] = htonl(hash[3]);
    hash[4] = htonl(hash[4]);
}

u32 rotr(u32 x, u32 n) {
    return (x >> n) | (x << (32 - n));
}

u32 shr(u32 x, u32 n) {
    return x >> n;
}

u32 sigma_rot(u32 x, int i) {
    if (i) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    } else {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }
}

u32 sigma_shr(u32 x, int i) {
    if (i) {
        return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10);
    } else {
        return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3);
    }
}

void sha256_block_operate(const u8* block, u32 hash[SHA256_RESULT_SIZE]) {
    u32 w[64];
    u32 a, b, c, d, e, f, g, h;
    u32 t1, t2;

    for (int t = 0; t < 64; t++) { // 16个字扩展成64个字
        if (t < 16) { // 将以大端排序的明文分组存入w[0..15]
            w[t] = (((u32)block[t * 4]) << 24) | (((u32)block[t * 4 + 1]) << 16) | (((u32)block[t * 4 + 2]) << 8) | ((u32)block[t * 4 + 3]);
        } else {
            w[t] = sigma_shr(w[t - 2], 1) + w[t - 7] + sigma_shr(w[t - 15], 0) + w[t - 16];
        }
    }

    for (int i = 0; i < 8; i++) {
        hash[i] = ntohl(hash[i]);
    }

    a = hash[0];
    b = hash[1];
    c = hash[2];
    d = hash[3];
    e = hash[4];
    f = hash[5];
    g = hash[6];
    h = hash[7];

    for (int i = 0; i < 64; i++) {
        t1 = h + sigma_rot(e, 1) + ch(e, f, g) + sha256_k[i] + w[i];
        t2 = sigma_rot(a, 0) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    hash[0] = a + hash[0];
    hash[1] = b + hash[1];
    hash[2] = c + hash[2];
    hash[3] = d + hash[3];
    hash[4] = e + hash[4];
    hash[5] = f + hash[5];
    hash[6] = g + hash[6];
    hash[7] = h + hash[7];

    for (int i = 0; i < 8; i++) {
        hash[i] = htonl(hash[i]);
    }
}


u64 ch_64(u64 x, u64 y, u64 z) {
    return (x & y) ^ (~x & z);
}

u64 maj_64(u64 x, u64 y, u64 z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

u64 rotr_64(u64 x, u32 n) {
    return (x >> n) | (x << (64 - n));
}

u64 shr_64(u64 x, u32 n) {
    return x >> n;
}

u64 sigma_rot_64(u64 x, int i) {
    if (i) {
        return rotr_64(x, 14) ^ rotr_64(x, 18) ^ rotr_64(x, 41);
    } else {
        return rotr_64(x, 28) ^ rotr_64(x, 34) ^ rotr_64(x, 39);
    }
}

u64 sigma_shr_64(u64 x, int i) {
    if (i) {
        return rotr_64(x, 19) ^ rotr_64(x, 61) ^ shr_64(x, 6);
    } else {
        return rotr_64(x, 1) ^ rotr_64(x, 8) ^ shr_64(x, 7);
    }
}

void sha512_block_operate(const u8* block, u64 hash[SHA512_RESULT_SIZE]) {
    u64 w[80];
    u64 a, b, c, d, e, f, g, h;
    u64 t1, t2;

    for (int t = 0; t < 80; t++) { // 16个字扩展成80个字
        if (t < 16) { // 将以大端排序的明文分组存入w[0..15]
            w[t] =
                (((u64)block[t * 8]) << 56) |
                (((u64)block[t * 8 + 1]) << 48) |
                (((u64)block[t * 8 + 2]) << 40) |
                (((u64)block[t * 8 + 3]) << 32) |
                (((u64)block[t * 8 + 4]) << 24) |
                (((u64)block[t * 8 + 5]) << 16) |
                (((u64)block[t * 8 + 6]) << 8) |
                ((u64)block[t * 8 + 7]);
        } else {
            w[t] = sigma_shr_64(w[t - 2], 1) + w[t - 7] + sigma_shr_64(w[t - 15], 0) + w[t - 16];
        }
    }

    for (int i = 0; i < 8; i++) {
        hash[i] = ntohll(hash[i]);
    }

    a = hash[0];
    b = hash[1];
    c = hash[2];
    d = hash[3];
    e = hash[4];
    f = hash[5];
    g = hash[6];
    h = hash[7];

    for (int i = 0; i < 80; i++) {
        t1 = h + sigma_rot_64(e, 1) + ch_64(e, f, g) + sha512_k[i] + w[i];
        t2 = sigma_rot_64(a, 0) + maj_64(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    hash[0] = a + hash[0];
    hash[1] = b + hash[1];
    hash[2] = c + hash[2];
    hash[3] = d + hash[3];
    hash[4] = e + hash[4];
    hash[5] = f + hash[5];
    hash[6] = g + hash[6];
    hash[7] = h + hash[7];

    for (int i = 0; i < 8; i++) {
        hash[i] = htonll(hash[i]);
    }
}

// 大端排序存储真实数据长度
void sha1_finalize(u8* padded_block, int length_in_bits) {
    padded_block[SHA1_BLOCK_SIZE - 4] = (length_in_bits & 0xFF000000) >> 24;
    padded_block[SHA1_BLOCK_SIZE - 3] = (length_in_bits & 0x00FF0000) >> 16;
    padded_block[SHA1_BLOCK_SIZE - 2] = (length_in_bits & 0x0000FF00) >> 8;
    padded_block[SHA1_BLOCK_SIZE - 1] = (length_in_bits & 0x000000FF);
}

// 大端排序存储真实数据长度
void sha512_finalize(u8* padded_block, int length_in_bits) {
    padded_block[SHA512_BLOCK_SIZE - 4] = (length_in_bits & 0xFF000000) >> 24;
    padded_block[SHA512_BLOCK_SIZE - 3] = (length_in_bits & 0x00FF0000) >> 16;
    padded_block[SHA512_BLOCK_SIZE - 2] = (length_in_bits & 0x0000FF00) >> 8;
    padded_block[SHA512_BLOCK_SIZE - 1] = (length_in_bits & 0x000000FF);
}

int sha1_hash(u8* input, int len, u32 hash[SHA1_RESULT_SIZE]) {
    u8 padded_block[SHA1_BLOCK_SIZE];
    int length_in_bits = len * 8;

    hash[0] = sha1_initial_hash[0];
    hash[1] = sha1_initial_hash[1];
    hash[2] = sha1_initial_hash[2];
    hash[3] = sha1_initial_hash[3];
    hash[4] = sha1_initial_hash[4];

    while (len >= SHA1_BLOCK_SIZE) {
        sha1_block_operate(input, hash);
        len -= SHA1_BLOCK_SIZE;
        input += SHA1_BLOCK_SIZE;
    }

    memset(padded_block, 0, SHA1_BLOCK_SIZE);
    padded_block[0] = 0x80;

    if (len) {
        memcpy(padded_block, input, len);
        padded_block[len] = 0x80;
        if (len >= SHA1_INPUT_BLOCK_SIZE) {
            sha1_block_operate(padded_block, hash);
            memset(padded_block, 0, SHA1_BLOCK_SIZE);
        }
    }

    sha1_finalize(padded_block, length_in_bits);
    sha1_block_operate(padded_block, hash);

    return 0;
}

int sha256_hash(u8* input, int len, u32 hash[SHA256_RESULT_SIZE]) {
    u8 padded_block[SHA256_BLOCK_SIZE];
    int length_in_bits = len * 8;

    hash[0] = sha256_initial_hash[0];
    hash[1] = sha256_initial_hash[1];
    hash[2] = sha256_initial_hash[2];
    hash[3] = sha256_initial_hash[3];
    hash[4] = sha256_initial_hash[4];
    hash[5] = sha256_initial_hash[5];
    hash[6] = sha256_initial_hash[6];
    hash[7] = sha256_initial_hash[7];

    while (len >= SHA256_BLOCK_SIZE) {
        sha256_block_operate(input, hash);
        len -= SHA256_BLOCK_SIZE;
        input += SHA256_BLOCK_SIZE;
    }

    memset(padded_block, 0, SHA256_BLOCK_SIZE);
    padded_block[0] = 0x80;

    if (len) {
        memcpy(padded_block, input, len);
        padded_block[len] = 0x80;
        if (len >= SHA256_INPUT_BLOCK_SIZE) {
            sha256_block_operate(padded_block, hash);
            memset(padded_block, 0, SHA256_BLOCK_SIZE);
        }
    }

    sha1_finalize(padded_block, length_in_bits);
    sha256_block_operate(padded_block, hash);

    return 0;
}

int sha512_hash(u8* input, int len, u64 hash[SHA512_RESULT_SIZE]) {
    u8 padded_block[SHA512_BLOCK_SIZE];
    int length_in_bits = len * 8;

    hash[0] = sha512_initial_hash[0];
    hash[1] = sha512_initial_hash[1];
    hash[2] = sha512_initial_hash[2];
    hash[3] = sha512_initial_hash[3];
    hash[4] = sha512_initial_hash[4];
    hash[5] = sha512_initial_hash[5];
    hash[6] = sha512_initial_hash[6];
    hash[7] = sha512_initial_hash[7];

    while (len >= SHA512_BLOCK_SIZE) {
        sha512_block_operate(input, hash);
        len -= SHA512_BLOCK_SIZE;
        input += SHA512_BLOCK_SIZE;
    }

    memset(padded_block, 0, SHA512_BLOCK_SIZE);
    padded_block[0] = 0x80;

    if (len) {
        memcpy(padded_block, input, len);
        padded_block[len] = 0x80;
        if (len >= SHA512_INPUT_BLOCK_SIZE) {
            sha512_block_operate(padded_block, hash);
            memset(padded_block, 0, SHA512_BLOCK_SIZE);
        }
    }

    sha512_finalize(padded_block, length_in_bits);
    sha512_block_operate(padded_block, hash);

    return 0;
}

void new_sha1_digest(digest_ctx* context) {
    context->hash_size = SHA1_RESULT_SIZE;
    context->word_size = SHA1_WORD_SIZE;
    context->result_size = SHA1_BYTE_SIZE;
    context->digest_block_size = SHA1_BLOCK_SIZE;
    context->digest_input_block_size = SHA1_INPUT_BLOCK_SIZE;
    context->input_len = 0;
    context->block_len = 0;
    context->input = NULL;
    context->hash = (void*)malloc(context->hash_size * sizeof(u32));
    context->block = (u8*)malloc(context->digest_block_size);
    memcpy(context->hash, sha1_initial_hash, context->hash_size * sizeof(u32));
    memset(context->block, '\0', context->digest_block_size);
    context->block_operate = (block_operate)sha1_block_operate;
    context->block_finalize = sha1_finalize;
}

void new_sha256_digest(digest_ctx* context) {
    context->hash_size = SHA256_RESULT_SIZE;
    context->word_size = SHA256_WORD_SIZE;
    context->result_size = SHA256_BYTE_SIZE;
    context->digest_block_size = SHA256_BLOCK_SIZE;
    context->digest_input_block_size = SHA256_INPUT_BLOCK_SIZE;
    context->input_len = 0;
    context->block_len = 0;
    context->input = NULL;
    context->hash = (void*)malloc(context->hash_size * sizeof(u32));
    context->block = (u8*)malloc(context->digest_block_size);
    memcpy(context->hash, sha256_initial_hash, context->hash_size * sizeof(u32));
    memset(context->block, '\0', context->digest_block_size);
    context->block_operate = (block_operate)sha256_block_operate;
    context->block_finalize = sha1_finalize;
}

void new_sha224_digest(digest_ctx* context) {
    context->hash_size = SHA256_RESULT_SIZE;
    context->word_size = SHA256_WORD_SIZE;
    context->result_size = SHA224_BYTE_SIZE;
    context->digest_block_size = SHA256_BLOCK_SIZE;
    context->digest_input_block_size = SHA256_INPUT_BLOCK_SIZE;
    context->input_len = 0;
    context->block_len = 0;
    context->input = NULL;
    context->hash = (void*)malloc(context->hash_size * sizeof(u32));
    context->block = (u8*)malloc(context->digest_block_size);
    memcpy(context->hash, sha224_initial_hash, context->hash_size * sizeof(u32));
    memset(context->block, '\0', context->digest_block_size);
    context->block_operate = (block_operate)sha256_block_operate;
    context->block_finalize = sha1_finalize;
}

void new_sha512_digest(digest_ctx* context) {
    context->hash_size = SHA512_RESULT_SIZE;
    context->word_size = SHA512_WORD_SIZE;
    context->result_size = SHA512_BYTE_SIZE;
    context->digest_block_size = SHA512_BLOCK_SIZE;
    context->digest_input_block_size = SHA512_INPUT_BLOCK_SIZE;
    context->input_len = 0;
    context->block_len = 0;
    context->input = NULL;
    context->hash = (void*)malloc(context->hash_size * sizeof(u64));
    context->block = (u8*)malloc(context->digest_block_size);
    memcpy(context->hash, sha512_initial_hash, context->hash_size * sizeof(u64));
    memset(context->block, '\0', context->digest_block_size);
    context->block_operate = (block_operate)sha512_block_operate;
    context->block_finalize = sha512_finalize;
}

void new_sha512_224_digest(digest_ctx* context) {
    context->hash_size = SHA512_RESULT_SIZE;
    context->word_size = SHA512_WORD_SIZE;
    context->result_size = SHA224_BYTE_SIZE;
    context->digest_block_size = SHA512_BLOCK_SIZE;
    context->digest_input_block_size = SHA512_INPUT_BLOCK_SIZE;
    context->input_len = 0;
    context->block_len = 0;
    context->input = NULL;
    context->hash = (void*)malloc(context->hash_size * sizeof(u64));
    context->block = (u8*)malloc(context->digest_block_size);
    memcpy(context->hash, sha512_224_initial_hash, context->hash_size * sizeof(u64));
    memset(context->block, '\0', context->digest_block_size);
    context->block_operate = (block_operate)sha512_block_operate;
    context->block_finalize = sha512_finalize;
}

void new_sha512_256_digest(digest_ctx* context) {
    context->hash_size = SHA512_RESULT_SIZE;
    context->word_size = SHA512_WORD_SIZE;
    context->result_size = SHA256_BYTE_SIZE;
    context->digest_block_size = SHA512_BLOCK_SIZE;
    context->digest_input_block_size = SHA512_INPUT_BLOCK_SIZE;
    context->input_len = 0;
    context->input = NULL;
    context->block_len = 0;
    context->hash = (void*)malloc(context->hash_size * sizeof(u64));
    context->block = (u8*)malloc(context->digest_block_size);
    memcpy(context->hash, sha512_256_initial_hash, context->hash_size * sizeof(u64));
    memset(context->block, '\0', context->digest_block_size);
    context->block_operate = (block_operate)sha512_block_operate;
    context->block_finalize = sha512_finalize;
}

void new_sha384_digest(digest_ctx* context) {
    context->hash_size = SHA512_RESULT_SIZE;
    context->word_size = SHA512_WORD_SIZE;
    context->result_size = SHA384_BYTE_SIZE;
    context->digest_block_size = SHA512_BLOCK_SIZE;
    context->digest_input_block_size = SHA512_INPUT_BLOCK_SIZE;
    context->input_len = 0;
    context->block_len = 0;
    context->input = NULL;
    context->hash = (void*)malloc(context->hash_size * sizeof(u64));
    context->block = (u8*)malloc(context->digest_block_size);
    memcpy(context->hash, sha384_initial_hash, context->hash_size * sizeof(u64));
    memset(context->block, '\0', context->digest_block_size);
    context->block_operate = (block_operate)sha512_block_operate;
    context->block_finalize = sha512_finalize;
}
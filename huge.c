#include <string.h>
#include <stdlib.h>
#include "huge.h"
#include "hex.h"
#include <stdio.h>
#include <time.h>

void huge_swap(huge* a, huge* b) {
    huge_word* rep = a->rep;
    unsigned int size = a->size;
    a->rep = b->rep;
    a->size = b->size;
    b->rep = rep;
    b->size = size;
}

void expand(huge* h) {
    huge_word* tmp = h->rep;
    h->rep = (huge_word*)malloc(h->size * HUGE_WORD_BYTES);
    memcpy(h->rep + 1, tmp, h->size * HUGE_WORD_BYTES);
    h->size++;
    h->rep[0] = 0x01;
    free(tmp);
}

void expand_right(huge* h, int size) {
    if (size <= 0 || h->size == 1 && !h->rep[0]) {
        return;
    }
    h->rep = (huge_word*)realloc(h->rep, (h->size + size) * HUGE_WORD_BYTES);
    memset(h->rep + h->size, 0, size * HUGE_WORD_BYTES);
    h->size += size;
}

void huge_copy(huge* a, huge* b) {
    if (a->rep && a->size) {
        free(a->rep);
    }
    a->sign = b->sign;
    a->size = b->size;
    a->rep = (huge_word*)malloc(b->size * HUGE_WORD_BYTES);
    memcpy(a->rep, b->rep, b->size * HUGE_WORD_BYTES);
}

void huge_load(huge* h, unsigned char* c, int length) {
    int i = 0, len = length;
    while (!c[i] && len) {
        i++;
        len--;
    }
    h->sign = 0;
    h->size = (len + HUGE_WORD_BYTES - 1) / HUGE_WORD_BYTES;
    h->size = h->size == 0 ? 1 : h->size;
    h->rep = (huge_word*)malloc(h->size * HUGE_WORD_BYTES);
    if (len) {
        int index = h->size - 1;
        i = length - 1;
        for (int index = h->size - 1; index >= 0; index--) {
            for (int j = 0; j < HUGE_WORD_BYTES && i >= 0; j++, i--) {
                h->rep[index] |= (c[i] << (j * 8));
            }
        }
    } else {
        h->rep[0] = 0;
    }
}

void huge_unload(huge* h, unsigned char* c, int length) {
    huge_word num = huge_hton(h->rep[0]);
    int btyes = 0, i = 0;
    unsigned char* tmp = (unsigned char*)(&num);

    btyes += h->size * HUGE_WORD_BYTES;
    while (!tmp[i] && i < HUGE_WORD_BYTES) {
        btyes--;
        i++;
    }

    memset(c, 0, length);
    c += length - btyes;
    memcpy(c, tmp + i, HUGE_WORD_BYTES - i);
    c += HUGE_WORD_BYTES - i;

    for (i = 1; i < h->size; i++) {
        num = huge_hton(h->rep[i]);
        memcpy(c, (unsigned char*)(&num), HUGE_WORD_BYTES);
        c += HUGE_WORD_BYTES;
    }
}

void huge_load_words(huge* h, huge_word* words, int length) {
    int i = 0;
    while (!words[i] && length) {
        i++;
        length--;
    }
    h->sign = 0;
    h->size = length ? length : 1;
    h->rep = (huge_word*)malloc(h->size * HUGE_WORD_BYTES);
    if (length) {
        memcpy(h->rep, words + i, h->size * HUGE_WORD_BYTES);
    } else {
        h->rep[0] = 0;
    }
}

void huge_unload_words(huge* h, huge_word* words, int length) {
    memset(words, 0, length * HUGE_WORD_BYTES);
    memcpy(words + length - h->size, h->rep, h->size * HUGE_WORD_BYTES);
}

void huge_free(huge* h) {
    free(h->rep);
    free(h);
}

void huge_contract(huge* h) {
    int i = 0;
    while (!h->rep[i] && i < h->size) {
        i++;
    }
    if (i > 0) {
        huge_word* tmp = h->rep;
        i = i == h->size ? h->size - 1 : i; // 保留一个0
        h->size -= i;
        h->rep = (huge_word*)malloc(h->size * HUGE_WORD_BYTES);
        memcpy(h->rep, tmp + i, h->size * HUGE_WORD_BYTES);
        free(tmp);
    }
}

int huge_compare(huge* a, huge* b) {
    if (a->size == b->size) {
        for (int i = 0; i < a->size; i++) {
            if (a->rep[i] > b->rep[i]) {
                return 1;
            } else if (a->rep[i] < b->rep[i]) {
                return -1;
            }
        }
        return 0;
    } else if (a->size > b->size) {
        return 1;
    } else {
        return -1;
    }
}

void huge_set(huge* h, unsigned int val) {
    h->rep = (huge_word*)malloc(HUGE_WORD_BYTES);
    h->size = 1;
    h->sign = 0;
    h->rep[0] = val;
}

void left_shift_1(huge* h) {
    if (h->rep[0] & HUGE_WORD_HIGH_BIT) {
        expand(h);
        h->rep[0] = 0;
    }

    for (int i = 0; i < h->size - 1; i++) {
        h->rep[i] = (h->rep[i] << 1) | ((h->rep[i + 1] & HUGE_WORD_HIGH_BIT) ? 1 : 0);
    }

    h->rep[h->size - 1] <<= 1;
}

void huge_left_shift(huge* h, int size) {
    if (size == 1) {
        left_shift_1(h);
        return;
    }

    int i = 0, words = size / HUGE_WORD_BITS, n2 = HUGE_WORD_HIGH_BIT, next = HUGE_WORD_HIGH_BIT;

    expand_right(h, words);
    size -= words * HUGE_WORD_BITS;
    if (size <= 0) {
        return;
    }

    for (i = 1; i < size; i++) {
        n2 >>= 1;
        next |= n2;
    }

    if (h->rep[0] >= n2) {
        expand(h);
        h->rep[0] = 0;
    }

    for (i = 0; i < h->size - 1; i++) {
        h->rep[i] = (h->rep[i] << size) | ((h->rep[i + 1] & next) >> (HUGE_WORD_BITS - size));
    }

    h->rep[h->size - 1] <<= size;
}

void right_shift_1(huge* h) {
    for (int i = h->size - 1; i > 0; i--) {
        h->rep[i] = (h->rep[i] >> 1) | ((h->rep[i - 1] & 0x01) ? HUGE_WORD_HIGH_BIT : 0);
    }

    h->rep[0] >>= 1;
    huge_contract(h);
}

void huge_right_shift(huge* h, int size) {
    if (size == 1) {
        right_shift_1(h);
        return;
    }

    int i = 0, words = size / HUGE_WORD_BITS, n2 = 0x1, next = 0x1;

    h->size -= words;
    size -= words * HUGE_WORD_BITS;
    if (h->size <= 0) {
        h->size = 1;
        h->rep[0] = 0;
        return;
    }

    for (i = 1; i < size; i++) {
        n2 <<= 1;
        next |= n2;
    }

    for (int i = h->size - 1; i > 0; i--) {
        h->rep[i] = (h->rep[i] >> size) | ((h->rep[i - 1] & next) << (HUGE_WORD_BITS - size));
    }

    h->rep[0] >>= size;
    huge_contract(h);
}

void huge_add(huge* a, huge* b) {
    huge x, y;
    x.rep = NULL;
    y.rep = NULL;
    huge_copy(&x, a);
    huge_copy(&y, b);
    if (x.sign == y.sign) {
        int i = 0, j = 0;
        int64_t carry = 0;
        if (y.size > x.size) {
            huge_swap(&x, &y);
        }
        i = x.size - 1;
        j = y.size - 1;
        while (i >= 0 || j >= 0) {
            int64_t sum = (int64_t)x.rep[i] + carry;
            if (j >= 0) {
                sum += y.rep[j];
            }
            x.rep[i] = sum % HUGE_WORD_MAX;
            carry = sum / HUGE_WORD_MAX;
            i--;
            j--;
        }
        if (carry) {
            expand(&x);
        }
    } else if (x.sign) { //-x+y
        huge_swap(&x, &y);
        x.sign = 0;
        huge_subtract(&x, &y);
    } else { //x+(-y)
        y.sign = 0;
        huge_subtract(&x, &y);
    }
    huge_copy(a, &x);
    free(x.rep);
    free(y.rep);
}

void huge_subtract(huge* a, huge* b) {
    huge x, y;
    x.rep = NULL;
    y.rep = NULL;
    huge_copy(&x, a);
    huge_copy(&y, b);
    if (x.sign == y.sign) {
        int i = 0, j = 0;
        int64_t carry = 0;
        if (x.sign) { //-x-(-y)
            huge_swap(&x, &y);
            x.sign = 0;
            y.sign = 0;
        }
        if (huge_compare(&x, &y) <= 0) { // 为0时也为负
            huge_swap(&x, &y);
            x.sign = 1;
        }
        i = x.size - 1;
        j = y.size - 1;
        while (j >= 0 || carry) {
            int64_t sub = (int64_t)x.rep[i] - (j >= 0 ? y.rep[j] : 0) - carry;
            if (sub < 0) { //向上借1
                sub += HUGE_WORD_MAX;
                carry = 1;
            } else {
                carry = 0;
            }
            x.rep[i] = sub;
            i--;
            j--;
        }
        huge_contract(&x);
    } else if (x.sign) { //-x-y
        x.sign = 1;
        y.sign = 1;
        huge_add(&x, &y);
    } else { //x-(-y)
        y.sign = 0;
        huge_add(&x, &y);
    }
    huge_copy(a, &x);
    free(x.rep);
    free(y.rep);
}

// 借助数组使用乘法实现大数相乘
void huge_multiply(huge* a, huge* b) {
    int sign = (a->sign != b->sign) ? 1 : 0;
    int size = a->size + b->size;
    huge_word sum[size];

    memset(sum, 0, size * HUGE_WORD_BYTES);

    for (int i = a->size; i >= 1; i--) {
        for (int j = b->size; j >= 1; j--) {
            int index = i + j;
            u_int64_t num = 0, p = 0;
            p = (u_int64_t)a->rep[i - 1] * b->rep[j - 1];

            do {
                index--;
                num = sum[index] + p;
                if (num >= HUGE_WORD_MAX) {
                    p = num / HUGE_WORD_MAX;
                    sum[index] = num % HUGE_WORD_MAX;
                } else {
                    p = 0;
                    sum[index] = num;
                }
            } while (p);
        }
    }

    int i = 0;
    while (!sum[i] && i < size - 1) {
        i++;
    }

    free(a->rep);
    huge_load_words(a, sum + i, size - i);
    a->sign = sign;
}

void huge_divide(huge* dividend, huge* divisor, huge* quotient) {
    int c = huge_compare(dividend, divisor);
    int sign = dividend->sign = (dividend->sign != divisor->sign) ? 1 : 0;
    huge* _dividend = dividend;

    if (_dividend == divisor) { //自己除自己
        _dividend = (huge*)malloc(sizeof(huge));
        _dividend->rep = NULL;
        huge_copy(_dividend, dividend);
    }
    _dividend->sign = 0;
    if (c < 0) {
        _dividend->sign = sign;
        if (_dividend != dividend) {
            huge_copy(dividend, _dividend);
            huge_free(_dividend);
        }
        if (quotient) {
            huge_set(quotient, 0);
        }
        return;
    }

    int bits = 1, bitPos = 0, zeros;
    huge_word mask = 0, tmp;
    huge _divisor;
    _divisor.rep = NULL;
    huge_copy(&_divisor, divisor);

    if (_dividend->size - _divisor.size > 0) {
        int words = _dividend->size - _divisor.size;
        if (_dividend->rep[0] <= _divisor.rep[0]) {
            words--;
        }
        if (words > 0) {
            expand_right(&_divisor, words);
            bits += words * HUGE_WORD_BITS;
        }
    }
    while (huge_compare(_dividend, &_divisor) >= 0) {
        huge_left_shift(&_divisor, 1);
        bits++;
    }
    huge_right_shift(&_divisor, 1);
    bits--;
    bitPos = (bits / HUGE_WORD_BITS + 1) * HUGE_WORD_BITS - bits;

    if (quotient) {
        quotient->size = bits / HUGE_WORD_BITS + 1;
        quotient->sign = 0;
        quotient->rep = (huge_word*)malloc(quotient->size * HUGE_WORD_BYTES);
        memset(quotient->rep, 0, quotient->size * HUGE_WORD_BYTES);
    }

    while (huge_compare(_dividend, divisor) >= 0 && _dividend->sign == 0) {
        if (huge_compare(_dividend, &_divisor) >= 0) {
            huge_subtract(_dividend, &_divisor);
            if (quotient) {
                quotient->rep[bitPos / HUGE_WORD_BITS] |= (HUGE_WORD_HIGH_BIT >> (bitPos % HUGE_WORD_BITS));
            }
        }

        bits = 0;
        if (_divisor.size > _dividend->size) { //使 _divisor 的位数和 _dividend 的位数一致，避免无效移位
            bits = 0;
            zeros = 0;
            tmp = _divisor.size - _dividend->size;
            if (tmp > 1) {
                bits += (tmp - 1) * HUGE_WORD_BITS;
            }
            for (mask = HUGE_WORD_HIGH_BIT; mask; mask >>= 1) {
                if (mask & _divisor.rep[0]) {
                    break;
                }
                zeros++;
            }
            bits += HUGE_WORD_BITS - zeros;
        }
        tmp = _divisor.rep[0];
        while (tmp > _dividend->rep[0]) { //尽可能一次移动多位
            tmp >>= 1;
            bits++;
        }
        bits = bits == 0 ? 1 : bits;

        huge_right_shift(&_divisor, bits);
        bitPos += bits;
    }

    _dividend->sign = sign;
    if (quotient) {
        quotient->sign = sign;
    }
    if (_dividend != dividend) {
        huge_copy(dividend, _dividend);
        huge_free(_dividend);
    }
    free(_divisor.rep);
}

// a = a^e%p (if p)
void huge_mod_pow(huge* a, huge* e, huge* p) {
    huge result, aTmp, ec;
    huge_set(&result, 1);
    aTmp.rep = NULL;
    ec.rep = NULL;
    huge_copy(&aTmp, a);
    huge_copy(&ec, e);
    if (p) { //利用公式【(a*b)%p = ((a%p)*(b%p))%p】提升求模运算性能
        huge_divide(a, p, NULL);
    }

    while (ec.rep[0]) {
        if (ec.rep[ec.size - 1] & 0x01) {
            huge_multiply(&result, &aTmp);
            if (p) {
                huge_divide(&result, p, NULL);
            }
        }
        huge_multiply(&aTmp, &aTmp);
        if (p) {
            huge_divide(&aTmp, p, NULL);
        }
        huge_right_shift(&ec, 1);
    }
    huge_copy(a, &result);
    free(result.rep);
    free(aTmp.rep);
    free(ec.rep);
}

// 负数的逆元
void huge_inverse_neg(huge* h, huge* p) {
    huge tmp;
    tmp.rep = NULL;

    if (h->sign) {
        huge_divide(h, p, NULL);
        h->sign = 0;
        huge_copy(&tmp, p);
        huge_subtract(&tmp, h);
        huge_copy(h, &tmp);
    }
}

void _mul_inverse(huge* a, huge* b, huge* x, huge* y) {
    if (b->size == 1 && !b->rep[0]) {
        huge_set(x, 1);
        huge_set(y, 0);
        return;
    }

    huge a1, b1, x1, y1;
    a1.rep = NULL;
    b1.rep = NULL;
    x1.rep = NULL;
    y1.rep = NULL;

    huge_copy(&a1, b);
    huge_copy(&b1, a);
    huge_divide(&b1, b, NULL);
    _mul_inverse(&a1, &b1, &x1, &y1);

    // x = y0
    huge_copy(x, &y1);

    // y = x0 - [a/b]*y0
    huge_copy(&a1, a);
    huge_divide(&a1, b, &b1);
    huge_multiply(&b1, &y1);
    huge_subtract(&x1, &b1);
    huge_copy(y, &x1);

    free(a1.rep);
    free(b1.rep);
    free(x1.rep);
    free(y1.rep);
}

// 求h在模p上的乘法逆元
void huge_inverse_mul(huge* h, huge* p) {
    huge x, y, tmp;
    x.rep = NULL;
    y.rep = NULL;
    tmp.rep = NULL;
    
    huge_inverse_neg(h, p);

    if (huge_compare(h, p) == 0) { //h==p
        huge_set(h, 1);
        return;
    }
    if (h->size == 1 && !h->rep[0]) { //0
        return;
    }

    huge_copy(&tmp, h);
    huge_divide(&tmp, p, NULL);
    if (tmp.size == 1 && !tmp.rep[0]) { //h%p==0,则返回p
        huge_copy(h, p);
        return;
    }

    _mul_inverse(h, p, &x, &y);
    huge_copy(h, &x);
    huge_inverse_neg(h, p);
}

// #define TEST_HUGE
#ifdef TEST_HUGE
#include <time.h>
int main() {
    time_t start, end;
    huge a, b, c;
    unsigned char* a1, * b1;
    int size1, size2;

    // size1 = hex_decode((unsigned char*)"0x1122334455", &a1);
    // unsigned char out[size1];
    // huge_load(&a, a1, size1);
    // huge_unload(&a, out, size1);
    // show_hex(out, size1);

    // huge_set(&a, 4294967295);
    // huge_set(&b, 123456789);
    // huge_add(&a, &b);
    // show_hex(a.rep, a.size, HUGE_WORD_BYTES);

    // huge_set(&a, 222222222);
    // huge_set(&b, 123456789);
    // huge_subtract(&a, &b);
    // show_hex(a.rep, a.size, HUGE_WORD_BYTES);

    // for (int i = 0; i < 1; i++) {
    //     size1 = hex_decode((unsigned char*)"0x81cd228f93f95f18673b5", &a1);
    //     size2 = hex_decode((unsigned char*)"0x763d981006a644ffb4415", &b1);
    //     huge_load(&a, a1, size1);
    //     huge_load(&b, b1, size2);
    //     huge_subtract(&a, &b);
    //     show_hex(a.rep, a.size, HUGE_WORD_BYTES);
    // }

    // huge_set(&a, 4294967295);
    // huge_set(&b, 123456);
    // huge_multiply(&a, &b);
    // show_hex(a.rep, a.size, HUGE_WORD_BYTES);
    // start = clock();
    // for (int i = 0; i < 1000000; i++) {
    //     huge_set(&a, 7654321);
    //     huge_set(&b, 123456790);
    //     huge_multiply(&a, &b);
    //     // show_hex(a.rep, a.size, HUGE_WORD_BYTES);
    //     huge_set(&a, 28406);
    //     huge_set(&b, 28406);
    //     huge_multiply(&a, &b);
    //     // show_hex(a.rep, a.size, HUGE_WORD_BYTES);
    // }
    // end = clock();
    // printf("duration: %fs\n", (double)(end - start) / CLOCKS_PER_SEC);
    // start = clock();
    // unsigned char* a1, * b1;
    // int size1, size2;
    // for (int i = 0; i < 1000000; i++) {
    //     size1 = hex_decode((unsigned char*)"0x40f73315d3f74703904e51e1c72686801de06a55417110e56280f1f8471a3802406d2110011e1f387f7b4c43258b0a1eedc558a3aac5aa2d20cf5e0d65d80db3", &a1);
    //     size2 = hex_decode((unsigned char*)"0x40f73315d3f74703904e51e1c72686801de06a55417110e56280f1f8471a3802406d2110011e1f387f7b4c43258b0a1eedc558a3aac5aa2d20cf5e0d65d80db3", &b1);
    //     huge_load(&a, a1, size1);
    //     huge_load(&b, b1, size2);
    //     huge_multiply(&a, &b);
    //     // show_hex(a.rep, a.size, HUGE_WORD_BYTES);
    // }
    // end = clock();
    // printf("duration: %fs\n", (double)(end - start) / CLOCKS_PER_SEC);
    // size1 = hex_decode((unsigned char*)"0x84bb4d5aa3c6d45a79d615461ba398a91632046307c5977cea48334743939abf7e1650fd3f16d1769f89691faf45b6bccb44e25d6525ddf03c832051a70d7337", &a1);
    // huge_load(&a, a1, size1);
    // huge_multiply(&a, &a);
    // show_hex(a.rep, a.size, HUGE_WORD_BYTES);

    // huge_set(&a, 1123456789);
    // huge_set(&b, 321123);
    // huge_set(&c, 0);
    // huge_divide(&a, &b, &c);
    // show_hex(a.rep, a.size, HUGE_WORD_BYTES);
    // show_hex(c.rep, c.size, HUGE_WORD_BYTES);
    // huge_set(&a, 20);
    // huge_set(&b, 3);
    // huge_set(&c, 0);
    // huge_divide(&a, &b, &c);
    // show_hex(a.rep, a.size, HUGE_WORD_BYTES);
    // show_hex(c.rep, c.size, HUGE_WORD_BYTES);
    // start = clock();
    // for (int i = 0; i < 10000; i++) {
    //     size1 = hex_decode((unsigned char*)"0x77229a8f6d60170c9dd81cd228f93f95f18673b50dbeee798fe518406ffe8ade37915578ba024dab12fcf26f05b5597f120775050929fb20061a155fd8a79339e004761259f9b6f8d862fe75ca87d07c0ff21f615daa9aaef04dc401bc707c465f2558b221db40821cf29adc7715d93f4a61d9d89700ca35dcd69173aefce440", &a1);
    //     size2 = hex_decode((unsigned char*)"0xc4f8e9e15dcadf2b96c763d981006a644ffb4415030a16ed1283883340f2aa0e2be2be8fa60150b9046965837c3e7d151b7de237ebb957c20663898250703b3f", &b1);
    //     huge_load(&a, a1, size1);
    //     huge_load(&b, b1, size2);
    //     huge_divide(&a, &b, &c);
    //     // show_hex(a.rep, a.size, HUGE_WORD_BYTES);
    // }
    // end = clock();
    // printf("duration: %fs\n", (double)(end - start) / CLOCKS_PER_SEC);

    // huge_set(&a, 21 + 23 * 123456);
    // a.sign = 1;
    // huge_set(&b, 23);
    // huge_inverse_mul(&a, &b);
    // printf("sign:%d\n", a.sign);
    // show_hex(a.rep, a.size, HUGE_WORD_BYTES);
    // huge_set(&a, 12);
    // huge_set(&b, 3);
    // huge_inverse_mul(&a, &b);
    // printf("sign:%d\n", a.sign);
    // show_hex(a.rep, a.size, HUGE_WORD_BYTES);

    // huge_set(&a, 1);
    // huge_set(&b, 0x80);
    // for (int i = 1; i <= 17; i++) {
    //     huge_left_shift(&a, 1);
    //     huge_left_shift(&b, 1);
    // }
    // show_hex(a.rep, a.size, HUGE_WORD_BYTES);
    // show_hex(b.rep, b.size, HUGE_WORD_BYTES);
    // for (int i = 1; i <= 17; i++) {
    //     huge_right_shift(&a, 1);
    //     huge_right_shift(&b, 1);
    // }
    // show_hex(a.rep, a.size, HUGE_WORD_BYTES);
    // show_hex(b.rep, b.size, HUGE_WORD_BYTES);
    // huge_set(&a, 0x6ef6);
    // huge_left_shift(&a, 2);
    // show_hex(a.rep, a.size, HUGE_WORD_BYTES);
    // huge_set(&a, 0x6ef6);
    // huge_left_shift(&a, 4);
    // show_hex(a.rep, a.size, HUGE_WORD_BYTES);

    // start = clock();
    // for (int i = 1; i <= 5000; i++) {
    //     // if (i != 2) {
    //     //     continue;
    //     // }
    //     huge_set(&a, 2);
    //     huge_set(&b, i);
    //     huge_set(&c, 23);
    //     huge_mod_pow(&a, &b, &c);
    //     show_hex(a.rep, a.size, HUGE_WORD_BYTES);
    // }
    // end = clock();
    // printf("duration: %fs", (double)(end - start) / CLOCKS_PER_SEC);

    return 0;
}
#endif
#include <string.h>
#include <stdlib.h>
#include "huge.h"
#include "hex.h"
#include <stdio.h>
#include <time.h>

void swap_huge_rep(huge* a, huge* b) {
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

void copy_huge(huge* a, huge* b) {
    if (a->rep && a->size) {
        free(a->rep);
    }
    a->sign = b->sign;
    a->size = b->size;
    a->rep = (huge_word*)malloc(b->size * HUGE_WORD_BYTES);
    memcpy(a->rep, b->rep, b->size * HUGE_WORD_BYTES);
}

void load_huge(huge* h, unsigned char* c, int length) {
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

void unload_huge(huge* h, unsigned char* c, int length) {
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

void load_words(huge* h, huge_word* words, int length) {
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

void unload_words(huge* h, huge_word* words, int length) {
    memset(words, 0, length * HUGE_WORD_BYTES);
    memcpy(words + length - h->size, h->rep, h->size * HUGE_WORD_BYTES);
}

void free_huge(huge* h) {
    free(h->rep);
    free(h);
}

void contract(huge* h) {
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

int compare(huge* a, huge* b) {
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

void set_huge(huge* h, unsigned int val) {
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

void left_shift(huge* h, int size) {
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
    contract(h);
}

void right_shift(huge* h, int size) {
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
    contract(h);
}

void add(huge* a, huge* b) {
    huge x, y;
    set_huge(&x, 0);
    set_huge(&y, 0);
    copy_huge(&x, a);
    copy_huge(&y, b);
    if (x.sign == y.sign) {
        int i = 0, j = 0;
        int64_t carry = 0;
        if (y.size > x.size) {
            swap_huge_rep(&x, &y);
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
        swap_huge_rep(&x, &y);
        x.sign = 0;
        subtract(&x, &y);
    } else { //x+(-y)
        y.sign = 0;
        subtract(&x, &y);
    }
    copy_huge(a, &x);
    free(x.rep);
    free(y.rep);
}

void subtract(huge* a, huge* b) {
    huge x, y;
    set_huge(&x, 0);
    set_huge(&y, 0);
    copy_huge(&x, a);
    copy_huge(&y, b);
    if (x.sign == y.sign) {
        int i = 0, j = 0;
        int64_t carry = 0;
        if (x.sign) { //-x-(-y)
            swap_huge_rep(&x, &y);
            x.sign = 0;
            y.sign = 0;
        }
        if (compare(&x, &y) <= 0) { // 为0时也为负
            swap_huge_rep(&x, &y);
            x.sign = 1;
        }
        i = x.size - 1;
        j = y.size - 1;
        while (i >= 0 && j >= 0) {
            int64_t sub = (int64_t)x.rep[i] - y.rep[j] - carry;
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
        if (carry) {
            x.rep[i] -= carry;
        }
        contract(&x);
    } else if (x.sign) { //-x-y
        x.sign = 1;
        y.sign = 1;
        add(&x, &y);
    } else { //x-(-y)
        y.sign = 0;
        add(&x, &y);
    }
    copy_huge(a, &x);
    free(x.rep);
    free(y.rep);
}

// 借助数组使用乘法实现大数相乘
void multiply(huge* a, huge* b) {
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
    load_words(a, sum + i, size - i);
    a->sign = sign;
}

void divide(huge* dividend, huge* divisor, huge* quotient) {
    int c = compare(dividend, divisor);
    int sign = dividend->sign = (dividend->sign != divisor->sign) ? 1 : 0;
    huge* _dividend = dividend;

    if (_dividend == divisor) { //自己除自己
        _dividend = (huge*)malloc(sizeof(huge));
        set_huge(_dividend, 0);
        copy_huge(_dividend, dividend);
    }
    _dividend->sign = 0;
    if (c < 0) {
        _dividend->sign = sign;
        if (_dividend != dividend) {
            copy_huge(dividend, _dividend);
            free_huge(_dividend);
        }
        if (quotient) {
            set_huge(quotient, 0);
        }
        return;
    }

    int bits = 1, bitPos = 0, zeros;
    huge_word mask = 0, tmp;
    huge _divisor;
    set_huge(&_divisor, 0);
    copy_huge(&_divisor, divisor);

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
    while (compare(_dividend, &_divisor) >= 0) {
        left_shift(&_divisor, 1);
        bits++;
    }
    right_shift(&_divisor, 1);
    bits--;
    bitPos = (bits / HUGE_WORD_BITS + 1) * HUGE_WORD_BITS - bits;

    if (quotient) {
        quotient->size = bits / HUGE_WORD_BITS + 1;
        quotient->sign = 0;
        quotient->rep = (huge_word*)malloc(quotient->size * HUGE_WORD_BYTES);
        memset(quotient->rep, 0, quotient->size * HUGE_WORD_BYTES);
    }

    while (compare(_dividend, divisor) >= 0 && _dividend->sign == 0) {
        if (compare(_dividend, &_divisor) >= 0) {
            subtract(_dividend, &_divisor);
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

        right_shift(&_divisor, bits);
        bitPos += bits;
    }

    _dividend->sign = sign;
    if (quotient) {
        quotient->sign = sign;
    }
    if (_dividend != dividend) {
        copy_huge(dividend, _dividend);
        free_huge(_dividend);
    }
    free(_divisor.rep);
}

// a = a^e%p (if p)
void mod_pow(huge* a, huge* e, huge* p) {
    huge result, aTmp, ec;
    set_huge(&result, 1);
    set_huge(&aTmp, 0);
    set_huge(&ec, 0);
    copy_huge(&aTmp, a);
    copy_huge(&ec, e);
    if (p) { //利用公式【(a*b)%p = ((a%p)*(b%p))%p】提升求模运算性能
        divide(a, p, NULL);
    }

    while (ec.rep[0]) {
        if (ec.rep[ec.size - 1] & 0x01) {
            multiply(&result, &aTmp);
            if (p) {
                divide(&result, p, NULL);
            }
        }
        multiply(&aTmp, &aTmp);
        if (p) {
            divide(&aTmp, p, NULL);
        }
        right_shift(&ec, 1);
    }
    copy_huge(a, &result);
    free(result.rep);
    free(aTmp.rep);
    free(ec.rep);
}

void _inv(huge* a, huge* b, huge* x, huge* y) {
    if (b->size == 1 && !b->rep[0]) {
        set_huge(x, 1);
        set_huge(y, 0);
        return;
    }

    huge a1, b1, x1, y1;

    set_huge(&a1, 0);
    set_huge(&b1, 0);
    set_huge(&x1, 0);
    set_huge(&y1, 0);

    copy_huge(&a1, b);
    copy_huge(&b1, a);
    divide(&b1, b, NULL);
    _inv(&a1, &b1, &x1, &y1);

    // x = y0
    copy_huge(x, &y1);

    // y = x0 - [a/b]*y0
    copy_huge(&a1, a);
    divide(&a1, b, &b1);
    multiply(&b1, &y1);
    subtract(&x1, &b1);
    copy_huge(y, &x1);

    free(a1.rep);
    free(b1.rep);
    free(x1.rep);
    free(y1.rep);
}

// 负数的逆元
void negativeInv(huge* h, huge* p) {
    huge tmp;
    set_huge(&tmp, 0);

    if (h->sign) {
        divide(h, p, NULL);
        h->sign = 0;
        copy_huge(&tmp, p);
        subtract(&tmp, h);
        copy_huge(h, &tmp);
    }
}

// 求h在模p上的乘法逆元
void inv(huge* h, huge* p) {
    huge x, y, tmp;
    set_huge(&x, 0);
    set_huge(&y, 0);
    set_huge(&tmp, 0);
    negativeInv(h, p);

    if (compare(h, p) == 0) { //h==p
        set_huge(h, 1);
        return;
    }
    if (h->size == 1 && !h->rep[0]) { //0
        return;
    }

    copy_huge(&tmp, h);
    divide(&tmp, p, NULL);
    if (tmp.size == 1 && !tmp.rep[0]) { //h%p==0,则返回p
        copy_huge(h, p);
        return;
    }

    _inv(h, p, &x, &y);
    copy_huge(h, &x);
    negativeInv(h, p);
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
    // load_huge(&a, a1, size1);
    // unload_huge(&a, out, size1);
    // show_hex(out, size1);

    // set_huge(&a, 4294967295);
    // set_huge(&b, 123456789);
    // add(&a, &b);
    // show_hex(a.rep, a.size, HUGE_WORD_BYTES);

    // set_huge(&a, 222222222);
    // set_huge(&b, 123456789);
    // subtract(&a, &b);
    // show_hex(a.rep, a.size, HUGE_WORD_BYTES);

    // for (int i = 0; i < 1; i++) {
    //     size1 = hex_decode((unsigned char*)"0x81cd228f93f95f18673b5", &a1);
    //     size2 = hex_decode((unsigned char*)"0x763d981006a644ffb4415", &b1);
    //     load_huge(&a, a1, size1);
    //     load_huge(&b, b1, size2);
    //     subtract(&a, &b);
    //     show_hex(a.rep, a.size, HUGE_WORD_BYTES);
    // }

    // set_huge(&a, 4294967295);
    // set_huge(&b, 123456);
    // multiply(&a, &b);
    // show_hex(a.rep, a.size, HUGE_WORD_BYTES);
    // start = clock();
    // for (int i = 0; i < 1000000; i++) {
    //     set_huge(&a, 7654321);
    //     set_huge(&b, 123456790);
    //     multiply(&a, &b);
    //     // show_hex(a.rep, a.size, HUGE_WORD_BYTES);
    //     set_huge(&a, 28406);
    //     set_huge(&b, 28406);
    //     multiply(&a, &b);
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
    //     load_huge(&a, a1, size1);
    //     load_huge(&b, b1, size2);
    //     multiply(&a, &b);
    //     // show_hex(a.rep, a.size, HUGE_WORD_BYTES);
    // }
    // end = clock();
    // printf("duration: %fs\n", (double)(end - start) / CLOCKS_PER_SEC);
    // size1 = hex_decode((unsigned char*)"0x84bb4d5aa3c6d45a79d615461ba398a91632046307c5977cea48334743939abf7e1650fd3f16d1769f89691faf45b6bccb44e25d6525ddf03c832051a70d7337", &a1);
    // load_huge(&a, a1, size1);
    // multiply(&a, &a);
    // show_hex(a.rep, a.size, HUGE_WORD_BYTES);

    // set_huge(&a, 1123456789);
    // set_huge(&b, 321123);
    // set_huge(&c, 0);
    // divide(&a, &b, &c);
    // show_hex(a.rep, a.size, HUGE_WORD_BYTES);
    // show_hex(c.rep, c.size, HUGE_WORD_BYTES);
    // set_huge(&a, 20);
    // set_huge(&b, 3);
    // set_huge(&c, 0);
    // divide(&a, &b, &c);
    // show_hex(a.rep, a.size, HUGE_WORD_BYTES);
    // show_hex(c.rep, c.size, HUGE_WORD_BYTES);
    // start = clock();
    // for (int i = 0; i < 10000; i++) {
    //     size1 = hex_decode((unsigned char*)"0x77229a8f6d60170c9dd81cd228f93f95f18673b50dbeee798fe518406ffe8ade37915578ba024dab12fcf26f05b5597f120775050929fb20061a155fd8a79339e004761259f9b6f8d862fe75ca87d07c0ff21f615daa9aaef04dc401bc707c465f2558b221db40821cf29adc7715d93f4a61d9d89700ca35dcd69173aefce440", &a1);
    //     size2 = hex_decode((unsigned char*)"0xc4f8e9e15dcadf2b96c763d981006a644ffb4415030a16ed1283883340f2aa0e2be2be8fa60150b9046965837c3e7d151b7de237ebb957c20663898250703b3f", &b1);
    //     load_huge(&a, a1, size1);
    //     load_huge(&b, b1, size2);
    //     divide(&a, &b, &c);
    //     // show_hex(a.rep, a.size, HUGE_WORD_BYTES);
    // }
    // end = clock();
    // printf("duration: %fs\n", (double)(end - start) / CLOCKS_PER_SEC);

    // set_huge(&a, 21 + 23 * 123456);
    // a.sign = 1;
    // set_huge(&b, 23);
    // inv(&a, &b);
    // printf("sign:%d\n", a.sign);
    // show_hex(a.rep, a.size, HUGE_WORD_BYTES);
    // set_huge(&a, 12);
    // set_huge(&b, 3);
    // inv(&a, &b);
    // printf("sign:%d\n", a.sign);
    // show_hex(a.rep, a.size, HUGE_WORD_BYTES);

    // set_huge(&a, 1);
    // set_huge(&b, 0x80);
    // for (int i = 1; i <= 17; i++) {
    //     left_shift(&a, 1);
    //     left_shift(&b, 1);
    // }
    // show_hex(a.rep, a.size, HUGE_WORD_BYTES);
    // show_hex(b.rep, b.size, HUGE_WORD_BYTES);
    // for (int i = 1; i <= 17; i++) {
    //     right_shift(&a, 1);
    //     right_shift(&b, 1);
    // }
    // show_hex(a.rep, a.size, HUGE_WORD_BYTES);
    // show_hex(b.rep, b.size, HUGE_WORD_BYTES);
    // set_huge(&a, 0x6ef6);
    // left_shift(&a, 2);
    // show_hex(a.rep, a.size, HUGE_WORD_BYTES);
    // set_huge(&a, 0x6ef6);
    // left_shift(&a, 4);
    // show_hex(a.rep, a.size, HUGE_WORD_BYTES);

    // start = clock();
    // for (int i = 1; i <= 5000; i++) {
    //     // if (i != 2) {
    //     //     continue;
    //     // }
    //     set_huge(&a, 2);
    //     set_huge(&b, i);
    //     set_huge(&c, 23);
    //     mod_pow(&a, &b, &c);
    //     show_hex(a.rep, a.size, HUGE_WORD_BYTES);
    // }
    // end = clock();
    // printf("duration: %fs", (double)(end - start) / CLOCKS_PER_SEC);

    return 0;
}
#endif
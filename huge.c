#include <string.h>
#include <stdlib.h>
#include "huge.h"
#include "hex.h"
#include <stdio.h>
#include <time.h>

void swap_huge_rep(huge* a, huge* b) {
    unsigned char* rep = a->rep;
    unsigned int size = a->size;
    a->rep = b->rep;
    a->size = b->size;
    b->rep = rep;
    b->size = size;
}

void expand(huge* h) {
    unsigned char* tmp = h->rep;
    h->rep = (unsigned char*)malloc(h->size + 1);
    memcpy(h->rep + 1, tmp, h->size);
    h->size++;
    h->rep[0] = 0x01;
    free(tmp);
}

void expand_right(huge* h, int size) {
    if (size <= 0 || h->size == 1 && !h->rep[0]) {
        return;
    }
    h->rep = (unsigned char*)realloc(h->rep, h->size + size);
    memset(h->rep + h->size, 0, size);
    h->size += size;
}

void copy_huge(huge* a, huge* b) {
    if (a->rep && a->size) {
        free(a->rep);
    }
    a->sign = b->sign;
    a->size = b->size;
    a->rep = (unsigned char*)malloc(b->size);
    memcpy(a->rep, b->rep, b->size);
}

void load_huge(huge* h, unsigned char* c, int length) {
    int i = 0;
    while (!c[i] && length) {
        i++;
        length--;
    }
    h->sign = 0;
    h->size = length ? length : 1;
    h->rep = (unsigned char*)malloc(h->size);
    if (length) {
        memcpy(h->rep, c + i, h->size);
    } else {
        h->rep[0] = 0;
    }
}

void unload_huge(huge* h, unsigned char* bytes, int length) {
    memset(bytes, 0, length);
    memcpy(bytes + length - h->size, h->rep, h->size);
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
        unsigned char* tmp = h->rep;
        i = i == h->size ? h->size - 1 : i; // 保留一个0
        h->size -= i;
        h->rep = (unsigned char*)malloc(h->size);
        memcpy(h->rep, tmp + i, h->size);
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
    unsigned int mask = 0xff000000;
    int shift = 0;

    h->sign = 0;
    h->size = 4;

    for (; mask > 0x000000ff; mask >>= 8) {
        if (!(mask & val)) {
            h->size--;
        } else {
            break;
        }
    }

    mask = 0x000000ff;
    h->rep = (unsigned char*)malloc(h->size);

    for (int i = h->size - 1; i >= 0; i--) {
        h->rep[i] = (mask & val) >> shift;
        mask <<= 8;
        shift += 8;
    }
}

void left_shift(huge* h, int size) {
    int i = 0, bytes = size / 8, n2 = 0x80, next = 0x80;

    expand_right(h, bytes);
    size -= bytes * 8;
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
        h->rep[i] = (h->rep[i] << size) | ((h->rep[i + 1] & next) >> (8 - size));
    }

    h->rep[h->size - 1] <<= size;
}

void right_shift(huge* h, int size) {
    int i = 0, bytes = size / 8, n2 = 0x1, next = 0x1;

    h->size -= bytes;
    size -= bytes * 8;
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
        h->rep[i] = (h->rep[i] >> size) | ((h->rep[i - 1] & next) << (8 - size));
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
        int i = 0, j = 0, carry = 0;
        if (y.size > x.size) {
            swap_huge_rep(&x, &y);
        }
        i = x.size - 1;
        j = y.size - 1;
        while (i >= 0 || j >= 0) {
            int sum = x.rep[i] + carry;
            if (j >= 0) {
                sum += y.rep[j];
            }
            x.rep[i] = sum % 256;
            carry = sum / 256;
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
            int sub = x.rep[i] - y.rep[j];
            if (sub < 0) { //向上借1
                int n = i - 1;
                sub += 256;
                while (n >= 0 && !x.rep[n]) {
                    x.rep[n] += 255;
                    n--;
                }
                if (n >= 0) {
                    x.rep[n] -= 1;
                }
            }
            x.rep[i] = sub;
            i--;
            j--;
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

void multiply_char(huge* a, unsigned char b) {
    huge x;
    set_huge(&x, 0);
    copy_huge(&x, a);

    int carry = 0, i = x.size - 1;
    while (i >= 0) {
        int sum = x.rep[i] * b + carry;
        x.rep[i] = sum % 256;
        carry = sum / 256;
        i--;
    }
    if (carry) {
        expand(&x);
        x.rep[0] = carry;
    }
    contract(&x);
    copy_huge(a, &x);
    free(x.rep);
}

// 借助数组使用乘法实现大数相乘
void multiply(huge* a, huge* b) {
    int sign = (a->sign != b->sign) ? 1 : 0;
    int size = a->size + b->size;
    unsigned char sum[size];

    memset(sum, 0, size);

    for (int i = a->size; i >= 1; i--) {
        for (int j = b->size; j >= 1; j--) {
            int index = i + j;
            int num = 0, p = 0;
            p = a->rep[i - 1] * b->rep[j - 1];

            do {
                index--;
                num = sum[index] + p;
                if (num >= 256) {
                    p = num / 256;
                    sum[index] = num % 256;
                } else {
                    p = 0;
                    sum[index] = num;
                }
            } while (p);
        }
    }

    int i = 0;
    while (!sum[i]) {
        i++;
    }

    free(a->rep);
    load_huge(a, sum + i, size - i);
    a->sign = sign;
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

void get_remainder(huge* a, huge* p) {
    int c = compare(a, p);
    if (c <= 0) {
        if (c == 0) {
            set_huge(a, 0);
        }
        return;
    }
    int one = a->rep[a->size - 1] & 0x01;
    right_shift(a, 1);
    get_remainder(a, p);
    left_shift(a, 1);
    if (one) {
        huge tmp;
        set_huge(&tmp, 1);
        add(a, &tmp);
        free(tmp.rep);
    }
    if (compare(a, p) >= 0) {
        subtract(a, p);
    }
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

    int bits = 1, bitPos = 0;
    huge _divisor;
    set_huge(&_divisor, 0);
    copy_huge(&_divisor, divisor);

    if (_dividend->size - _divisor.size > 0) {
        int bytes = _dividend->size - _divisor.size;
        if (_dividend->rep[0] <= _divisor.rep[0]) {
            bytes--;
        }
        if (bytes > 0) {
            expand_right(&_divisor, bytes);
            bits += bytes * 8;
        }
    }
    while (compare(_dividend, &_divisor) >= 0) {
        left_shift(&_divisor, 1);
        bits++;
    }
    right_shift(&_divisor, 1);
    bits--;
    bitPos = (bits / 8 + 1) * 8 - bits;

    if (quotient) {
        quotient->size = bits / 8 + 1;
        quotient->sign = 0;
        quotient->rep = (unsigned char*)malloc(quotient->size);
        memset(quotient->rep, 0, quotient->size);
    }

    while (compare(_dividend, divisor) >= 0) {
        if (compare(_dividend, &_divisor) >= 0) {
            subtract(_dividend, &_divisor);
            if (quotient) {
                quotient->rep[bitPos / 8] |= (0x80 >> (bitPos % 8));
            }
        }
        right_shift(&_divisor, 1);
        bitPos++;
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
    // unsigned char s1[2], s2[2];
    // s1[0] = 254;
    // s1[1] = 255;
    // s2[0] = 1;
    // s2[1] = 1;
    // load_huge(&a, s1, 2);
    // load_huge(&b, s2, 2);
    // a.sign = 1;
    // add(&a, &b);
    // show_hex(a.rep, a.size);

    // s1[0] = 2;
    // s1[1] = 1;
    // s2[0] = 1;
    // s2[1] = 4;
    // load_huge(&a, s1, 2);
    // load_huge(&b, s2, 2);
    // subtract(&a, &b);
    // show_hex(a.rep, a.size);

    // start = clock();
    // for (int i = 0; i < 1000000; i++) {
    //     set_huge(&a, 7654321);
    //     set_huge(&b, 123456790);
    //     multiply(&a, &b);
    //     // show_hex(a.rep, a.size);
    //     set_huge(&a, 28406);
    //     set_huge(&b, 28406);
    //     multiply(&a, &b);
    //     // show_hex(a.rep, a.size);
    // }
    // end = clock();
    // printf("duration: %fs\n", (double)(end - start) / CLOCKS_PER_SEC);

    // start = clock();
    // unsigned char* a1, * b1;
    // int size1, size2;
    // for (int i = 0; i < 100000; i++) {
    //     size1 = hex_decode((unsigned char*)"0x40f73315d3f74703904e51e1c72686801de06a55417110e56280f1f8471a3802406d2110011e1f387f7b4c43258b0a1eedc558a3aac5aa2d20cf5e0d65d80db3", &a1);
    //     size2 = hex_decode((unsigned char*)"0x40f73315d3f74703904e51e1c72686801de06a55417110e56280f1f8471a3802406d2110011e1f387f7b4c43258b0a1eedc558a3aac5aa2d20cf5e0d65d80db3", &b1);
    //     load_huge(&a, a1, size1);
    //     load_huge(&b, b1, size2);
    //     multiply(&a, &b);
    //     // show_hex(a.rep, a.size);
    // }
    // end = clock();
    // printf("duration: %fs\n", (double)(end - start) / CLOCKS_PER_SEC);

    set_huge(&a, 1123456789);
    set_huge(&b, 321123);
    set_huge(&c, 0);
    divide(&a, &b, &c);
    show_hex(a.rep, a.size);
    show_hex(c.rep, c.size);
    // set_huge(&a, 20);
    // set_huge(&b, 3);
    // set_huge(&c, 0);
    // divide(&a, &b, &c);
    // show_hex(a.rep, a.size);
    // show_hex(c.rep, c.size);
    start = clock();
    unsigned char* a1, * b1;
    int size1, size2;
    for (int i = 0; i < 1; i++) {
        size1 = hex_decode((unsigned char*)"0x77229a8f6d60170c9dd81cd228f93f95f18673b50dbeee798fe518406ffe8ade37915578ba024dab12fcf26f05b5597f120775050929fb20061a155fd8a79339e004761259f9b6f8d862fe75ca87d07c0ff21f615daa9aaef04dc401bc707c465f2558b221db40821cf29adc7715d93f4a61d9d89700ca35dcd69173aefce440", &a1);
        size2 = hex_decode((unsigned char*)"0xc4f8e9e15dcadf2b96c763d981006a644ffb4415030a16ed1283883340f2aa0e2be2be8fa60150b9046965837c3e7d151b7de237ebb957c20663898250703b3f", &b1);
        load_huge(&a, a1, size1);
        load_huge(&b, b1, size2);
        divide(&a, &b, &c);
        // get_remainder(&a, &b);
        show_hex(a.rep, a.size);
    }
    end = clock();
    printf("duration: %fs\n", (double)(end - start) / CLOCKS_PER_SEC);

    // set_huge(&a, 21 + 23 * 123456);
    // a.sign = 1;
    // set_huge(&b, 23);
    // inv(&a, &b);
    // printf("sign:%d\n", a.sign);
    // show_hex(a.rep, a.size);
    // set_huge(&a, 12);
    // set_huge(&b, 3);
    // inv(&a, &b);
    // printf("sign:%d\n", a.sign);
    // show_hex(a.rep, a.size);

    // set_huge(&a, 1);
    // set_huge(&b, 0x80);
    // for (int i = 1; i <= 17; i++) {
    //     left_shift(&a, 1);
    //     left_shift(&b, 1);
    // }
    // show_hex(a.rep, a.size);
    // show_hex(b.rep, b.size);
    // for (int i = 1; i <= 17; i++) {
    //     right_shift(&a, 1);
    //     right_shift(&b, 1);
    // }
    // show_hex(a.rep, a.size);
    // show_hex(b.rep, b.size);
    // set_huge(&a, 0x6ef6);
    // left_shift(&a, 2);
    // show_hex(a.rep, a.size);
    // set_huge(&a, 0x6ef6);
    // left_shift(&a, 4);
    // show_hex(a.rep, a.size);

    // start = clock();
    // for (int i = 1; i <= 5000; i++) {
    //     // if (i != 2) {
    //     //     continue;
    //     // }
    //     set_huge(&a, 2);
    //     set_huge(&b, i);
    //     set_huge(&c, 23);
    //     mod_pow(&a, &b, &c);
    //     show_hex(a.rep, a.size);
    // }
    // end = clock();
    // printf("duration: %fs", (double)(end - start) / CLOCKS_PER_SEC);

    // for (int i = 0; i < 10000; i++) {
    //     // if (i != 46) {
    //     //     continue;;
    //     // }
    //     set_huge(&a, i);
    //     set_huge(&b, 23);
    //     get_remainder(&a, &b);
    //     printf("i=%d\n", i);
    //     // show_hex(a.rep, a.size);
    //     printf("%.02x\n", i % 23);
    // }

    return 0;
}
#endif
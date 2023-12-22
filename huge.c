#include <string.h>
#include <stdlib.h>
#include "huge.h"
#include "hex.h"

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
    if (size <= 0 || h->size <= 0) {
        return;
    }
    h->rep = (unsigned char*)realloc(h->rep, h->size + size);
    h->rep[h->size] = 0;
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
    while (!c[i]) {
        i++;
        length--;
    }
    h->sign = 0;
    h->size = length;
    h->rep = (unsigned char*)malloc(h->size);
    memcpy(h->rep, c + i, h->size);
}

void unload_huge(huge* h, unsigned char* bytes, int length) {
    memcpy(bytes + length - h->size, h, h->size);
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

    for (; mask; mask >>= 8) {
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
        while (i >= 0 && j >= 0) {
            int sum = x.rep[i] + y.rep[j] + carry;
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
        if (compare(&x, &y) < 0) {
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

void _multiply(huge* a, unsigned char b) {
    huge x;
    set_huge(&x, 0);
    copy_huge(&x, a);

    if (a->size == 0 || b == 0) {
        a->size = 0;
        a->sign = 0;
        a->rep = (unsigned char*)malloc(0);
        return;
    }

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
    copy_huge(a, &x);
    free(x.rep);
}

void multiply(huge* a, huge* b) {
    huge x, y;
    set_huge(&x, 0);
    set_huge(&y, 0);
    copy_huge(&x, a);
    copy_huge(&y, b);

    if (a->size == 0 || b->size == 0) {
        a->size = 0;
        a->sign = 0;
        a->rep = (unsigned char*)malloc(0);
        return;
    }

    if (compare(&x, &y) < 0) {
        swap_huge_rep(&x, &y);
    }

    int zeros = 0;
    huge sum, tmp;
    set_huge(&sum, 0);
    set_huge(&tmp, 0);
    copy_huge(&tmp, &x);
    for (int i = y.size - 1; i >= 0; i--) {
        _multiply(&tmp, y.rep[i]);
        expand_right(&tmp, zeros);
        add(&sum, &tmp);
        copy_huge(&tmp, &x);
        zeros++;
    }
    copy_huge(a, &sum);
    free(x.rep);
    free(y.rep);
    free(sum.rep);
    free(tmp.rep);
    a->sign = (a->sign || b->sign) ? 1 : 0;
}

void divide(huge* dividend, huge* divisor, huge* quotient) {
    int c = compare(dividend, divisor);
    if (c < 0) {
        if (quotient) {
            copy_huge(quotient, dividend);
        }
        free(dividend->rep);
        dividend->size = 0;
        dividend->rep = (unsigned char*)malloc(0);
        dividend->sign = (dividend->sign || divisor->sign) ? 1 : 0;
        return;
    }

    huge result, sum, one, tmp;
    set_huge(&result, 0);
    set_huge(&sum, 0);
    set_huge(&one, 1);
    set_huge(&tmp, 0);

    while (compare(&result, dividend) < 0) {
        if (compare(&sum, &one) < 0) {
            add(&sum, divisor);
            add(&result, &one);
        }
        copy_huge(&tmp, &sum);
        add(&tmp, &sum);
        if (compare(&tmp, dividend) <= 0) {
            copy_huge(&sum, &tmp);
            copy_huge(&tmp, &result);
            add(&result, &tmp);
        } else {
            copy_huge(&tmp, dividend);
            subtract(&tmp, &sum);
            divide(&tmp, divisor, quotient);
            add(&result, &tmp);
            break;
        }
    }

    copy_huge(dividend, &result);
    free(result.rep);
    free(sum.rep);
    free(one.rep);
    free(tmp.rep);
}

void _inv(huge* a, huge* b, huge* x, huge* y) {
    if (b->size <= 0) {
        set_huge(x, 1);
        set_huge(y, 0);
        return;
    }

    huge a1, b1, x1, y1, tmp;

    set_huge(&a1, 0);
    set_huge(&b1, 0);
    set_huge(&x1, 0);
    set_huge(&y1, 0);
    set_huge(&tmp, 0);

    copy_huge(&a1, b);
    copy_huge(&tmp, a);
    divide(&tmp, b, &b1);
    _inv(&a1, &b1, &x1, &y1);

    // x = y0
    copy_huge(x, &y1);

    // y = x0 - [a/b]*y0
    copy_huge(&a1, a);
    divide(&a1, b, NULL);
    multiply(&a1, &y1);
    subtract(&x1, &a1);
    copy_huge(y, &x1);

    free(a1.rep);
    free(b1.rep);
    free(x1.rep);
    free(y1.rep);
    free(tmp.rep);
}

// 负数的逆元
void _negative(huge* h, huge* p) {
    huge tmp;
    set_huge(&tmp, 0);

    if (h->sign) {
        divide(h, p, &tmp);
        copy_huge(h, &tmp);
        h->sign = 0;
        copy_huge(&tmp, p);
        subtract(&tmp, h);
        copy_huge(h, &tmp);
    }
}

// 求h在模p上的乘法逆元
void inv(huge* h, huge* p) {
    huge x, y;
    set_huge(&x, 0);
    set_huge(&y, 0);

    _negative(h, p);
    _inv(h, p, &x, &y);
    copy_huge(h, &x);
    _negative(h, p);
}

#define TEST_HUGE
#ifdef TEST_HUGE
int main() {
    unsigned char s1[2], s2[2];
    huge a, b, c;
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

    // set_huge(&a, 7654321);
    // set_huge(&b, 123456790);
    // multiply(&a, &b);
    // show_hex(a.rep, a.size);

    // set_huge(&a, 1234567891);
    // set_huge(&b, 321123);
    // set_huge(&c, 0);
    // divide(&a, &b, &c);
    // show_hex(a.rep, a.size);
    // show_hex(c.rep, c.size);

    set_huge(&a, 12);
    set_huge(&b, 23);
    inv(&a, &b);
    show_hex(a.rep, a.size);

    return 0;
}
#endif
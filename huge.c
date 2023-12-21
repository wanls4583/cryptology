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

void copy_huge(huge* a, huge* b) {
    a->sign = b->sign;
    a->size = b->size;
    if (a->rep) {
        free(a->rep);
    }
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

void add(huge* a, huge* b) {
    huge* x = (huge*)malloc(sizeof(huge));
    huge* y = (huge*)malloc(sizeof(huge));
    copy_huge(x, a);
    copy_huge(y, b);
    if (x->sign == y->sign) {
        int i = 0, j = 0, carry = 0;
        if (y->size > x->size) {
            swap_huge_rep(x, y);
        }
        i = x->size - 1;
        j = y->size - 1;
        while (i >= 0 && j >= 0) {
            int sum = x->rep[i] + y->rep[j] + carry;
            x->rep[i] = sum % 256;
            carry = sum / 256;
            i--;
            j--;
        }
        if (carry) {
            expand(x);
        }
    } else if (x->sign) { //-x+y
        swap_huge_rep(x, y);
        x->sign = 0;
        subtract(x, y);
    } else { //x+(-y)
        y->sign = 0;
        subtract(x, y);
    }
    copy_huge(a, x);
    free_huge(x);
    free_huge(y);
}

void subtract(huge* a, huge* b) {
    huge* x = (huge*)malloc(sizeof(huge));
    huge* y = (huge*)malloc(sizeof(huge));
    copy_huge(x, a);
    copy_huge(y, b);
    if (x->sign == y->sign) {
        int i = 0, j = 0;
        if (x->sign) { //-x-(-y)
            swap_huge_rep(x, y);
            x->sign = 0;
            y->sign = 0;
        }
        if (compare(a, b) < 0) {
            swap_huge_rep(x, y);
            x->sign = 1;
        }
        i = x->size - 1;
        j = y->size - 1;
        while (i >= 0 && j >= 0) {
            int sub = x->rep[i] - y->rep[j];
            if (sub < 0) { //向上借1
                int n = i - 1;
                sub += 256;
                while (n >= 0 && !x->rep[n]) {
                    x->rep[n] += 255;
                    n--;
                }
                if (n >= 0) {
                    x->rep[n] -= 1;
                }
            }
            x->rep[i] = sub;
            i--;
            j--;
        }
        contract(x);
    } else if (x->sign) { //-x-y
        x->sign = 1;
        y->sign = 1;
        add(x, y);
    } else { //x-(-y)
        y->sign = 0;
        add(x, y);
    }
    copy_huge(a, x);
    free_huge(x);
    free_huge(y);
}

// #define TEST_HUGE
#ifdef TEST_HUGE
int main() {
    unsigned char s1[2], s2[2];
    huge a, b;
    s1[0] = 254;
    s1[1] = 255;
    s2[0] = 1;
    s2[1] = 1;
    load_huge(&a, s1, 2);
    load_huge(&b, s2, 2);
    a.sign = 1;
    add(&a, &b);
    show_hex(a.rep, a.size);

    s1[0] = 2;
    s1[1] = 1;
    s2[0] = 1;
    s2[1] = 4;
    load_huge(&a, s1, 2);
    load_huge(&b, s2, 2);
    subtract(&a, &b);
    show_hex(a.rep, a.size);

    return 0;
}
#endif
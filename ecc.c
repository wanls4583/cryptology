#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "ecc.h"

unsigned char prime192v1_P[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};
unsigned char prime192v1_A[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
};
unsigned char prime192v1_B[] = {
    0x64, 0x21, 0x05, 0x19, 0xE5, 0x9C, 0x80, 0xE7,
    0x0F, 0xA7, 0xE9, 0xAB, 0x72, 0x24, 0x30, 0x49,
    0xFE, 0xB8, 0xDE, 0xEC, 0xC1, 0x46, 0xB9, 0xB1
};
unsigned char prime192v1_Gx[] = {
    0x18, 0x8D, 0xA8, 0x0E, 0xB0, 0x30, 0x90, 0xF6,
    0x7C, 0xBF, 0x20, 0xEB, 0x43, 0xA1, 0x88, 0x00,
    0xF4, 0xFF, 0x0A, 0xFD, 0x82, 0xFF, 0x10, 0x12
};
unsigned char prime192v1_Gy[] = {
    0x07, 0x19, 0x2B, 0x95, 0xFF, 0xC8, 0xDA, 0x78,
    0x63, 0x10, 0x11, 0xED, 0x6B, 0x24, 0xCD, 0xD5,
    0x73, 0xF9, 0x77, 0xA1, 0x1E, 0x79, 0x48, 0x11
};
unsigned char prime192v1_N[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x99, 0xDE, 0xF8, 0x36,
    0x14, 0x6B, 0xC9, 0xB1, 0xB4, 0xD2, 0x28, 0x31
};

unsigned char prime256v1_P[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};
unsigned char prime256v1_A[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
};
unsigned char prime256v1_B[] = {
    0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7,
    0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
    0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
    0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B
};
unsigned char prime256v1_Gx[] = {
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
    0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
    0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
    0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96
};
unsigned char prime256v1_Gy[] = {
    0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B,
    0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
    0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
    0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5
};
unsigned char prime256v1_N[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
};

int get_named_curve(const char* curve_name, elliptic_curve* target) {
    if (!strcmp("prime192v1", curve_name) || !strcmp("secp192r1", curve_name)) {
        huge_load(&target->p, prime192v1_P, sizeof(prime192v1_P));
        huge_load(&target->a, prime192v1_A, sizeof(prime192v1_A));
        huge_load(&target->b, prime192v1_B, sizeof(prime192v1_B));
        huge_load(&target->G.x, prime192v1_Gx, sizeof(prime192v1_Gx));
        huge_load(&target->G.y, prime192v1_Gy, sizeof(prime192v1_Gy));
        huge_load(&target->n, prime192v1_N, sizeof(prime192v1_N));
        return 0;
    } else if (!strcmp("prime256v1", curve_name) || !strcmp("secp256r1", curve_name)) {
        huge_load(&target->p, prime256v1_P, sizeof(prime256v1_P));
        huge_load(&target->a, prime256v1_A, sizeof(prime256v1_A));
        huge_load(&target->b, prime256v1_B, sizeof(prime256v1_B));
        huge_load(&target->G.x, prime256v1_Gx, sizeof(prime256v1_Gx));
        huge_load(&target->G.y, prime256v1_Gy, sizeof(prime256v1_Gy));
        huge_load(&target->n, prime256v1_N, sizeof(prime256v1_N));
        return 0;
    }
    return 1;
}

void double_point(point* p1, huge* a, huge* p) {
    //if p1==p2
    //k=(3x1^2+a)/(2y1)
    //x3=k^2-x1-x2
    //y3=k(x1-x3)-y1

    huge k, x3, y3, tmp;
    huge_set(&k, 3);
    huge_multiply(&k, &p1->x);
    huge_multiply(&k, &p1->x);
    huge_add(&k, a);
    huge_set(&tmp, 2);
    huge_multiply(&tmp, &p1->y);
    huge_inverse_mul(&tmp, p);
    huge_multiply(&k, &tmp);

    huge_set(&x3, 0);
    huge_copy(&x3, &k);
    huge_multiply(&x3, &k);
    huge_subtract(&x3, &p1->x);
    huge_subtract(&x3, &p1->x);
    huge_divide(&x3, p, NULL);

    huge_set(&y3, 0);
    huge_copy(&y3, &p1->x);
    huge_subtract(&y3, &x3);
    huge_multiply(&y3, &k);
    huge_subtract(&y3, &p1->y);
    huge_divide(&y3, p, NULL);

    x3.sign = 0;
    // huge_inverse_neg(&x3, p);
    huge_inverse_neg(&y3, p);

    huge_copy(&p1->x, &x3);
    huge_copy(&p1->y, &y3);
    free(k.rep);
    free(x3.rep);
    free(y3.rep);
    free(tmp.rep);
}

void add_points(point* p1, point* p2, huge* p) {
    //if p1!=p2
    //k=(y2-y1)/(x2-x1)
    //x3=k^2-x1-x2
    //y3=k(x1-x3)-y1

    huge k, x3, y3, tmp;
    huge_set(&k, 0);
    huge_copy(&k, &p2->y);
    huge_subtract(&k, &p1->y);
    huge_set(&tmp, 0);
    huge_copy(&tmp, &p2->x);
    huge_subtract(&tmp, &p1->x);
    huge_inverse_mul(&tmp, p);
    huge_multiply(&k, &tmp);

    huge_set(&x3, 0);
    huge_copy(&x3, &k);
    huge_multiply(&x3, &k);
    huge_subtract(&x3, &p1->x);
    huge_subtract(&x3, &p2->x);
    huge_divide(&x3, p, NULL);

    huge_set(&y3, 0);
    huge_copy(&y3, &p1->x);
    huge_subtract(&y3, &x3);
    huge_multiply(&y3, &k);
    huge_subtract(&y3, &p1->y);
    huge_divide(&y3, p, NULL);

    huge_inverse_neg(&x3, p);
    huge_inverse_neg(&y3, p);

    huge_copy(&p1->x, &x3);
    huge_copy(&p1->y, &y3);
    free(k.rep);
    free(x3.rep);
    free(y3.rep);
    free(tmp.rep);
}

void multiply_point(point* p1, huge* k, huge* a, huge* p) {
    point sum;
    int hasCopy = 0;

    huge_set(&sum.x, 0);
    huge_set(&sum.y, 0);
    huge_copy(&sum.x, &p1->x);
    huge_copy(&sum.y, &p1->y);

    for (int i = k->size - 1; i >= 0; i--) {
        for (unsigned int mask = 0x00000001; mask; mask <<= 1) {
            if (k->rep[i] & mask) {
                if (!hasCopy) {
                    hasCopy = 1;
                    huge_copy(&p1->x, &sum.x);
                    huge_copy(&p1->y, &sum.y);
                } else {
                    add_points(p1, &sum, p);
                    // printf("before-----------:\n");
                    // show_hex(p1->x.rep, p1->x.size, HUGE_WORD_BYTES);
                    // show_hex(p1->y.rep, p1->y.size, HUGE_WORD_BYTES);
                    // printf("double:\n");
                    // show_hex(sum.x.rep, sum.x.size, HUGE_WORD_BYTES);
                    // show_hex(sum.y.rep, sum.y.size, HUGE_WORD_BYTES);
                    // add_points(p1, &sum, p);
                    // printf("after-----------:\n");
                    // show_hex(p1->x.rep, p1->x.size, HUGE_WORD_BYTES);
                    // show_hex(p1->y.rep, p1->y.size, HUGE_WORD_BYTES);
                }
            }
            double_point(&sum, a, p);
            // printf("double:\n");
            // show_hex(sum.x.rep, sum.x.size, HUGE_WORD_BYTES);
            // show_hex(sum.y.rep, sum.y.size, HUGE_WORD_BYTES);
        }
    }

    free(sum.x.rep);
    free(sum.y.rep);
}

// #define TEST_ECC
#ifdef TEST_ECC
#include "hex.h"
#include <time.h>

int main() {
    clock_t start, end;
    int _a = 1, b = 1, _p = 23;
    point p1, p2;
    huge a, p, k;
    huge_set(&a, _a);
    huge_set(&p, _p);

    // for (int x = 0; x < 100; x += 1) {
    //     int y = x * x * x + _a * x * x + b, r = y * 2 % _p;
    //     printf("x=%d,y=%d,r=%d\n", x, y, r);
    //     huge_set(&p1.x, x);
    //     huge_set(&p1.y, y);
    //     double_point(&p1, &a, &p);
    //     show_hex(p1.x.rep, p1.x.size, HUGE_WORD_BYTES);
    //     show_hex(p1.y.rep, p1.y.size, HUGE_WORD_BYTES);
    // }

    // huge_set(&p1.x, 1);
    // huge_set(&p1.y, 0);
    // double_point(&p1, &a, &p);
    // show_hex(p1.x.rep, p1.x.size, HUGE_WORD_BYTES);
    // show_hex(p1.y.rep, p1.y.size, HUGE_WORD_BYTES);

    // for (int x = 0; x < 200; x += 2) {
    //     int x1 = x, x2 = x+1;
    //     int y1 = x1 * x1 * x1 + _a * x1 * x1 + b;
    //     int y2 = x2 * x2 * x2 + _a * x2 * x2 + b;
    //     printf("x1=%d,y1=%d,x2=%d,y2=%d\n", x1, y1, x2, y2);
    //     huge_set(&p1.x, x1);
    //     huge_set(&p1.y, y1);
    //     huge_set(&p2.x, x2);
    //     huge_set(&p2.y, y2);
    //     add_points(&p1, &p2, &p);
    //     show_hex(p1.x.rep, p1.x.size, HUGE_WORD_BYTES);
    //     show_hex(p1.y.rep, p1.y.size, HUGE_WORD_BYTES);
    // }

    // huge_set(&p1.x, 0x04);
    // huge_set(&p1.y, 0x51);
    // huge_set(&p2.x, 1);
    // huge_set(&p2.y, 3);
    // add_points(&p1, &p2, &p);
    // show_hex(p1.x.rep, p1.x.size, HUGE_WORD_BYTES);
    // show_hex(p1.y.rep, p1.y.size, HUGE_WORD_BYTES);
    start = clock();
    for (int x = 0; x < 1000; x += 1) {
        // if (x != 126) {
        //     continue;
        // }
        int y = x * x * x + _a * x * x + b, r = y * 2 % _p;
        printf("x=%d,y=%d,r=%d\n", x, y, r);
        huge_set(&p1.x, x);
        huge_set(&p1.y, y);
        huge_set(&k, 1234);
        multiply_point(&p1, &k, &a, &p);
        show_hex(p1.x.rep, p1.x.size, HUGE_WORD_BYTES);
        show_hex(p1.y.rep, p1.y.size, HUGE_WORD_BYTES);

        huge_set(&p1.x, x);
        huge_set(&p1.y, y);
        huge_set(&k, 101);
        multiply_point(&p1, &k, &a, &p);
        show_hex(p1.x.rep, p1.x.size, HUGE_WORD_BYTES);
        show_hex(p1.y.rep, p1.y.size, HUGE_WORD_BYTES);
    }
    end = clock();
    printf("duration: %fs", (double)(end - start) / CLOCKS_PER_SEC);

    return 0;
}
#endif
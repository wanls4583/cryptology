#include <stdlib.h>
#include <stdio.h>
#include "ecc.h"

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
#include <stdlib.h>
#include "ecc.h"
#include "hex.h"

void double_point(point* p1, huge* a, huge* p) {
    //if p1==p2
    //k=(3x1^2+a)/(2y1)
    //x3=k^2-x1-x2
    //y3=k(x1-x3)-y1

    huge k, x3, y3, tmp;
    set_huge(&k, 3);
    multiply(&k, &p1->x);
    multiply(&k, &p1->x);
    add(&k, a);
    set_huge(&tmp, 2);
    multiply(&tmp, &p1->y);
    inv(&tmp, p);
    multiply(&k, &tmp);

    set_huge(&x3, 0);
    copy_huge(&x3, &k);
    multiply(&x3, &k);
    subtract(&x3, &p1->x);
    subtract(&x3, &p1->x);
    divide(&x3, p, NULL);

    set_huge(&y3, 0);
    copy_huge(&y3, &p1->x);
    subtract(&y3, &x3);
    multiply(&y3, &k);
    subtract(&y3, &p1->y);
    divide(&x3, p, NULL);

    negativeInv(&x3, p);
    negativeInv(&y3, p);

    copy_huge(&p1->x, &x3);
    copy_huge(&p1->y, &y3);
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
    set_huge(&k, 0);
    copy_huge(&k, &p2->y);
    subtract(&k, &p1->y);
    set_huge(&tmp, 0);
    copy_huge(&tmp, &p2->x);
    subtract(&tmp, &p1->x);
    inv(&tmp, p);
    multiply(&k, &tmp);

    set_huge(&x3, 0);
    copy_huge(&x3, &k);
    multiply(&x3, &k);
    subtract(&x3, &p1->x);
    subtract(&x3, &p2->x);
    divide(&x3, p, NULL);

    set_huge(&y3, 0);
    copy_huge(&y3, &p1->x);
    subtract(&y3, &x3);
    multiply(&y3, &k);
    subtract(&y3, &p1->y);
    divide(&x3, p, NULL);

    negativeInv(&x3, p);
    negativeInv(&y3, p);

    copy_huge(&p1->x, &x3);
    copy_huge(&p1->y, &y3);
    free(k.rep);
    free(x3.rep);
    free(y3.rep);
    free(tmp.rep);
}

void multiply_point(point* p1, huge* k, huge* a, huge* p) {
    point sum;
    int hasCopy = 0;

    set_huge(&sum.x, 0);
    set_huge(&sum.y, 0);
    copy_huge(&sum.x, &p1->x);
    copy_huge(&sum.y, &p1->y);

    for (int i = k->size - 1; i >= 0; i--) {
        for (unsigned char mask = 0x00000001; mask; mask <<= 1) {
            if (k->rep[i] & mask) {
                if (!hasCopy) {
                    hasCopy = 1;
                    copy_huge(&p1->x, &sum.x);
                    copy_huge(&p1->y, &sum.y);
                } else {
                    add_points(p1, &sum, p);
                }
            }
            double_point(&sum, a, p);
        }
    }

    free(sum.x.rep);
    free(sum.y.rep);
}

#define TEST_ECC
#ifdef TEST_ECC
int main() {
  point p1, p2;
  huge a, p;
  set_huge(&a, 1);
  set_huge(&p, 23);

  set_huge(&p1.x, 0);
  set_huge(&p1.y, 1);
  double_point(&p1, &a, &p);
  show_hex(p1.x.rep, p1.x.size);
  show_hex(p1.y.rep, p1.y.size);

  return 0;
}
#endif
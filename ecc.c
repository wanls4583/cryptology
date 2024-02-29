#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "ecc.h"
#include "hex.h"

unsigned char prime192v1_P[] = "0xfffffffffffffffffffffffffffffffeffffffffffffffff";
unsigned char prime192v1_A[] = "0xfffffffffffffffffffffffffffffffefffffffffffffffc";
unsigned char prime192v1_B[] = "0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1";
unsigned char prime192v1_Gx[] = "0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012";
unsigned char prime192v1_Gy[] = "0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811";
unsigned char prime192v1_N[] = "0xffffffffffffffffffffffff99def836146bc9b1b4d22831";

unsigned char prime256v1_P[] = "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
unsigned char prime256v1_A[] = "0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc";
unsigned char prime256v1_B[] = "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
unsigned char prime256v1_Gx[] = "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
unsigned char prime256v1_Gy[] = "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
unsigned char prime256v1_N[] = "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

unsigned char secp192k1_P[] = "0xfffffffffffffffffffffffffffffffffffffffeffffee37";
unsigned char secp192k1_A[] = "0x000000000000000000000000000000000000000000000000";
unsigned char secp192k1_B[] = "0x000000000000000000000000000000000000000000000003";
unsigned char secp192k1_Gx[] = "0xdb4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d";
unsigned char secp192k1_Gy[] = "0x9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d";
unsigned char secp192k1_N[] = "0xfffffffffffffffffffffffe26f2fc170f69466a74defd8d";

unsigned char x25519_P[] = "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed";
unsigned char x25519_A[] = "0x076d06";
unsigned char x25519_B[] = "0x01";
unsigned char x25519_Gx[] = "0x09";
unsigned char x25519_Gy[] = "0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9";
unsigned char x25519_N[] = "0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed";

unsigned char curve_A[] = { 0x07, 0x6d, 0x06 };

int get_named_curve(const char* curve_name, elliptic_curve* target) {
    unsigned char* p, * a, * b, * x, * y, * n = NULL;
    int p_size, a_size, b_size, x_size, y_size, n_size;

    if (!strcmp("prime192v1", curve_name) || !strcmp("secp192r1", curve_name)) {
        p_size = hex_decode(prime192v1_P, &p);
        a_size = hex_decode(prime192v1_A, &a);
        b_size = hex_decode(prime192v1_B, &b);
        x_size = hex_decode(prime192v1_Gx, &x);
        y_size = hex_decode(prime192v1_Gy, &y);
        n_size = hex_decode(prime192v1_N, &n);
    } else if (!strcmp("prime256v1", curve_name) || !strcmp("secp256r1", curve_name)) {
        p_size = hex_decode(prime256v1_P, &p);
        a_size = hex_decode(prime256v1_A, &a);
        b_size = hex_decode(prime256v1_B, &b);
        x_size = hex_decode(prime256v1_Gx, &x);
        y_size = hex_decode(prime256v1_Gy, &y);
        n_size = hex_decode(prime256v1_N, &n);
    } else if (!strcmp("secp192k1", curve_name) || !strcmp("ansip192k1", curve_name)) {
        p_size = hex_decode(secp192k1_P, &p);
        a_size = hex_decode(secp192k1_A, &a);
        b_size = hex_decode(secp192k1_B, &b);
        x_size = hex_decode(secp192k1_Gx, &x);
        y_size = hex_decode(secp192k1_Gy, &y);
        n_size = hex_decode(secp192k1_N, &n);
    } else if (!strcmp("x25519", curve_name) || !strcmp("Curve25519", curve_name)) {
        p_size = hex_decode(x25519_P, &p);
        a_size = hex_decode(x25519_A, &a);
        b_size = hex_decode(x25519_B, &b);
        x_size = hex_decode(x25519_Gx, &x);
        y_size = hex_decode(x25519_Gy, &y);
        n_size = hex_decode(x25519_N, &n);
    }

    if (n) {
        huge_load(&target->p, p, p_size);
        huge_load(&target->a, a, a_size);
        huge_load(&target->b, b, b_size);
        huge_load(&target->G.x, x, x_size);
        huge_load(&target->G.y, y, y_size);
        huge_load(&target->n, n, n_size);
        return 0;
    }
    return 1;
}

void double_point(point* p1, huge* a, huge* p) {
    //if p1==p2
    //k=(3*x1^2+a)/(2y1)
    //if is25519
    //k=(3*x1^2+2A*x1+1)/(2y1)
    //x3=k^2-x1-x2
    //if is25519
    //x3=k^2-A-x1-x2
    //y3=k(x1-x3)-y1

    int is25519 = 0;
    huge k, x3, y3, tmp;
    huge_set(&k, 3);
    huge_multiply(&k, &p1->x);
    huge_multiply(&k, &p1->x);

    if (is25519) {
        huge_set(&tmp, 1);
        huge_add(&k, &tmp);
        huge_load(&tmp, curve_A, sizeof(curve_A));
        huge_add(&tmp, &tmp);
        huge_multiply(&tmp, &p1->x);
        huge_add(&k, &tmp);
    } else {
        huge_add(&k, a);
    }

    huge_set(&tmp, 2);
    huge_multiply(&tmp, &p1->y);
    huge_inverse_mul(&tmp, p);
    huge_multiply(&k, &tmp);

    huge_set(&x3, 0);
    huge_copy(&x3, &k);
    huge_multiply(&x3, &k);
    huge_subtract(&x3, &p1->x);
    huge_subtract(&x3, &p1->x);

    if (is25519) {
        huge_load(&tmp, curve_A, sizeof(curve_A));
        huge_subtract(&x3, &tmp);
    }

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
    //if is25519
    //x3=k^2-A-x1-x2
    //y3=k(x1-x3)-y1

    int is25519 = 0;
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

    if (is25519) {
        huge_load(&tmp, curve_A, sizeof(curve_A));
        huge_subtract(&x3, &tmp);
    }

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

void multiply_25519(huge* p1, huge* k, huge* p) {
    huge x_1, x_2, z_2, x_3, z_3;

    huge_set(&x_1, 0);
    huge_copy(&x_1, p1);

    huge_set(&x_2, 1);
    huge_set(&z_2, 0);

    huge_set(&x_3, 0);
    huge_copy(&x_3, p1);
    huge_set(&z_3, 1);

    int swap = 0, k_t;
    huge k1, A, AA, B, BB, C, D, E, DA, CB;
    huge curveA, multA24;

    huge_set(&k1, 0);
    huge_set(&A, 0);
    huge_set(&AA, 0);
    huge_set(&B, 0);
    huge_set(&BB, 0);
    huge_set(&C, 0);
    huge_set(&D, 0);
    huge_set(&E, 0);
    huge_set(&DA, 0);
    huge_set(&CB, 0);
    huge_set(&multA24, 0);

    huge_load(&curveA, curve_A, sizeof(curve_A));
    // multA24 = (curveA - 2) / 4
    huge_copy(&multA24, &curveA);
    huge_set(&k1, 2);
    huge_subtract(&multA24, &k1);
    huge_set(&k1, 4);
    huge_divide(&multA24, &k1, &A);
    huge_copy(&multA24, &A);

    for (int t = 255; t >= 0; t--) {
        huge_copy(&k1, k);
        huge_right_shift(&k1, t);
        k_t = k1.rep[k1.size - 1] & 0x01;
        swap ^= k_t;
        if (swap) {
            huge_swap(&x_2, &x_3, 1);
            huge_swap(&z_2, &z_3, 1);
        }
        swap = k_t;

        // A = x_2 + z_2
        huge_copy(&A, &x_2);
        huge_add(&A, &z_2);
        // AA = A*A
        huge_copy(&AA, &A);
        huge_multiply(&AA, &A);

        // B = x_2 - z_2
        huge_copy(&B, &x_2);
        huge_subtract(&B, &z_2);
        // BB = B*B
        huge_copy(&BB, &B);
        huge_multiply(&BB, &B);

        // E = AA - BB
        huge_copy(&E, &AA);
        huge_subtract(&E, &BB);

        // C = x_3 + z_3
        huge_copy(&C, &x_3);
        huge_add(&C, &z_3);

        // D = x_3 - z_3
        huge_copy(&D, &x_3);
        huge_subtract(&D, &z_3);

        // DA = D * A
        huge_copy(&DA, &D);
        huge_multiply(&DA, &A);

        // CB = C * B
        huge_copy(&CB, &C);
        huge_multiply(&CB, &B);

        // x_3 = (DA + CB) * (DA + CB);
        huge_copy(&x_3, &DA);
        huge_add(&x_3, &CB);
        huge_multiply(&x_3, &x_3);
        huge_divide(&x_3, p, NULL);

        // z_3 = x_1 * (DA - CB) * (DA - CB)
        huge_copy(&z_3, &DA);
        huge_subtract(&z_3, &CB);
        huge_multiply(&z_3, &z_3);
        huge_multiply(&z_3, &x_1);
        huge_divide(&z_3, p, NULL);

        // x_2 = AA * BB
        huge_copy(&x_2, &AA);
        huge_multiply(&x_2, &BB);
        huge_divide(&x_2, p, NULL);

        // z_2 = E * (AA + multA24 * E)
        huge_copy(&z_2, &multA24);
        huge_multiply(&z_2, &E);
        huge_add(&z_2, &AA);
        huge_multiply(&z_2, &E);
        huge_divide(&z_2, p, NULL);
        // printf("t=%d\n", t);
        // show_hex(x_3.rep, x_3.size, HUGE_WORD_BYTES);
        // show_hex(z_3.rep, z_3.size, HUGE_WORD_BYTES);
        // show_hex(x_2.rep, x_2.size, HUGE_WORD_BYTES);
        // show_hex(z_2.rep, z_2.size, HUGE_WORD_BYTES);
        // printf("----------------------------------\n");
    }

    if (swap) {
        huge_swap(&x_2, &x_3, 1);
        huge_swap(&z_2, &z_3, 1);
    }

    // x = x_2 / z_2
    huge_copy(p1, &z_2);
    huge_inverse_mul(p1, p);
    huge_multiply(p1, &x_2);
    huge_divide(p1, p, NULL);
}

// #define TEST_ECC
#ifdef TEST_ECC
#include "hex.h"
#include "privkey.h"
#include <time.h>

int test1() {
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

void test2() {
    elliptic_curve curve;
    huge priv, pub;
    int len;
    unsigned char* tmp;

    huge_set(&priv, 0);
    huge_set(&pub, 0);
    get_named_curve("x25519", &curve);

    len = hex_decode((unsigned char*)"0x77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", &tmp);
    huge_load(&priv, tmp, len);
    clamp_x25519_priv(&priv);
    len = hex_decode((unsigned char*)"0xde9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", &tmp);
    huge_load(&pub, tmp, len);
    huge_reverse(&pub);
    multiply_25519(&pub, &priv, &curve.p);
    huge_reverse(&pub);
    // 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
    show_hex(pub.rep, pub.size, HUGE_WORD_BYTES);

    len = hex_decode((unsigned char*)"0x5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", &tmp);
    huge_load(&priv, tmp, len);
    clamp_x25519_priv(&priv);
    len = hex_decode((unsigned char*)"0x8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", &tmp);
    huge_load(&pub, tmp, len);
    huge_reverse(&pub);
    multiply_25519(&pub, &priv, &curve.p);
    huge_reverse(&pub);
    // 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
    show_hex(pub.rep, pub.size, HUGE_WORD_BYTES);
}

int main() {
    test2();
    return 0;
}
#endif
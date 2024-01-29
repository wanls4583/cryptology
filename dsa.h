#ifndef DSA_H
#define DSA_H

#include "huge.h"
#include "digest.h"

typedef struct {
	huge g;
	huge p;
	huge q;
}
dsa_params;

typedef struct {
	dsa_params params;
	huge pub;
	huge key;
}
dsa_key;

typedef struct {
	huge r;
	huge s;
}
dsa_signature;

void dsa_sign(
	dsa_params* params,
	huge* private_key,
	unsigned char* sign_input,
	int sign_input_len,
	dsa_signature* signature
);

int dsa_verify(
	dsa_params* params,
	huge* public_key,
	unsigned char* sign_input,
	int sign_input_len,
	dsa_signature* signature
);

#endif

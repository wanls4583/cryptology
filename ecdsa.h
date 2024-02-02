#ifndef ECDSA_H
#define ECDSA_H

#include "huge.h"
#include "digest.h"
#include "ecc.h"

typedef struct {
	huge r;
	huge s;
}
ecdsa_signature;

void ecdsa_sign(
	elliptic_curve* params,
	ecc_key* private_key,
	unsigned char* sign_input,
	int sign_input_len,
	ecdsa_signature* signature
);

int ecdsa_verify(
	elliptic_curve* params,
	ecc_key* public_key,
	unsigned char* sign_input,
	int sign_input_len,
	ecdsa_signature* signature
);

#endif

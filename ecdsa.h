#ifndef DSA_H
#define DSA_H

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
	digest_ctx* ctx,
	ecdsa_signature* signature
);

int ecdsa_verify(
	elliptic_curve* params,
	ecc_key* public_key,
	digest_ctx* ctx,
	ecdsa_signature* signature
);

#endif

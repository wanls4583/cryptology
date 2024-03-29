#ifndef X509_H
#define X509_H

#include <time.h>
#include "huge.h"
#include "rsa.h"
#include "dsa.h"
#include "dh.h"

typedef enum {
	rsa,
	dsa,
	dh
}
algorithmIdentifier;

typedef enum {
	md5WithRSAEncryption,
	shaWithRSAEncryption,
	sha256WithRSAEncryption,
	shaWithDSA
}
signatureAlgorithmIdentifier;

/**
 * A name (or "distinguishedName") is a list of attribute-value pairs.
 * Instead of keeping track of all of them, just keep track of
 * the most interesting ones.
 */
typedef struct {
	char* idAtCountryName;
	char* idAtStateOrProvinceName;
	char* idAtLocalityName;
	char* idAtOrganizationName;
	char* idAtOrganizationalUnitName;
	char* idAtCommonName;
}
name;

typedef struct {
	// TODO deal with the "utcTime" or "GeneralizedTime" choice.
	time_t notBefore;
	time_t notAfter;
}
validity_period;

typedef huge uniqueIdentifier;

typedef struct {
	algorithmIdentifier algorithm;
	rsa_key rsa_public_key;

	// DSA or DH parameters, only if algorithm == dsa
	dsa_params dsa_parameters;

	// DSA parameters, only if algorithm == dsa
	huge dsa_public_key;

	dh_key dh_parameters;
}
public_key_info;

typedef huge objectIdentifier;

typedef struct {
	int version;
	huge serialNumber; // This can be much longer than a 4-byte long allows
	signatureAlgorithmIdentifier signature;
	name issuer;
	validity_period validity;
	name subject;
	public_key_info subjectPublicKeyInfo;
	uniqueIdentifier issuerUniqueId;
	uniqueIdentifier subjectUniqueId;
	int certificate_authority; // 1 if this is a CA, 0 if not
}
x509_certificate;

typedef struct {
	x509_certificate tbsCertificate;
	digest_ctx* digest;
	signatureAlgorithmIdentifier algorithm;
	huge rsa_signature_value;
	dsa_signature dsa_signature_value;
}
signed_x509_certificate;

void init_x509_certificate(signed_x509_certificate* certificate);
int parse_x509_certificate(
	unsigned char* buffer,
	unsigned int certificate_length,
	signed_x509_certificate* parsed_certificate
);
unsigned char* parse_x509_chain(
	unsigned char* buffer,
	int pdu_length,
	public_key_info* server_public_key
);
void free_x509_certificate(signed_x509_certificate* certificate);

#endif

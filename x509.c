#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "asn1.h"
#include "x509.h"
#include "digest.h"
#include "md5.h"
#include "sha.h"
#include "hex.h"

int validate_node(
    struct asn1struct* source,
    int expected_tag,
    int expected_children,
    char* desc) {

    if (!source) {
        fprintf(stderr, "Error - '%s' missing.\n", desc);
    }

    if (source->tag != expected_tag) {
        fprintf(stderr, "Error parsing '%s'; expected a %d tag, got a %d.\n", desc, expected_tag, source->tag);
        return 0;
    }

    int counted_children = 0;
    struct asn1struct* child = source->children;
    while (counted_children < expected_children) {
        if (!child) {
            fprintf(stderr, "Error parsing '%s'; expected %d children, found %d.\n", desc, expected_children, counted_children);
            return 0;
        }
        counted_children++;
        child = child->next;
    }

    return 1;
}

void init_x509_certificate(signed_x509_certificate* certificate) {
    huge_set(&certificate->tbsCertificate.serialNumber, 1);
    memset(&certificate->tbsCertificate.issuer, 0, sizeof(name));
    memset(&certificate->tbsCertificate.subject, 0, sizeof(name));
    certificate->tbsCertificate.subjectPublicKeyInfo.rsa_public_key.p = (huge*)malloc(sizeof(huge));
    certificate->tbsCertificate.subjectPublicKeyInfo.rsa_public_key.key = (huge*)malloc(sizeof(huge));
    huge_set(certificate->tbsCertificate.subjectPublicKeyInfo.rsa_public_key.p, 0);
    huge_set(certificate->tbsCertificate.subjectPublicKeyInfo.rsa_public_key.key, 0);
    huge_set(&certificate->rsa_signature_value, 0);
    huge_set(&certificate->dsa_signature_value.r, 0);
    huge_set(&certificate->dsa_signature_value.s, 0);
    certificate->tbsCertificate.certificate_authority = 0;
}

void free_x500_name(name* x500_name) {
    if (x500_name->idAtCountryName) { free(x500_name->idAtCountryName); }
    if (x500_name->idAtStateOrProvinceName) { free(x500_name->idAtStateOrProvinceName); }
    if (x500_name->idAtLocalityName) { free(x500_name->idAtLocalityName); }
    if (x500_name->idAtOrganizationName) { free(x500_name->idAtOrganizationName); }
    if (x500_name->idAtOrganizationalUnitName) { free(x500_name->idAtOrganizationalUnitName); }
    if (x500_name->idAtCommonName) { free(x500_name->idAtCommonName); }
}

void free_x509_certificate(signed_x509_certificate* certificate) {
    huge_free(&certificate->tbsCertificate.serialNumber);
    free_x500_name(&certificate->tbsCertificate.issuer);
    free_x500_name(&certificate->tbsCertificate.subject);
    huge_free(certificate->tbsCertificate.subjectPublicKeyInfo.rsa_public_key.p);
    huge_free(certificate->tbsCertificate.subjectPublicKeyInfo.rsa_public_key.key);
    free(certificate->tbsCertificate.subjectPublicKeyInfo.rsa_public_key.p);
    free(certificate->tbsCertificate.subjectPublicKeyInfo.rsa_public_key.key);
    huge_free(&certificate->rsa_signature_value);
    huge_free(&certificate->dsa_signature_value.r);
    huge_free(&certificate->dsa_signature_value.s);
}

void parse_huge(huge* target, struct asn1struct* source) {
    huge_load(target, source->data, source->length);
}

static const unsigned char OID_md5WithRSA[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04 };
static const unsigned char OID_sha1WithRSA[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05 };
static const unsigned char OID_sha1WithDSA[] = { 0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x03 };
static const unsigned char OID_sha256WithRSA[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B };

int parse_algorithm_identifier(signatureAlgorithmIdentifier* target, struct asn1struct* source) {
    struct asn1struct* oid = (struct asn1struct*)source->children;

    if (!validate_node(oid, ASN1_OBJECT_IDENTIFIER, 0, "algorithm identifier oid")) {
        return 2;
    }

    if (!memcmp(oid->data, OID_md5WithRSA, oid->length)) {
        *target = md5WithRSAEncryption;
    } else if (!memcmp(oid->data, OID_sha1WithDSA, oid->length)) {
        *target = shaWithDSA;
    } else if (!memcmp(oid->data, OID_sha1WithRSA, oid->length)) {
        *target = shaWithRSAEncryption;
    } else if (!memcmp(oid->data, OID_sha256WithRSA, oid->length)) {
        *target = sha256WithRSAEncryption;
    } else {
        fprintf(stderr, "Unsupported or unrecognized algorithm identifier OID ");
        for (int i = 0; i < oid->length; i++) {
            fprintf(stderr, "%.02x ", oid->data[i]);
        }
        fprintf(stderr, "\n");
        return 2;
    }

    return 0;
}

static unsigned char OID_idAtCommonName[] = { 0x55, 0x04, 0x03 };
static unsigned char OID_idAtCountryName[] = { 0x55, 0x04, 0x06 };
static unsigned char OID_idAtLocalityName[] = { 0x55, 0x04, 0x07 };
static unsigned char OID_idAtStateOrProvinceName[] = { 0x55, 0x04, 0x08 };
static unsigned char OID_idAtOrganizationName[] = { 0x55, 0x04, 0x0A };
static unsigned char OID_idAtOrganizationalUnitName[] = { 0x55, 0x04, 0x0B };

/**
 * Name parsing is a bit different. Loop through all of the
 * children of the source, each of which is going to be a struct containing
 * an OID and a value. If the OID is recognized, copy it's contents
 * to the correct spot in "target". Otherwise, ignore it.
 */
int parse_name(name* target, struct asn1struct* source) {
    struct asn1struct* typeValuePair;
    struct asn1struct* typeValuePairSequence;
    struct asn1struct* type;
    struct asn1struct* value;

    target->idAtCountryName = NULL;
    target->idAtStateOrProvinceName = NULL;
    target->idAtLocalityName = NULL;
    target->idAtOrganizationName = NULL;
    target->idAtOrganizationalUnitName = NULL;
    target->idAtCommonName = NULL;

    if (!validate_node(source, ASN1_SEQUENCE, 1, "name")) {
        return 1;
    }

    typeValuePair = source->children;
    while (typeValuePair) {
        if (!validate_node(typeValuePair, ASN1_SET, 1, "tag value pair in name")) {
            return 1;
        }

        typeValuePairSequence = (struct asn1struct*)typeValuePair->children;

        if (!validate_node(typeValuePairSequence, ASN1_SEQUENCE, 2, "tag value pair in name")) {
            return 2;
        }

        type = (struct asn1struct*)typeValuePairSequence->children;

        if (!validate_node(type, ASN1_OBJECT_IDENTIFIER, 0, "tag value pair in name type")) {
            return 3;
        }

        value = (struct asn1struct*)type->next;

        if (!(value->tag == ASN1_PRINTABLE_STRING ||
            value->tag == ASN1_TELETEX_STRING ||
            value->tag == ASN1_IA5_STRING ||
            value->tag == ASN1_UTF8_STRING)) {
            fprintf(stderr, "Error parsing tag value pair in name, expected a string tag, got a %d\n",
                value->tag);
            return 4;
        }

        if (!memcmp(type->data, OID_idAtCountryName, type->length)) {
            target->idAtCountryName = (char*)malloc(value->length + 1);
            memcpy(target->idAtCountryName, value->data, value->length);
            target->idAtCountryName[value->length] = 0;
        } else if (!memcmp(type->data, OID_idAtStateOrProvinceName, type->length)) {
            target->idAtStateOrProvinceName = (char*)malloc(value->length + 1);
            memcpy(target->idAtStateOrProvinceName, value->data, value->length);
            target->idAtStateOrProvinceName[value->length] = 0;
        } else if (!memcmp(type->data, OID_idAtLocalityName, type->length)) {
            target->idAtLocalityName = (char*)malloc(value->length + 1);
            memcpy(target->idAtLocalityName, value->data, value->length);
            target->idAtLocalityName[value->length] = 0;
        } else if (!memcmp(type->data, OID_idAtOrganizationName, type->length)) {
            target->idAtOrganizationName = (char*)malloc(value->length + 1);
            memcpy(target->idAtOrganizationName, value->data, value->length);
            target->idAtOrganizationName[value->length] = 0;
        } else if (!memcmp(type->data, OID_idAtOrganizationalUnitName,
            type->length)) {
            target->idAtOrganizationalUnitName = (char*)
                malloc(value->length + 1);
            memcpy(target->idAtOrganizationalUnitName, value->data, value->length);
            target->idAtOrganizationalUnitName[value->length] = 0;
        } else if (!memcmp(type->data, OID_idAtCommonName, type->length)) {
            target->idAtCommonName = (char*)malloc(value->length + 1);
            memcpy(target->idAtCommonName, value->data, value->length);
            target->idAtCommonName[value->length] = 0;
        } else {
            int i;

            // This is just advisory - NOT a problem
            printf("Skipping unrecognized or unsupported name token OID of ");
            for (i = 0; i < type->length; i++) {
                printf("%.02x ", type->data[i]);
            }
            printf("\n");
        }

        typeValuePair = typeValuePair->next;
    }

    return 0;
}

int parse_validity(validity_period* target, struct asn1struct* source) {
    struct asn1struct* not_before;
    struct asn1struct* not_after;
    struct tm not_before_tm;
    struct tm not_after_tm;

    if (!validate_node(source, ASN1_SEQUENCE, 2, "validity")) {
        return 1;
    }

    not_before = source->children;

    if ((not_before->tag != ASN1_UTC_TIME) && (not_before->tag != ASN1_GENERALIZED_TIME)) {
        fprintf(stderr, "Error parsing not before; expected a date but got a %d\n", not_before->tag);
        return 3;
    }

    not_after = not_before->next;

    if ((not_after->tag != ASN1_UTC_TIME) && (not_after->tag != ASN1_GENERALIZED_TIME)) {
        fprintf(stderr, "Error parsing not after; expected a date but got a %d\n", not_after->tag);
        return 5;
    }

    // Convert time instances into time_t
    if (sscanf((char*)not_before->data, "%2d%2d%2d%2d%2d%2d",
        &not_before_tm.tm_year, &not_before_tm.tm_mon, &not_before_tm.tm_mday,
        &not_before_tm.tm_hour, &not_before_tm.tm_min, &not_before_tm.tm_sec) < 6) {
        fprintf(stderr, "Error parsing not before; malformed date.");
        return 6;
    }
    if (sscanf((char*)not_after->data, "%2d%2d%2d%2d%2d%2d",
        &not_after_tm.tm_year, &not_after_tm.tm_mon, &not_after_tm.tm_mday,
        &not_after_tm.tm_hour, &not_after_tm.tm_min, &not_after_tm.tm_sec) < 6) {
        fprintf(stderr, "Error parsing not after; malformed date.");
        return 7;
    }

    not_before_tm.tm_year += 100;
    not_after_tm.tm_year += 100;
    not_before_tm.tm_mon -= 1;
    not_after_tm.tm_mon -= 1;

    // TODO account for TZ information on end
    target->notBefore = mktime(&not_before_tm);
    target->notAfter = mktime(&not_after_tm);

    return 0;
}

static const unsigned char OID_RSA[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
static const unsigned char OID_DSA[] = { 0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01 };
static const unsigned char OID_DH[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x03, 0x01 };

static int parse_dsa_params(public_key_info* target, struct asn1struct* source) {
    struct asn1struct* p;
    struct asn1struct* q;
    struct asn1struct* g;

    p = source->children;
    q = p->next;
    g = q->next;

    parse_huge(&target->dsa_parameters.p, p);
    parse_huge(&target->dsa_parameters.q, q);
    parse_huge(&target->dsa_parameters.g, g);

    return 0;
}

static int parse_dh_params(public_key_info* target, struct asn1struct* source) {
    struct asn1struct* p;
    struct asn1struct* g;

    p = source->children;
    g = p->next;

    parse_huge(&target->dh_parameters.p, p);
    parse_huge(&target->dh_parameters.g, g);

    return 0;
}

static int parse_public_key_info(public_key_info* target, struct asn1struct* source) {
    struct asn1struct* oid;
    struct asn1struct* public_key;
    struct asn1struct public_key_value;

    if (!validate_node(source, ASN1_SEQUENCE, 2, "public key info")) {
        return 1;
    }

    if (!validate_node(source->children, ASN1_SEQUENCE, 1, "public key OID")) {
        return 2;
    }

    oid = source->children->children;
    public_key = source->children->next;

    if (!validate_node(oid, ASN1_OBJECT_IDENTIFIER, 0, "public key OID")) {
        return 3;
    }

    if (!validate_node(public_key, ASN1_BIT_STRING, 0, "public key info")) {
        return 4;
    }

    // The public key is a bit string encoding yet another ASN.1 DER-encoded
    // value - need to parse *that* here
    // Skip over the "0" byte in the public key.
    if (asn1parse(public_key->data + 1,
        public_key->length - 1,
        &public_key_value)) {
        fprintf(stderr, "Error; public key node is malformed (not ASN.1 DER-encoded)\n");
        return 5;
    }

    if (!memcmp(oid->data, &OID_RSA, sizeof(OID_RSA))) {
        target->algorithm = rsa;

        if (!validate_node(&public_key_value, ASN1_SEQUENCE, 2, "RSA public key value")) {
            return 6;
        }

        parse_huge(target->rsa_public_key.p, public_key_value.children);
        parse_huge(target->rsa_public_key.key, public_key_value.children->next);
        // This is important. Most times, the response includes a trailing 0 byte
        // to stop implementations from interpreting it as a twos-complement
        // negative number. However, in this implementation, this causes the
        // results to be the wrong size, so they need to be contracted.
        huge_contract(target->rsa_public_key.p);
        huge_contract(target->rsa_public_key.key);
    } else if (!memcmp(oid->data, &OID_DSA, sizeof(OID_DSA))) {
        struct asn1struct* params;
        target->algorithm = dsa;

        if (!validate_node(&public_key_value, ASN1_INTEGER, 0, "DSA public key value")) {
            return 6;
        }

        parse_huge(&target->dsa_public_key, &public_key_value);
        params = oid->next;

        if (!validate_node(params, ASN1_SEQUENCE, 3, "DSA public key params")) {
            return 6;
        }

        parse_dsa_params(target, params);
    } else  if (!memcmp(oid->data, &OID_DH, sizeof(OID_DH))) {
        struct asn1struct* params;
        target->algorithm = dh;

        if (!validate_node(&public_key_value, ASN1_INTEGER, 0, "DH public key value")) {
            return 6;
        }

        parse_huge(&target->dh_parameters.Y, &public_key_value);
        params = oid->next;

        if (!validate_node(params, ASN1_SEQUENCE, 2, "DH public key params")) {
            return 6;
        }

        parse_dh_params(target, params);
    } else {
        fprintf(stderr, "Error; unsupported OID in public key info.\n");
        return 7;
    }

    asn1free(&public_key_value);

    return 0;
}

int asn1_get_bit(int length, unsigned char* bit_string, int bit) {
    if (bit > ((length - 1) * 8)) {
        return 0;
    } else {
        return bit_string[1 + (bit / 8)] & (0x80 >> (bit % 8));
    }
}

static const unsigned char OID_keyUsage[] = { 0x55, 0x1D, 0x0F };
#define BIT_CERT_SIGNER 5

static int parse_extension(x509_certificate* certificate,
    struct asn1struct* source) {
    struct asn1struct* oid;
    struct asn1struct* critical;
    struct asn1struct* data;

    oid = (struct asn1struct*)source->children;
    critical = (struct asn1struct*)oid->next;
    if (critical->tag == ASN1_BOOLEAN) {
        data = (struct asn1struct*)critical->next;
    } else {
        // critical defaults to false
        data = critical;
        critical = NULL;
    }
    if (!memcmp(oid->data, OID_keyUsage, oid->length)) {
        struct asn1struct key_usage_bit_string;
        asn1parse(data->data, data->length, &key_usage_bit_string);
        if (asn1_get_bit(key_usage_bit_string.length, key_usage_bit_string.data, BIT_CERT_SIGNER)) {
            certificate->certificate_authority = 1;
        }
        asn1free(&key_usage_bit_string);
    }
    // TODO recognize and parse extensions � there are several

    return 0;
}

int parse_extensions(x509_certificate* certificate, struct asn1struct* source) {
    // Parse each extension; if one is recognized, update the certificate
    // in some way
    source = source->children->children;
    while (source) {
        if (parse_extension(certificate, source)) {
            return 1;
        }
        source = source->next;
    }

    return 0;
}

int parse_tbs_certificate(x509_certificate* target, struct asn1struct* source) {
    struct asn1struct* version;
    struct asn1struct* serialNumber;
    struct asn1struct* signatureAlgorithmIdentifier;
    struct asn1struct* issuer;
    struct asn1struct* validity;
    struct asn1struct* subject;
    struct asn1struct* publicKeyInfo;
    struct asn1struct* extensions;

    if (!validate_node(source, ASN1_SEQUENCE, 6, "TBS certificate")) {
        return 2;
    }

    // Figure out if there's an explicit version or not; if there is, then everything
    // else "shifts down" one spot.
    version = (struct asn1struct*)source->children;

    if (version->tag == 0 && version->tag_class == ASN1_CONTEXT_SPECIFIC) {
        struct asn1struct* versionNumber = (struct asn1struct*)version->children;

        if (!validate_node(versionNumber, ASN1_INTEGER, 0, "version number")) {
            return 2;
        }

        // This will only ever be one byte; safe
        target->version = (*versionNumber->data) + 1;
        serialNumber = (struct asn1struct*)version->next;
    } else {
        target->version = 1; // default if not provided
        serialNumber = (struct asn1struct*)version;
    }

    signatureAlgorithmIdentifier = (struct asn1struct*)serialNumber->next;
    issuer = (struct asn1struct*)signatureAlgorithmIdentifier->next;
    validity = (struct asn1struct*)issuer->next;
    subject = (struct asn1struct*)validity->next;
    publicKeyInfo = (struct asn1struct*)subject->next;
    extensions = (struct asn1struct*)publicKeyInfo->next;

    parse_huge(&target->serialNumber, serialNumber);

    if (parse_algorithm_identifier(&target->signature,
        signatureAlgorithmIdentifier)) {
        return 3;
    }
    if (parse_name(&target->issuer, issuer)) { return 4; }
    if (parse_validity(&target->validity, validity)) { return 5; }
    if (parse_name(&target->subject, subject)) { return 6; }
    if (parse_public_key_info(&target->subjectPublicKeyInfo, publicKeyInfo)) {
        return 7;
    }
    if (extensions) {
        if (parse_extensions(target, extensions)) { return 8; }
    }

    return 0;
}

int parse_rsa_signature_value(signed_x509_certificate* target, struct asn1struct* source) {
    parse_huge(&target->rsa_signature_value, source);
    huge_contract(&target->rsa_signature_value);

    return 0;
}

int parse_dsa_signature_value(signed_x509_certificate* target, struct asn1struct* source) {
    struct asn1struct dsa_signature;

    if (asn1parse(source->data + 1, source->length - 1, &dsa_signature)) {
        fprintf(stderr, "Unable to parse ASN.1 DER-encoded signature.\n");
        return 1;
    }

    parse_huge(&target->dsa_signature_value.r, dsa_signature.children);
    parse_huge(&target->dsa_signature_value.s, dsa_signature.children->next);

    asn1free(&dsa_signature);

    return 0;
}

int parse_x509_certificate(
    unsigned char* buffer,
    unsigned int certificate_length,
    signed_x509_certificate* parsed_certificate
) {
    struct asn1struct certificate;
    struct asn1struct* tbsCertificate;
    struct asn1struct* algorithmIdentifier;
    struct asn1struct* signatureValue;
    digest_ctx* digest = (digest_ctx*)malloc(sizeof(digest_ctx));

    // First, read the whole thing into a traversable ASN.1 structure
    asn1parse(buffer, certificate_length, &certificate);

    // Version can be implicit or explicit
    tbsCertificate = (struct asn1struct*)certificate.children;

    algorithmIdentifier = (struct asn1struct*)tbsCertificate->next;
    signatureValue = (struct asn1struct*)algorithmIdentifier->next;

    if (parse_tbs_certificate(&parsed_certificate->tbsCertificate,
        tbsCertificate)) {
        fprintf(stderr, "Error trying to parse TBS certificate\n");
        return 42;
    }
    if (parse_algorithm_identifier(&parsed_certificate->algorithm,
        algorithmIdentifier)) {
        return 42;
    }

    switch (parsed_certificate->algorithm) {
    case md5WithRSAEncryption:
    case shaWithRSAEncryption:
    case sha256WithRSAEncryption:
        if (parse_rsa_signature_value(parsed_certificate, signatureValue)) {
            return 42;
        }
        break;
    case shaWithDSA:
        if (parse_dsa_signature_value(parsed_certificate, signatureValue)) {
            return 42;
        }
    }

    switch (parsed_certificate->algorithm) {
    case md5WithRSAEncryption:
        new_md5_digest(digest);
        break;
    case shaWithRSAEncryption:
    case shaWithDSA:
        new_sha1_digest(digest);
        break;
    case sha256WithRSAEncryption:
        new_sha256_digest(digest);
    default:
        break;
    }
    update_digest(digest, tbsCertificate->data, tbsCertificate->length);
    finalize_digest(digest);
    parsed_certificate->digest = digest;
    asn1free(&certificate);

    return 0;
}

/**
 * This is called by "receive_server_hello" when the "certificate" PDU
 * is encountered.  The input to this function should be a certificate chain.
 * The most important certificate is the first one, since this contains the
 * public key of the subject as well as the DNS name information (which
 * has to be verified against).
 * Each subsequent certificate acts as a signer for the previous certificate.
 * Each signature is verified by this function.
 * The public key of the first certificate in the chain will be returned in
 * "server_public_key" (subsequent certificates are just needed for signature
 * verification).
 * TODO verify signatures.
 */
unsigned char* parse_x509_chain(
    unsigned char* buffer,
    int pdu_length,
    public_key_info* server_public_key
) {
    int pos;
    signed_x509_certificate certificate;
    unsigned int chain_length, certificate_length;
    unsigned char* ptr;
    ptr = buffer;

    pos = 0;

    // TODO this won't work on a big-endian machine
    chain_length = (*ptr << 16) | (*(ptr + 1) << 8) | (*(ptr + 2));
    ptr += 3;

    // The chain length is actually redundant since the length of the PDU has
    // already been input.
    assert(chain_length == (pdu_length - 3));

    while ((ptr - buffer) < pdu_length) {
        // TODO this won't work on a big-endian machine
        certificate_length = (*ptr << 16) | (*(ptr + 1) << 8) | (*(ptr + 2));
        ptr += 3;

        init_x509_certificate(&certificate);

        parse_x509_certificate((void*)ptr, certificate_length, &certificate);
        if (!pos++) {
            server_public_key->algorithm =
                certificate.tbsCertificate.subjectPublicKeyInfo.algorithm;
            switch (server_public_key->algorithm) {
            case rsa:
                server_public_key->rsa_public_key.p = (huge*)malloc(sizeof(huge));
                server_public_key->rsa_public_key.key = (huge*)malloc(sizeof(huge));
                huge_set(server_public_key->rsa_public_key.p, 0);
                huge_set(server_public_key->rsa_public_key.key, 0);
                huge_copy(server_public_key->rsa_public_key.p, certificate.tbsCertificate.subjectPublicKeyInfo.rsa_public_key.p);
                huge_copy(server_public_key->rsa_public_key.key, certificate.tbsCertificate.subjectPublicKeyInfo.rsa_public_key.key);
                break;
            default:
                break;
            }
        }

        ptr += certificate_length;

        // TODO compute the hash of the certificate so that it can be validated by
        // the next one

        free_x509_certificate(&certificate);
    }

    return ptr;
}

void output_x500_name(name* x500_name) {
    printf("C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s\n",
        (x500_name->idAtCountryName ? x500_name->idAtCountryName : "?"),
        (x500_name->idAtStateOrProvinceName ? x500_name->idAtStateOrProvinceName : "?"),
        (x500_name->idAtLocalityName ? x500_name->idAtLocalityName : "?"),
        (x500_name->idAtOrganizationName ? x500_name->idAtOrganizationName : "?"),
        (x500_name->idAtOrganizationalUnitName ? x500_name->idAtOrganizationalUnitName : "?"),
        (x500_name->idAtCommonName ? x500_name->idAtCommonName : "?"));
}

void print_huge(huge* h) {
    show_hex(h->rep, h->size, HUGE_WORD_BYTES);
}

void display_x509_certificate(signed_x509_certificate* certificate) {
    printf("Certificate details:\n");
    printf("Version: %d\n", certificate->tbsCertificate.version);
    printf("Serial number: ");
    print_huge(&certificate->tbsCertificate.serialNumber);
    printf("issuer: ");
    output_x500_name(&certificate->tbsCertificate.issuer);
    printf("subject: ");
    output_x500_name(&certificate->tbsCertificate.subject);
    printf("not before: %s", asctime(gmtime(
        &certificate->tbsCertificate.validity.notBefore)));
    printf("not after: %s", asctime(gmtime(
        &certificate->tbsCertificate.validity.notAfter)));
    printf("Public key algorithm: ");
    switch (certificate->tbsCertificate.subjectPublicKeyInfo.algorithm) {
    case rsa:
        printf("RSA\n");
        printf("p: ");
        print_huge(certificate->tbsCertificate.subjectPublicKeyInfo.rsa_public_key.p);
        printf("key: ");
        print_huge(certificate->tbsCertificate.subjectPublicKeyInfo.rsa_public_key.key);
        break;
    case dsa:
        printf("DSA\n");
        printf("y: ");
        print_huge(&certificate->tbsCertificate.subjectPublicKeyInfo.dsa_public_key);
        printf("p: ");
        print_huge(&certificate->tbsCertificate.subjectPublicKeyInfo.dsa_parameters.p);
        printf("q: ");
        print_huge(&certificate->tbsCertificate.subjectPublicKeyInfo.dsa_parameters.q);
        printf("g: ");
        print_huge(&certificate->tbsCertificate.subjectPublicKeyInfo.dsa_parameters.g);
        break;
    case dh:
        printf("DH\n");
        printf("y: ");
        print_huge(&certificate->tbsCertificate.subjectPublicKeyInfo.dh_parameters.Y);
        printf("p: ");
        print_huge(&certificate->tbsCertificate.subjectPublicKeyInfo.dh_parameters.p);
        printf("g: ");
        print_huge(&certificate->tbsCertificate.subjectPublicKeyInfo.dh_parameters.g);
        break;
    default:
        printf("?\n");
        break;
    }

    printf("Signature algorithm: ");

    switch (certificate->algorithm) {
    case md5WithRSAEncryption:
        printf("MD5 with RSA Encryption\n");
        break;
    case shaWithDSA:
        printf("SHA-1 with DSA\n");
        break;
    case shaWithRSAEncryption:
        printf("SHA-1 with RSA Encryption\n");
        break;
    case sha256WithRSAEncryption:
        printf("SHA-256 with RSA Encryption\n");
        break;
    }

    printf("Signature value: ");

    switch (certificate->algorithm) {
    case md5WithRSAEncryption:
    case shaWithRSAEncryption:
    case sha256WithRSAEncryption:
        print_huge(&certificate->rsa_signature_value);
        break;
    case shaWithDSA:
        printf("\n\tr:");
        print_huge(&certificate->dsa_signature_value.r);
        printf("\ts:");
        print_huge(&certificate->dsa_signature_value.s);
        break;
    }
    printf("\n");

    if (certificate->tbsCertificate.certificate_authority) {
        printf("is a CA\n");
    } else {
        printf("is not a CA\n");
    }
}

/**
 * An RSA signature is an ASN.1 DER-encoded PKCS-7 structure including
 * the OID of the signature algorithm (again), and the signature value.
 */
int validate_certificate_rsa(signed_x509_certificate* certificate, rsa_key* public_key) {
    unsigned char* pkcs7_signature_decrypted;
    int pkcs7_signature_len;
    struct asn1struct pkcs7_signature;
    struct asn1struct* hash_value;
    int valid = 0;
    int bytes = huge_bytes(&certificate->rsa_signature_value);
    unsigned char input[bytes];

    huge_unload(&certificate->rsa_signature_value, input, bytes);
    pkcs7_signature_len = rsa_decrypt(public_key, input, bytes, &pkcs7_signature_decrypted, RSA_PKCS1_PADDING);
    if (pkcs7_signature_len == -1) {
        fprintf(stderr, "Unable to decode signature value.\n");
        return valid;
    }
    if (asn1parse(pkcs7_signature_decrypted, pkcs7_signature_len, &pkcs7_signature)) {
        fprintf(stderr, "Unable to parse signature\n");
        return valid;
    }

    hash_value = pkcs7_signature.children->next;

    if (memcmp(hash_value->data, certificate->digest->hash, certificate->digest->hash_size)) {
        valid = 0;
    } else {
        valid = 1;
    }

    asn1free(&pkcs7_signature);

    return valid;
}

int validate_certificate_dsa(signed_x509_certificate* certificate) {
    return dsa_verify(
        &certificate->tbsCertificate.subjectPublicKeyInfo.dsa_parameters,
        &certificate->tbsCertificate.subjectPublicKeyInfo.dsa_public_key,
        (unsigned char*)certificate->digest->hash,
        certificate->digest->result_size,
        &certificate->dsa_signature_value);
}

// #define TEST_X509
#ifdef TEST_X509
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
int main() {
    int argc = 3;
    char* argv[] = { "", "-pem", "./res/dhserver.pem" };
    int certificate_file;
    struct stat certificate_file_stat;
    unsigned char* buffer;
    unsigned char* bufptr;
    int buffer_size;
    int bytes_read;
    int code;

    signed_x509_certificate certificate;


    if ((certificate_file = open(argv[2], O_RDONLY)) == -1) {
        perror("Unable to open certificate file");
        return 1;
    }

    // Slurp the whole thing into memory
    if (fstat(certificate_file, &certificate_file_stat)) {
        perror("Unable to stat certificate file");
        return 2;
    }

    buffer_size = certificate_file_stat.st_size;
    buffer = (unsigned char*)malloc(buffer_size);
    if (!buffer) {
        perror("Not enough memory");
        return 3;
    }

    bufptr = buffer;

    while ((bytes_read = read(certificate_file, (void*)buffer, buffer_size))) {
        bufptr += bytes_read;
    }

    unsigned char* pem_buffer = buffer;
    buffer = (unsigned char*)malloc(buffer_size);
    buffer_size = pem_decode(pem_buffer, buffer, NULL, NULL);
    free(pem_buffer);

    // now parse it
    init_x509_certificate(&certificate);
    if (!(code = parse_x509_certificate(buffer, buffer_size,
        &certificate))) {
        printf("X509 Certificate:\n");
        display_x509_certificate(&certificate);

        // Assume it's a self-signed certificate and try to validate it that
        switch (certificate.algorithm) {
        case md5WithRSAEncryption:
        case shaWithRSAEncryption:
        case sha256WithRSAEncryption:
            if (rsa == certificate.tbsCertificate.subjectPublicKeyInfo.algorithm &&
                validate_certificate_rsa(&certificate, &certificate.tbsCertificate.subjectPublicKeyInfo.rsa_public_key)) {
                printf("Certificate is a valid self-signed certificate.\n");
            } else {
                printf("Certificate is corrupt or not self-signed.\n");
            }
            break;
        case shaWithDSA:
            if (dsa == certificate.tbsCertificate.subjectPublicKeyInfo.algorithm && validate_certificate_dsa(&certificate)) {
                printf("Certificate is a valid self-signed certificate.\n");
            } else {
                printf("Certificate is corrupt or not self-signed.\n");
            }
        }
    } else {
        printf("error parsing certificate: %d\n", code);
    }

    free_x509_certificate(&certificate);
    free(buffer);
    return 0;
}
#endif

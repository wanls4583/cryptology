#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#ifdef WIN32
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#include <arpa/inet.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include "file.h"
#include "privkey.h"
#include "md5.h"
#include "sha.h"
#include "digest.h"
#include "hmac.h"
#include "prf.h"
#include "des.h"
#include "rc4.h"
#include "aes.h"
#include "tls.h"
#include "hex.h"
#include "asn1.h"
#include "ecdsa.h"
#include "hkdf.h"

#define VERIFY_DATA_LEN 12

// session_id 和 session_ticket 机制不能同时启用
#ifndef USE_SESSION_ID
#define USE_SESSION_TICKET
#endif

#ifndef USE_SESSION_TICKET
#define USE_SESSION_ID
#endif

#if TLS_VERSION_MINOR >= 4
#undef USE_SESSION_TICKET
#undef USE_SESSION_ID
#endif

extern unsigned char SECP256R1_OID[8];
extern unsigned char SECP192R1_OID[8];
extern unsigned char SECP192K1_OID[5];

typedef struct {
    unsigned char* session_id;
    unsigned char* master_secret;
} session_and_master;

static int next_session_id = 1;
static int session_count = 0;
static unsigned char SESSION_TICKET_EXT[] = { 0x00, 0x23 };
static unsigned char KEY_SHARE_EXT[] = { 0x00, 0x33 };
static unsigned char KEY_SHARE_GROUP_X25519[] = { 0x00, 0x1d };
static unsigned char SUPPORT_VERSION_EXT[] = { 0x00, 0x2b };
static unsigned char RENEGOTIATE_INF_EXT[] = { 0xff, 0x01 };
static unsigned char session_key[] = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };

//RFC 3447-9.2 EMSA-PKCS1-v1_5
// DigestInfo ::= SEQUENCE {
//     digestAlgorithm AlgorithmIdentifier,
//     digest OCTET STRING
// }
const static unsigned char MD5_DER_PRE[] = { 0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10 };
const static unsigned char SHA_1_DER_PRE[] = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };
const static unsigned char SHA_256_DER_PRE[] = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
const static unsigned char SHA_384_DER_PRE[] = { 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 };
const static unsigned char sha_512_DER_PRE[] = { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };

static session_and_master stored_sessions[100];

int tls3_decrypt(
    unsigned char* header,
    unsigned char* encrypted_message,
    short encrypted_length,
    unsigned char** decrypted_message,
    ProtectionParameters* parameters
);

void set_data(unsigned char* target, unsigned char* str) {
    int length;
    unsigned char* data;
    length = hex_decode(str, &data);
    memcpy(target, data, length);
}
/*
Key Exchange Algorithm               Description                             Key size limit
------------------------------------------------------------------------------------------------------
DHE_DSS                              Ephemeral DH with DSS signatures        None

DHE_DSS_EXPORT                       Ephemeral DH with DSS signatures        DH = 512 bits

DHE_RSA                              Ephemeral DH with RSA signatures        None

DHE_RSA_EXPORT                       Ephemeral DH with RSA signatures        DH = 512 bits, RSA = none

DH_anon                              Anonymous DH, no signatures             None

DH_anon_EXPORT                       Anonymous DH, no signatures             DH = 512 bits

DH_DSS                               DH with DSS-based certificates          None

DH_DSS_EXPORT                        DH with DSS-based certificates          DH = 512 bits

DH_RSA                               DH with RSA-based certificates          None

DH_RSA_EXPORT                        DH with RSA-based certificates          DH = 512 bits,RSA = none

NULL                                 No key exchange                         N/A

RSA                                  RSA key exchange                        None

RSA_EXPORT                           RSA key exchange                        RSA = 512 bits
 */
CipherSuite suites[MAX_SUPPORTED_CIPHER_SUITE] =
{
    { TLS_NULL_WITH_NULL_NULL, 1, 0, 0, 0, 0, NULL, NULL, NULL },
    { TLS_RSA_WITH_NULL_MD5, 1, 0, 0, 0, MD5_BYTE_SIZE, NULL, NULL, new_md5_digest },
    { TLS_RSA_WITH_NULL_SHA, 1, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
    { TLS_RSA_EXPORT_WITH_RC4_40_MD5, 1, 0, 0, 5, MD5_BYTE_SIZE, rc4_40_encrypt, rc4_40_decrypt, new_md5_digest },
    { TLS_RSA_WITH_RC4_128_MD5, 1, 0, 0, 16, MD5_BYTE_SIZE, rc4_128_encrypt, rc4_128_decrypt, new_md5_digest },
    { TLS_RSA_WITH_RC4_128_SHA, 1, 0, 0, 16, SHA1_BYTE_SIZE, rc4_128_encrypt, rc4_128_decrypt, new_sha1_digest },
    { TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5, 1, 0, 0, 0, MD5_BYTE_SIZE, NULL, NULL, new_md5_digest },
    { TLS_RSA_WITH_IDEA_CBC_SHA, 1, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
    { TLS_RSA_EXPORT_WITH_DES40_CBC_SHA, 1, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
    { TLS_RSA_WITH_DES_CBC_SHA, 1, 8, 8, 8, SHA1_BYTE_SIZE, (encrypt_func)des_encrypt, (decrypt_func)des_decrypt, new_sha1_digest },
    { TLS_RSA_WITH_3DES_EDE_CBC_SHA, 1, 8, 8, 14, SHA1_BYTE_SIZE, (encrypt_func)des3_encrypt, (decrypt_func)des3_decrypt, new_sha1_digest },
    { TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA, 1, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
    { TLS_DH_DSS_WITH_DES_CBC_SHA, 1, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
    { TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA, 1, 8, 8, 14, SHA1_BYTE_SIZE, (encrypt_func)des3_encrypt, (decrypt_func)des3_decrypt, new_sha1_digest },
    { TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA, 1, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
    { TLS_DH_RSA_WITH_DES_CBC_SHA, 1, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
    { TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA, 1, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
    { TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA, 1, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
    { TLS_DHE_DSS_WITH_DES_CBC_SHA, 1, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
    { TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, 1, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
    { TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA, 1, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
    { TLS_DHE_RSA_WITH_DES_CBC_SHA, 1, 8, 8, 8, SHA1_BYTE_SIZE, (encrypt_func)des_encrypt, (decrypt_func)des_decrypt, new_sha1_digest },
    { TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA, 1, 8, 8, 14, SHA1_BYTE_SIZE, (encrypt_func)des3_encrypt, (decrypt_func)des3_decrypt, new_sha1_digest },
    { TLS_DH_anon_EXPORT_WITH_RC4_40_MD5, 1, 0, 0, 0, MD5_BYTE_SIZE, NULL, NULL, new_md5_digest },
    { TLS_DH_anon_WITH_RC4_128_MD5, 1, 0, 0, 0, MD5_BYTE_SIZE, NULL, NULL, new_md5_digest },
    { TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA, 1, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
    { TLS_DH_anon_WITH_DES_CBC_SHA, 1, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
    { TLS_DH_anon_WITH_3DES_EDE_CBC_SHA, 1, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
    { 0x001C, 1, 0, 0, 0, 0, NULL, NULL, NULL },
    { 0x001D, 1, 0, 0, 0, 0, NULL, NULL, NULL },
    { TLS_KRB5_WITH_DES_CBC_SHA, 1, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
    { TLS_KRB5_WITH_3DES_EDE_CBC_SHA, 1, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
    { TLS_KRB5_WITH_RC4_128_SHA, 1, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
    { TLS_KRB5_WITH_IDEA_CBC_SHA, 1, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
    { TLS_KRB5_WITH_DES_CBC_MD5, 1, 0, 0, 0, MD5_BYTE_SIZE, NULL, NULL, new_md5_digest },
    { TLS_KRB5_WITH_3DES_EDE_CBC_MD5, 1, 0, 0, 0, MD5_BYTE_SIZE, NULL, NULL, new_md5_digest },
    { TLS_KRB5_WITH_RC4_128_MD5, 1, 0, 0, 0, MD5_BYTE_SIZE, NULL, NULL, new_md5_digest },
    { TLS_KRB5_WITH_IDEA_CBC_MD5, 1, 0, 0, 0, MD5_BYTE_SIZE, NULL, NULL, new_md5_digest },
    { TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA, 1, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
    { TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA, 1, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
    { TLS_KRB5_EXPORT_WITH_RC4_40_SHA, 1, 0, 0, 0, SHA1_BYTE_SIZE, NULL, NULL, new_sha1_digest },
    { TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5, 1, 0, 0, 0, MD5_BYTE_SIZE, NULL, NULL, new_md5_digest },
    { TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5, 1, 0, 0, 0, MD5_BYTE_SIZE, NULL, NULL, new_md5_digest },
    { TLS_KRB5_EXPORT_WITH_RC4_40_MD5, 1, 0, 0, 0, MD5_BYTE_SIZE, NULL, NULL, new_md5_digest },
    { 0x002C, 1, 0, 0, 0, 0, NULL, NULL, NULL },
    { 0x002D, 1, 0, 0, 0, 0, NULL, NULL, NULL },
    { 0x002E, 1, 0, 0, 0, 0, NULL, NULL, NULL },
    { TLS_RSA_WITH_AES_128_CBC_SHA, 1, 16, 16, 16, SHA1_BYTE_SIZE, (encrypt_func)aes_128_encrypt, (decrypt_func)aes_128_decrypt, new_sha1_digest },
    { TLS_DH_DSS_WITH_AES_128_CBC_SHA, 1, 16, 16, 16, SHA1_BYTE_SIZE, (encrypt_func)aes_128_encrypt, (decrypt_func)aes_128_decrypt, new_sha1_digest },
    { TLS_DH_RSA_WITH_AES_128_CBC_SHA, 1, 16, 16, 16, SHA1_BYTE_SIZE, (encrypt_func)aes_128_encrypt, (decrypt_func)aes_128_decrypt, new_sha1_digest },
    { TLS_DHE_DSS_WITH_AES_128_CBC_SHA, 1, 16, 16, 16, SHA1_BYTE_SIZE, (encrypt_func)aes_128_encrypt, (decrypt_func)aes_128_decrypt, new_sha1_digest },
    { TLS_DHE_RSA_WITH_AES_128_CBC_SHA, 1, 16, 16, 16, SHA1_BYTE_SIZE, (encrypt_func)aes_128_encrypt, (decrypt_func)aes_128_decrypt, new_sha1_digest },
    { TLS_DH_anon_WITH_AES_128_CBC_SHA, 1, 16, 16, 16, SHA1_BYTE_SIZE, (encrypt_func)aes_128_encrypt, (decrypt_func)aes_128_decrypt, new_sha1_digest },
    { TLS_RSA_WITH_AES_256_CBC_SHA, 1, 16, 16, 32, SHA1_BYTE_SIZE, (encrypt_func)aes_256_encrypt, (decrypt_func)aes_256_decrypt, new_sha1_digest },
    { TLS_DH_DSS_WITH_AES_256_CBC_SHA, 1, 16, 16, 32, SHA1_BYTE_SIZE, (encrypt_func)aes_256_encrypt, (decrypt_func)aes_256_decrypt, new_sha1_digest },
    { TLS_DH_RSA_WITH_AES_256_CBC_SHA, 1, 16, 16, 32, SHA1_BYTE_SIZE, (encrypt_func)aes_256_encrypt, (decrypt_func)aes_256_decrypt, new_sha1_digest },
    { TLS_DHE_DSS_WITH_AES_256_CBC_SHA, 1, 16, 16, 32, SHA1_BYTE_SIZE, (encrypt_func)aes_256_encrypt, (decrypt_func)aes_256_decrypt, new_sha1_digest },
    { TLS_DHE_RSA_WITH_AES_256_CBC_SHA, 1, 16, 16, 32, SHA1_BYTE_SIZE, (encrypt_func)aes_256_encrypt, (decrypt_func)aes_256_decrypt, new_sha1_digest },
    { TLS_DH_anon_WITH_AES_256_CBC_SHA, 1, 16, 16, 32, SHA1_BYTE_SIZE, (encrypt_func)aes_256_encrypt, (decrypt_func)aes_256_decrypt, new_sha1_digest },
};

rsa_key private_rsa_key;
rsa_key private_rsa_export_key;
dsa_key private_dsa_key;
ecc_key private_ecc_key;
ecc_key private_ecc_25519_key;
ecc_key private_ecdsa_key;
dh_key dh_priv_key;
dh_key dh_tmp_key;
huge dh_priv;

void init_dh_tmp_key() {
    unsigned char priv[] = {
        0x53, 0x61, 0xae, 0x4f, 0x6f, 0x25, 0x98, 0xde, 0xc4, 0xbf, 0x0b, 0xbe, 0x09,
        0x5f, 0xdf, 0x90, 0x2f, 0x4c, 0x8e, 0x09
    };
    unsigned char P[] = {
        0x9c, 0x4c, 0xaa, 0x76, 0x31, 0x2e, 0x71, 0x4d, 0x31, 0xd6, 0xe4, 0xd7, 0xe9,
        0xa7, 0x29, 0x7b, 0x7f, 0x05, 0xee, 0xfd, 0xca, 0x35, 0x14, 0x1e, 0x9f, 0xe5,
        0xc0, 0x2a, 0xe0, 0x12, 0xd9, 0xc4, 0xc0, 0xde, 0xcc, 0x66, 0x96, 0x2f, 0xf1,
        0x8f, 0x1a, 0xe1, 0xe8, 0xbf, 0xc2, 0x29, 0x0d, 0x27, 0x07, 0x48, 0xb9, 0x71,
        0x04, 0xec, 0xc7, 0xf4, 0x16, 0x2e, 0x50, 0x8d, 0x67, 0x14, 0x84, 0x7b,
        0x9c, 0x4c, 0xaa, 0x76, 0x31, 0x2e, 0x71, 0x4d, 0x31, 0xd6, 0xe4, 0xd7, 0xe9,
        0xa7, 0x29, 0x7b, 0x7f, 0x05, 0xee, 0xfd, 0xca, 0x35, 0x14, 0x1e, 0x9f, 0xe5,
        0xc0, 0x2a, 0xe0, 0x12, 0xd9, 0xc4, 0xc0, 0xde, 0xcc, 0x66, 0x96, 0x2f, 0xf1,
        0x8f, 0x1a, 0xe1, 0xe8, 0xbf, 0xc2, 0x29, 0x0d, 0x27, 0x07, 0x48, 0xb9, 0x71,
        0x04, 0xec, 0xc7, 0xf4, 0x16, 0x2e, 0x50, 0x8d, 0x67, 0x14, 0x84, 0x7b
    };
    unsigned char G[] = {
        0x7d, 0xcd, 0x66, 0x81, 0x61, 0x52, 0x21, 0x10, 0xf7, 0xa0, 0x83, 0x4c, 0x5f,
        0xc8, 0x84, 0xca, 0xe8, 0x8a, 0x9b, 0x9f, 0x19, 0x14, 0x8c, 0x7d, 0xd0, 0xee,
        0x33, 0xce, 0xb4, 0x57, 0x2d, 0x5e, 0x78, 0x3f, 0x06, 0xd7, 0xb3, 0xd6, 0x40,
        0x70, 0x2e, 0xb6, 0x12, 0x3f, 0x4a, 0x61, 0x38, 0xae, 0x72, 0x12, 0xfb, 0x77,
        0xde, 0x53, 0xb3, 0xa1, 0x99, 0xd8, 0xa8, 0x19, 0x96, 0xf7, 0x7f, 0x99,
        0x7d, 0xcd, 0x66, 0x81, 0x61, 0x52, 0x21, 0x10, 0xf7, 0xa0, 0x83, 0x4c, 0x5f,
        0xc8, 0x84, 0xca, 0xe8, 0x8a, 0x9b, 0x9f, 0x19, 0x14, 0x8c, 0x7d, 0xd0, 0xee,
        0x33, 0xce, 0xb4, 0x57, 0x2d, 0x5e, 0x78, 0x3f, 0x06, 0xd7, 0xb3, 0xd6, 0x40,
        0x70, 0x2e, 0xb6, 0x12, 0x3f, 0x4a, 0x61, 0x38, 0xae, 0x72, 0x12, 0xfb, 0x77,
        0xde, 0x53, 0xb3, 0xa1, 0x99, 0xd8, 0xa8, 0x19, 0x96, 0xf7, 0x7f, 0x99
    };

    huge pub;
    pub.rep = NULL;
    dh_tmp_key.Y.rep = NULL;

    huge_load(&dh_tmp_key.p, P, sizeof(P));
    huge_load(&dh_tmp_key.g, G, sizeof(G));
    huge_load(&dh_priv, priv, sizeof(priv));

    huge_copy(&pub, &dh_tmp_key.g);
    huge_mod_pow(&pub, &dh_priv, &dh_tmp_key.p);
    huge_copy(&dh_tmp_key.Y, &pub);
}

int init_dh_key() {
    unsigned char* pem_buffer;
    unsigned char* buffer;
    int buffer_length;

    if (!(pem_buffer = load_file("./res/dh_key.pem", &buffer_length))) {
        perror("Unable to load file");
        return 0;
    }

    buffer = (unsigned char*)malloc(buffer_length);
    buffer_length = pem_decode(pem_buffer, buffer, NULL, NULL);

    parse_private_dh_key(&dh_priv_key, buffer, buffer_length);
    free(buffer);

    return 1;
}

int init_rsa_key() {
    unsigned char* pem_buffer;
    unsigned char* buffer;
    int buffer_length;

    if (!(pem_buffer = load_file("./res/rsa_key.pem", &buffer_length))) {
        perror("Unable to load file");
        return 0;
    }
    buffer = (unsigned char*)malloc(buffer_length);
    buffer_length = pem_decode(pem_buffer, buffer, NULL, NULL);

    parse_private_key(&private_rsa_key, buffer, buffer_length);
    free(buffer);

    return 1;
}

int init_rsa_export_key() {
    unsigned char* pem_buffer;
    unsigned char* buffer;
    int buffer_length;

    if (!(pem_buffer = load_file("./res/rsa_export_key.pem", &buffer_length))) {
        perror("Unable to load file");
        return 0;
    }
    buffer = (unsigned char*)malloc(buffer_length);
    buffer_length = pem_decode(pem_buffer, buffer, NULL, NULL);

    parse_private_key(&private_rsa_export_key, buffer, buffer_length);
    free(buffer);

    return 1;
}

int init_dsa_key() {
    unsigned char* pem_buffer;
    unsigned char* buffer;
    int buffer_length;

    if (!(pem_buffer = load_file("./res/dsa_key.pem", &buffer_length))) {
        perror("Unable to load file");
        return 0;
    }
    buffer = (unsigned char*)malloc(buffer_length);
    buffer_length = pem_decode(pem_buffer, buffer, NULL, NULL);

    parse_private_dsa_key(&private_dsa_key, buffer, buffer_length);
    free(buffer);

    return 1;
}

int init_ecc_key() {
    unsigned char* pem_buffer;
    unsigned char* buffer;
    int buffer_length;

    if (!(pem_buffer = load_file("./res/ecdh_key.pem", &buffer_length))) {
        perror("Unable to load file");
        return 0;
    }
    buffer = (unsigned char*)malloc(buffer_length);
    buffer_length = pem_decode(pem_buffer, buffer, NULL, NULL);

    parse_private_ecdsa_key(&private_ecc_key, buffer, buffer_length);
    free(buffer);

    return 1;
}

int init_ecc_x25519_key() {
    unsigned char* pem_buffer;
    unsigned char* buffer;
    int buffer_length;

    if (!(pem_buffer = load_file("./res/ecdh_x25519_key.pem", &buffer_length))) {
        perror("Unable to load file");
        return 0;
    }
    buffer = (unsigned char*)malloc(buffer_length);
    buffer_length = pem_decode(pem_buffer, buffer, NULL, NULL);

    parse_x25519_priv(&private_ecc_25519_key, buffer, buffer_length);
    free(buffer);

    if (!(pem_buffer = load_file("./res/ecdh_x25519_pub.pem", &buffer_length))) {
        perror("Unable to load file");
        return 0;
    }
    buffer = (unsigned char*)malloc(buffer_length);
    buffer_length = pem_decode(pem_buffer, buffer, NULL, NULL);

    parse_x25519_pub(&private_ecc_25519_key, buffer, buffer_length);
    free(buffer);

    return 1;
}

int init_ecdsa_key() {
    unsigned char* pem_buffer;
    unsigned char* buffer;
    int buffer_length;

    if (!(pem_buffer = load_file("./res/ecdsa_key.pem", &buffer_length))) {
        perror("Unable to load file");
        return 0;
    }
    buffer = (unsigned char*)malloc(buffer_length);
    buffer_length = pem_decode(pem_buffer, buffer, NULL, NULL);

    parse_private_ecdsa_key(&private_ecdsa_key, buffer, buffer_length);
    free(buffer);

    return 1;
}

void init_ciphers() {
    suites[TLS_RSA_WITH_AES_128_GCM_SHA256].id = TLS_RSA_WITH_AES_128_GCM_SHA256;
    suites[TLS_RSA_WITH_AES_128_GCM_SHA256].min_version = 3;
    suites[TLS_RSA_WITH_AES_128_GCM_SHA256].block_size = 16;
    suites[TLS_RSA_WITH_AES_128_GCM_SHA256].IV_size = 12;
    suites[TLS_RSA_WITH_AES_128_GCM_SHA256].key_size = 16;
    suites[TLS_RSA_WITH_AES_128_GCM_SHA256].hash_size = 0;
    suites[TLS_RSA_WITH_AES_128_GCM_SHA256].bulk_encrypt = NULL;
    suites[TLS_RSA_WITH_AES_128_GCM_SHA256].bulk_decrypt = NULL;
    suites[TLS_RSA_WITH_AES_128_GCM_SHA256].new_digest = new_sha256_digest;
    suites[TLS_RSA_WITH_AES_128_GCM_SHA256].aead_encrypt = (aead_encrypt_func)aes_128_gcm_encrypt;
    suites[TLS_RSA_WITH_AES_128_GCM_SHA256].aead_decrypt = (aead_decrypt_func)aes_128_gcm_decrypt;

    memcpy(&suites[TLS_AES_128_GCM_SHA256], &suites[TLS_RSA_WITH_AES_128_GCM_SHA256], sizeof(CipherSuite));
    suites[TLS_AES_128_GCM_SHA256].hash_size = SHA256_BYTE_SIZE;

    suites[TLS_RSA_WITH_AES_256_GCM_SHA384].id = TLS_RSA_WITH_AES_256_GCM_SHA384;
    suites[TLS_RSA_WITH_AES_256_GCM_SHA384].min_version = 3;
    suites[TLS_RSA_WITH_AES_256_GCM_SHA384].block_size = 16;
    suites[TLS_RSA_WITH_AES_256_GCM_SHA384].IV_size = 12;
    suites[TLS_RSA_WITH_AES_256_GCM_SHA384].key_size = 32;
    suites[TLS_RSA_WITH_AES_256_GCM_SHA384].hash_size = 0;
    suites[TLS_RSA_WITH_AES_256_GCM_SHA384].bulk_encrypt = NULL;
    suites[TLS_RSA_WITH_AES_256_GCM_SHA384].bulk_decrypt = NULL;
    suites[TLS_RSA_WITH_AES_256_GCM_SHA384].new_digest = new_sha384_digest;
    suites[TLS_RSA_WITH_AES_256_GCM_SHA384].aead_encrypt = (aead_encrypt_func)aes_256_gcm_encrypt;
    suites[TLS_RSA_WITH_AES_256_GCM_SHA384].aead_decrypt = (aead_decrypt_func)aes_256_gcm_decrypt;

    memcpy(&suites[TLS_AES_256_GCM_SHA384], &suites[TLS_RSA_WITH_AES_256_GCM_SHA384], sizeof(CipherSuite));
    suites[TLS_AES_256_GCM_SHA384].hash_size = SHA384_BYTE_SIZE;

    suites[TLS_ECDH_RSA_WITH_AES_128_CBC_SHA].id = TLS_ECDH_RSA_WITH_AES_128_CBC_SHA;
    suites[TLS_ECDH_RSA_WITH_AES_128_CBC_SHA].min_version = 3;
    suites[TLS_ECDH_RSA_WITH_AES_128_CBC_SHA].block_size = 16;
    suites[TLS_ECDH_RSA_WITH_AES_128_CBC_SHA].IV_size = 16;
    suites[TLS_ECDH_RSA_WITH_AES_128_CBC_SHA].key_size = 16;
    suites[TLS_ECDH_RSA_WITH_AES_128_CBC_SHA].hash_size = SHA1_BYTE_SIZE;
    suites[TLS_ECDH_RSA_WITH_AES_128_CBC_SHA].bulk_encrypt = (encrypt_func)aes_128_encrypt;
    suites[TLS_ECDH_RSA_WITH_AES_128_CBC_SHA].bulk_decrypt = (decrypt_func)aes_128_decrypt;
    suites[TLS_ECDH_RSA_WITH_AES_128_CBC_SHA].new_digest = new_sha1_digest;
    suites[TLS_ECDH_RSA_WITH_AES_128_CBC_SHA].aead_encrypt = NULL;
    suites[TLS_ECDH_RSA_WITH_AES_128_CBC_SHA].aead_decrypt = NULL;

    suites[TLS_ECDH_RSA_WITH_AES_256_CBC_SHA].id = TLS_ECDH_RSA_WITH_AES_256_CBC_SHA;
    suites[TLS_ECDH_RSA_WITH_AES_256_CBC_SHA].min_version = 3;
    suites[TLS_ECDH_RSA_WITH_AES_256_CBC_SHA].block_size = 16;
    suites[TLS_ECDH_RSA_WITH_AES_256_CBC_SHA].IV_size = 16;
    suites[TLS_ECDH_RSA_WITH_AES_256_CBC_SHA].key_size = 32;
    suites[TLS_ECDH_RSA_WITH_AES_256_CBC_SHA].hash_size = SHA1_BYTE_SIZE;
    suites[TLS_ECDH_RSA_WITH_AES_256_CBC_SHA].bulk_encrypt = (encrypt_func)aes_256_encrypt;
    suites[TLS_ECDH_RSA_WITH_AES_256_CBC_SHA].bulk_decrypt = (decrypt_func)aes_256_decrypt;
    suites[TLS_ECDH_RSA_WITH_AES_256_CBC_SHA].new_digest = new_sha1_digest;
    suites[TLS_ECDH_RSA_WITH_AES_256_CBC_SHA].aead_encrypt = NULL;
    suites[TLS_ECDH_RSA_WITH_AES_256_CBC_SHA].aead_decrypt = NULL;

    suites[TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA].id = TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA;
    suites[TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA].min_version = 3;
    suites[TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA].block_size = 16;
    suites[TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA].IV_size = 16;
    suites[TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA].key_size = 16;
    suites[TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA].hash_size = SHA1_BYTE_SIZE;
    suites[TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA].bulk_encrypt = (encrypt_func)aes_128_encrypt;
    suites[TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA].bulk_decrypt = (decrypt_func)aes_128_decrypt;
    suites[TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA].new_digest = new_sha1_digest;
    suites[TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA].aead_encrypt = NULL;
    suites[TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA].aead_decrypt = NULL;

    suites[TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA].id = TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA;
    suites[TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA].min_version = 3;
    suites[TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA].block_size = 16;
    suites[TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA].IV_size = 16;
    suites[TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA].key_size = 32;
    suites[TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA].hash_size = SHA1_BYTE_SIZE;
    suites[TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA].bulk_encrypt = (encrypt_func)aes_256_encrypt;
    suites[TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA].bulk_decrypt = (decrypt_func)aes_256_decrypt;
    suites[TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA].new_digest = new_sha1_digest;
    suites[TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA].aead_encrypt = NULL;
    suites[TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA].aead_decrypt = NULL;

    suites[TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA].id = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA;
    suites[TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA].min_version = 3;
    suites[TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA].block_size = 16;
    suites[TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA].IV_size = 16;
    suites[TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA].key_size = 16;
    suites[TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA].hash_size = SHA1_BYTE_SIZE;
    suites[TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA].bulk_encrypt = (encrypt_func)aes_128_encrypt;
    suites[TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA].bulk_decrypt = (decrypt_func)aes_128_decrypt;
    suites[TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA].new_digest = new_sha1_digest;
    suites[TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA].aead_encrypt = NULL;
    suites[TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA].aead_decrypt = NULL;

    suites[TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA].id = TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA;
    suites[TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA].min_version = 3;
    suites[TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA].block_size = 16;
    suites[TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA].IV_size = 16;
    suites[TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA].key_size = 32;
    suites[TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA].hash_size = SHA1_BYTE_SIZE;
    suites[TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA].bulk_encrypt = (encrypt_func)aes_256_encrypt;
    suites[TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA].bulk_decrypt = (decrypt_func)aes_256_decrypt;
    suites[TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA].new_digest = new_sha1_digest;
    suites[TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA].aead_encrypt = NULL;
    suites[TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA].aead_decrypt = NULL;

    suites[TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384].id = TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384;
    suites[TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384].min_version = 3;
    suites[TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384].block_size = 16;
    suites[TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384].IV_size = 16;
    suites[TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384].key_size = 32;
    suites[TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384].hash_size = SHA384_BYTE_SIZE;
    suites[TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384].bulk_encrypt = (encrypt_func)aes_256_encrypt;
    suites[TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384].bulk_decrypt = (decrypt_func)aes_256_decrypt;
    suites[TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384].new_digest = new_sha384_digest;
    suites[TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384].aead_encrypt = NULL;
    suites[TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384].aead_decrypt = NULL;

    suites[TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA].id = TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA;
    suites[TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA].min_version = 3;
    suites[TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA].block_size = 16;
    suites[TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA].IV_size = 16;
    suites[TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA].key_size = 16;
    suites[TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA].hash_size = SHA1_BYTE_SIZE;
    suites[TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA].bulk_encrypt = (encrypt_func)aes_128_encrypt;
    suites[TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA].bulk_decrypt = (decrypt_func)aes_128_decrypt;
    suites[TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA].new_digest = new_sha1_digest;
    suites[TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA].aead_encrypt = NULL;
    suites[TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA].aead_decrypt = NULL;

    suites[TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA].id = TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA;
    suites[TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA].min_version = 3;
    suites[TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA].block_size = 16;
    suites[TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA].IV_size = 16;
    suites[TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA].key_size = 32;
    suites[TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA].hash_size = SHA1_BYTE_SIZE;
    suites[TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA].bulk_encrypt = (encrypt_func)aes_256_encrypt;
    suites[TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA].bulk_decrypt = (decrypt_func)aes_256_decrypt;
    suites[TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA].new_digest = new_sha1_digest;
    suites[TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA].aead_encrypt = NULL;
    suites[TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA].aead_decrypt = NULL;
}

void init_protection_parameters(ProtectionParameters* parameters) {
    parameters->MAC_secret = NULL;
    parameters->key = NULL;
    parameters->IV = NULL;
    parameters->seq_num = 0;
    parameters->key_done = 0;
    parameters->suite = TLS_NULL_WITH_NULL_NULL;
    parameters->tls3_keys.handshake_key = NULL;
    parameters->tls3_keys.handshake_iv = NULL;
    parameters->tls3_keys.finished_key = NULL;
    parameters->tls3_keys.application_key = NULL;
    parameters->tls3_keys.application_iv = NULL;
}

void init_parameters(TLSParameters* parameters) {
    init_protection_parameters(&parameters->send_parameters);
    init_protection_parameters(&parameters->recv_parameters);
    init_dh_tmp_key();
    init_dh_key();
    init_rsa_key();
    init_rsa_export_key();
    // init_dsa_key();
    init_ecc_key();
    init_ecc_x25519_key();
    init_ecdsa_key();
    init_ciphers();

    memset(parameters->master_secret, '\0', MASTER_SECRET_LENGTH);
    memset(parameters->client_random, '\0', RANDOM_LENGTH);
    memset(parameters->server_random, '\0', RANDOM_LENGTH);
    huge_set(&parameters->key_share, 0);

    parameters->got_client_hello = 0;
    parameters->server_hello_done = 0;
    parameters->peer_finished = 0;
    parameters->peer_ping = 0;

    parameters->session_ticket = NULL;
    parameters->session_ticket_length = 0;

    parameters->session_id = NULL;
    parameters->session_id_length = 0;

    parameters->unread_buffer = NULL;
    parameters->unread_length = 0;

    parameters->handshake_secret = NULL;
}

unsigned char* append_buffer(unsigned char* dest, unsigned char* src, size_t n) {
    memcpy(dest, src, n);
    return dest + n;
}

unsigned char* read_buffer(unsigned char* dest, unsigned char* src, size_t n) {
    memcpy(dest, src, n);
    return src + n;
}

unsigned char* create_session_id() {
    int num = htonl(next_session_id++);
    unsigned char* session_id = (unsigned char*)malloc(32);
    memset(session_id, 0, 32);
    memcpy(session_id, &num, sizeof(int));

    return session_id;
}

void remember_session(TLSParameters* parameters) {
    unsigned char* session_id;
    unsigned char* master_secret = (unsigned char*)malloc(MASTER_SECRET_LENGTH);
    memcpy(master_secret, parameters->master_secret, MASTER_SECRET_LENGTH);

    session_id = (unsigned char*)malloc(parameters->session_id_length);
    memcpy(session_id, parameters->session_id, parameters->session_id_length);

    if (session_count >= sizeof(stored_sessions)) {
        for (int i = 0, size = sizeof(stored_sessions); i < size; i++) {
            free(stored_sessions[session_count].master_secret);
            free(stored_sessions[session_count].session_id);
        }
        session_count = 0;
    }
    stored_sessions[session_count].master_secret = master_secret;
    stored_sessions[session_count].session_id = session_id;
    session_count++;
}

void find_stored_session(TLSParameters* parameters) {
    if (parameters->session_id_length) {
        int finded = 0;
        for (int i = 0; i < session_count; i++) {
            if (!memcmp(stored_sessions[i].session_id, parameters->session_id, parameters->session_id_length)) {
                memcpy(parameters->master_secret, stored_sessions[i].master_secret, MASTER_SECRET_LENGTH);
                finded = 1;
                break;
            }
        }
        if (!finded) {
            parameters->session_id_length = 0;
            free(parameters->session_id);
        }
    }
}

void compute_handshake_hash(TLSParameters* parameters, unsigned char* handshake_hash) {
    digest_ctx tmp_md5_handshake_digest;
    digest_ctx tmp_sha1_handshake_digest;
    digest_ctx tmp_sha256_handshake_digest;
    digest_ctx tmp_sha384_handshake_digest;
    CipherSuite* send_suite = &(suites[parameters->send_parameters.suite]);

    if (TLS_VERSION_MINOR >= 3) {
        if (send_suite->new_digest == new_sha384_digest) {
            copy_digest(&tmp_sha384_handshake_digest, &parameters->sha384_handshake_digest);
            finalize_digest(&tmp_sha384_handshake_digest);

            memcpy(handshake_hash, tmp_sha384_handshake_digest.hash, SHA384_BYTE_SIZE);
            free(tmp_sha384_handshake_digest.hash);
        } else {
            copy_digest(&tmp_sha256_handshake_digest, &parameters->sha256_handshake_digest);
            finalize_digest(&tmp_sha256_handshake_digest);

            memcpy(handshake_hash, tmp_sha256_handshake_digest.hash, SHA256_BYTE_SIZE);
            free(tmp_sha256_handshake_digest.hash);
        }
    } else {
        // "cheating".  Copy the handshake digests into local memory (and change
        // the hash pointer) so that we can finalize twice (
        copy_digest(&tmp_md5_handshake_digest, &parameters->md5_handshake_digest);
        copy_digest(&tmp_sha1_handshake_digest, &parameters->sha1_handshake_digest);

        finalize_digest(&tmp_md5_handshake_digest);
        finalize_digest(&tmp_sha1_handshake_digest);

        memcpy(handshake_hash, tmp_md5_handshake_digest.hash, MD5_BYTE_SIZE);
        memcpy(handshake_hash + MD5_BYTE_SIZE, tmp_sha1_handshake_digest.hash, SHA1_BYTE_SIZE);

        free(tmp_md5_handshake_digest.hash);
        free(tmp_sha1_handshake_digest.hash);
    }
}

void calculate_handshake_keys(TLSParameters* parameters) {
    CipherSuite* send_suite = &(suites[parameters->send_parameters.suite]);
    digest_ctx ctx;
    send_suite->new_digest(&ctx);
    unsigned char* handshake_hash = (unsigned char*)malloc(ctx.result_size);

    unsigned char* shared_secret;
    unsigned char zero_key[ctx.result_size];
    unsigned char early_secret[ctx.result_size];
    unsigned char derived_secret[ctx.result_size];
    unsigned char handshake_secret[ctx.result_size];
    unsigned char handshake_traffic_secret[ctx.result_size];
    unsigned char* handshake_key = (unsigned char*)malloc(send_suite->key_size);
    unsigned char* handshake_iv = (unsigned char*)malloc(send_suite->IV_size);
    unsigned char* finished_key = (unsigned char*)malloc(send_suite->hash_size);
    unsigned char traffic_label[12];
    int share_secret_len = huge_bytes(&parameters->key_share);

    huge_unload(&parameters->key_share, shared_secret, share_secret_len);
    compute_handshake_hash(parameters, handshake_hash);
    memset(zero_key, 0, ctx.result_size);

    HKDF_extract(NULL, 0, zero_key, ctx.result_size, early_secret, ctx);
    derive_secret(early_secret, ctx.result_size, (unsigned char*)"derived", 7, NULL, 0, derived_secret, ctx.result_size, ctx);
    HKDF_extract(derived_secret, ctx.result_size, shared_secret, share_secret_len, handshake_secret, ctx);
    parameters->handshake_secret = (unsigned char*)malloc(ctx.result_size);
    memcpy(parameters->handshake_secret, handshake_secret, ctx.result_size);

    if (connection_end_client == parameters->connection_end) {
        memcpy(traffic_label, (void*)"c hs traffic", 12);
    } else {
        memcpy(traffic_label, (void*)"s hs traffic", 12);
    }

    HKDF_expand_label(handshake_secret, ctx.result_size, traffic_label, 12, handshake_hash, ctx.result_size, handshake_traffic_secret, ctx.result_size, ctx);
    HKDF_expand_label(handshake_traffic_secret, ctx.result_size, (unsigned char*)"key", 3, NULL, 0, handshake_key, send_suite->key_size, ctx);
    HKDF_expand_label(handshake_traffic_secret, ctx.result_size, (unsigned char*)"iv", 2, NULL, 0, handshake_iv, send_suite->IV_size, ctx);
    HKDF_expand_label(handshake_traffic_secret, ctx.result_size, (unsigned char*)"finished", 8, NULL, 0, finished_key, ctx.result_size, ctx);
    parameters->send_parameters.tls3_keys.handshake_key = handshake_key;
    parameters->send_parameters.tls3_keys.handshake_iv = handshake_iv;
    parameters->send_parameters.tls3_keys.finished_key = finished_key;

    // printf("handshake_key:");
    // show_hex(parameters->send_parameters.tls3_keys.handshake_key, send_suite->key_size, 1);
    // printf("handshake_iv:");
    // show_hex(parameters->send_parameters.tls3_keys.handshake_iv, send_suite->IV_size, 1);
    // printf("finished_key:");
    // show_hex(parameters->send_parameters.tls3_keys.finished_key, ctx.result_size, 1);

    if (connection_end_client == parameters->connection_end) {
        memcpy(traffic_label, (void*)"s hs traffic", 12);
    } else {
        memcpy(traffic_label, (void*)"c hs traffic", 12);
    }

    handshake_key = (unsigned char*)malloc(send_suite->key_size);
    handshake_iv = (unsigned char*)malloc(send_suite->IV_size);
    finished_key = (unsigned char*)malloc(send_suite->hash_size);

    HKDF_expand_label(handshake_secret, ctx.result_size, traffic_label, 12, handshake_hash, ctx.result_size, handshake_traffic_secret, ctx.result_size, ctx);
    HKDF_expand_label(handshake_traffic_secret, ctx.result_size, (unsigned char*)"key", 3, NULL, 0, handshake_key, send_suite->key_size, ctx);
    HKDF_expand_label(handshake_traffic_secret, ctx.result_size, (unsigned char*)"iv", 2, NULL, 0, handshake_iv, send_suite->IV_size, ctx);
    HKDF_expand_label(handshake_traffic_secret, ctx.result_size, (unsigned char*)"finished", 8, NULL, 0, finished_key, ctx.result_size, ctx);
    parameters->recv_parameters.tls3_keys.handshake_key = handshake_key;
    parameters->recv_parameters.tls3_keys.handshake_iv = handshake_iv;
    parameters->recv_parameters.tls3_keys.finished_key = finished_key;

    // printf("handshake_key:");
    // show_hex(parameters->recv_parameters.tls3_keys.handshake_key, send_suite->key_size, 1);
    // printf("handshake_iv:");
    // show_hex(parameters->recv_parameters.tls3_keys.handshake_iv, send_suite->IV_size, 1);
    // printf("finished_key:");
    // show_hex(parameters->recv_parameters.tls3_keys.finished_key, ctx.result_size, 1);
}

void calculate_application_keys(TLSParameters* parameters) {
    CipherSuite* send_suite = &(suites[parameters->send_parameters.suite]);
    digest_ctx ctx;
    send_suite->new_digest(&ctx);
    unsigned char handshake_hash[ctx.result_size];

    unsigned char zero_key[ctx.result_size];
    unsigned char master_secret[ctx.result_size];
    unsigned char derived_secret[ctx.result_size];
    unsigned char application_traffic_secret[ctx.result_size];
    unsigned char* application_key = (unsigned char*)malloc(send_suite->key_size);
    unsigned char* application_iv = (unsigned char*)malloc(send_suite->IV_size);
    unsigned char traffic_label[12];

    compute_handshake_hash(parameters, handshake_hash);
    memset(zero_key, 0, ctx.result_size);

    derive_secret(parameters->handshake_secret, ctx.result_size, (unsigned char*)"derived", 7, NULL, 0, derived_secret, ctx.result_size, ctx);
    HKDF_extract(derived_secret, ctx.result_size, zero_key, ctx.result_size, master_secret, ctx);

    if (connection_end_client == parameters->connection_end) {
        memcpy(traffic_label, (void*)"c ap traffic", 12);
    } else {
        memcpy(traffic_label, (void*)"s ap traffic", 12);
    }

    HKDF_expand_label(master_secret, ctx.result_size, traffic_label, 12, handshake_hash, ctx.result_size, application_traffic_secret, ctx.result_size, ctx);
    HKDF_expand_label(application_traffic_secret, ctx.result_size, (unsigned char*)"key", 3, NULL, 0, application_key, send_suite->key_size, ctx);
    HKDF_expand_label(application_traffic_secret, ctx.result_size, (unsigned char*)"iv", 2, NULL, 0, application_iv, send_suite->IV_size, ctx);
    parameters->send_parameters.tls3_keys.application_key = application_key;
    parameters->send_parameters.tls3_keys.application_iv = application_iv;

    if (connection_end_client == parameters->connection_end) {
        memcpy(traffic_label, (void*)"s ap traffic", 12);
    } else {
        memcpy(traffic_label, (void*)"c ap traffic", 12);
    }

    application_key = (unsigned char*)malloc(send_suite->key_size);
    application_iv = (unsigned char*)malloc(send_suite->IV_size);

    HKDF_expand_label(master_secret, ctx.result_size, traffic_label, 12, handshake_hash, ctx.result_size, application_traffic_secret, ctx.result_size, ctx);
    HKDF_expand_label(application_traffic_secret, ctx.result_size, (unsigned char*)"key", 3, NULL, 0, application_key, send_suite->key_size, ctx);
    HKDF_expand_label(application_traffic_secret, ctx.result_size, (unsigned char*)"iv", 2, NULL, 0, application_iv, send_suite->IV_size, ctx);
    parameters->recv_parameters.tls3_keys.application_key = application_key;
    parameters->recv_parameters.tls3_keys.application_iv = application_iv;
}

void compute_tls3_verify_data(unsigned char* finished_key, unsigned char* verify_data, TLSParameters* parameters) {
    CipherSuite* send_suite = &(suites[parameters->send_parameters.suite]);
    digest_ctx ctx;
    send_suite->new_digest(&ctx);
    unsigned char handshake_hash[ctx.result_size];

    compute_handshake_hash(parameters, handshake_hash);
    hmac(&ctx, finished_key, ctx.result_size, handshake_hash, ctx.result_size);
    memcpy(verify_data, ctx.hash, ctx.result_size);
}

void tls_prf(
    TLSParameters* parameters,
    unsigned char* secret,
    int secret_len,
    unsigned char* label,
    int label_len,
    unsigned char* seed,
    int seed_len,
    unsigned char* output,
    int out_len
) {
    CipherSuite* send_suite = &(suites[parameters->send_parameters.suite]);

    if (TLS_VERSION_MINOR >= 3) {
        if (send_suite->new_digest == new_sha384_digest) {
            PRF_WITH_DIGEST(secret, secret_len, label, label_len, seed, seed_len, output, out_len, new_sha384_digest);
        } else {
            PRF_WITH_DIGEST(secret, secret_len, label, label_len, seed, seed_len, output, out_len, new_sha256_digest);
        }
    } else {
        PRF(secret, secret_len, label, label_len, seed, seed_len, output, out_len);
    }
}

/**
 * 7.4.9:
 * verify_data = PRF( master_secret, "client finished", MD5(handshake_messages) +
 *  SHA-1(handshake_messages)) [0..11]
 *
 * master_secret = PRF( pre_master_secret, "master secret", ClientHello.random +
 *  ServerHello.random );
 * always 48 bytes in length.
 */
void compute_verify_data(
    unsigned char* finished_label,
    TLSParameters* parameters,
    unsigned char* verify_data
) {
    CipherSuite* send_suite = &(suites[parameters->send_parameters.suite]);
    int hash_bytes = TLS_VERSION_MINOR >= 3 ? (send_suite->new_digest == new_sha384_digest ? SHA384_BYTE_SIZE : SHA256_BYTE_SIZE) : MD5_BYTE_SIZE + SHA1_BYTE_SIZE;
    unsigned char handshake_hash[hash_bytes];

    compute_handshake_hash(parameters, handshake_hash);
    tls_prf(
        parameters,
        parameters->master_secret, MASTER_SECRET_LENGTH,
        finished_label, strlen((char*)finished_label),
        handshake_hash, hash_bytes,
        verify_data, VERIFY_DATA_LEN
    );
}

/**
 * Turn the premaster secret into an actual master secret (the
 * server side will do this concurrently) as specified in section 8.1:
 * master_secret = PRF( pre_master_secret, "master secret",
 * ClientHello.random + ServerHello.random );
 * ( premaster_secret, parameters );
 * Note that, with DH, the master secret len is determined by the generator (p)
 * value.
 */
void compute_master_secret(
    unsigned char* premaster_secret,
    int premaster_secret_len,
    TLSParameters* parameters
) {
    unsigned char label[] = "master secret";

    tls_prf(
        parameters,
        premaster_secret,
        premaster_secret_len,
        label, strlen((char*)label),
        // Note - cheating, since client_random & server_random are defined
        // sequentially in the structure
        parameters->client_random, RANDOM_LENGTH * 2,
        parameters->master_secret, MASTER_SECRET_LENGTH
    );

    printf("master_secret:");
    show_hex(parameters->master_secret, 48, 1);
}

/**
6.3:Compute a key block, including MAC secrets, keys, and IVs for client & server
Notice that the seed is server random followed by client random (whereas for master
secret computation, it's client random followed by server random).  Sheesh!
*/
void calculate_keys(TLSParameters* parameters) {
    // XXX assuming send suite & recv suite will always be the same
    CipherSuite* suite = &(suites[parameters->send_parameters.suite]);
    unsigned char label[] = "key expansion";
    int key_block_length = suite->hash_size * 2 + suite->key_size * 2 + suite->IV_size * 2;
    int iv_fixed_len = suite->aead_encrypt ? 4 : suite->IV_size;
    unsigned char seed[RANDOM_LENGTH * 2];
    unsigned char* key_block = (unsigned char*)malloc(key_block_length);
    unsigned char* key_block_ptr;

    ProtectionParameters* send_parameters = &parameters->send_parameters;
    ProtectionParameters* recv_parameters = &parameters->recv_parameters;

    memcpy(seed, parameters->server_random, RANDOM_LENGTH);
    memcpy(seed + RANDOM_LENGTH, parameters->client_random, RANDOM_LENGTH);

    tls_prf(parameters, parameters->master_secret, MASTER_SECRET_LENGTH, label, strlen((const char*)label), seed, RANDOM_LENGTH * 2, key_block, key_block_length);
    send_parameters->MAC_secret = (unsigned char*)malloc(suite->hash_size);
    recv_parameters->MAC_secret = (unsigned char*)malloc(suite->hash_size);
    send_parameters->key = (unsigned char*)malloc(suite->key_size);
    recv_parameters->key = (unsigned char*)malloc(suite->key_size);
    send_parameters->IV = (unsigned char*)malloc(suite->IV_size);
    recv_parameters->IV = (unsigned char*)malloc(suite->IV_size);

    if (parameters->connection_end == connection_end_client) {
        key_block_ptr = read_buffer(send_parameters->MAC_secret, key_block, suite->hash_size);
        key_block_ptr = read_buffer(recv_parameters->MAC_secret, key_block_ptr, suite->hash_size);
        key_block_ptr = read_buffer(send_parameters->key, key_block_ptr, suite->key_size);
        key_block_ptr = read_buffer(recv_parameters->key, key_block_ptr, suite->key_size);
        key_block_ptr = read_buffer(send_parameters->IV, key_block_ptr, iv_fixed_len);
        key_block_ptr = read_buffer(recv_parameters->IV, key_block_ptr, iv_fixed_len);
    } else  // I'm the server
    {
        key_block_ptr = read_buffer(recv_parameters->MAC_secret, key_block, suite->hash_size);
        key_block_ptr = read_buffer(send_parameters->MAC_secret, key_block_ptr, suite->hash_size);
        key_block_ptr = read_buffer(recv_parameters->key, key_block_ptr, suite->key_size);
        key_block_ptr = read_buffer(send_parameters->key, key_block_ptr, suite->key_size);
        key_block_ptr = read_buffer(recv_parameters->IV, key_block_ptr, iv_fixed_len);
        key_block_ptr = read_buffer(send_parameters->IV, key_block_ptr, iv_fixed_len);
    }

    switch (suite->id) {
    case TLS_RSA_EXPORT_WITH_RC4_40_MD5:
    case TLS_RSA_WITH_RC4_128_MD5:
    case TLS_RSA_WITH_RC4_128_SHA:
    case TLS_DH_anon_EXPORT_WITH_RC4_40_MD5:
    case TLS_DH_anon_WITH_RC4_128_MD5:
    {
        rc4_state* read_state = malloc(sizeof(rc4_state));
        rc4_state* write_state = malloc(sizeof(rc4_state));
        read_state->i = read_state->j = write_state->i = write_state->j = 0;
        send_parameters->IV = (unsigned char*)read_state;
        recv_parameters->IV = (unsigned char*)write_state;
        memset(read_state->S, '\0', RC4_STATE_ARRAY_LEN);
        memset(write_state->S, '\0', RC4_STATE_ARRAY_LEN);
    }
    break;
    default:
        break;
    }

    free(key_block);
}

int send_tls2_message(
    int connection,
    int content_type,
    unsigned char* content,
    short content_len,
    ProtectionParameters* parameters
) {
    TLSPlaintext header;
    unsigned char* send_buffer;
    int send_buffer_size;
    int padding_length = 0;
    unsigned char* mac = NULL;
    unsigned char mac_header[13];
    int cbc_attack_mode = 0;
    int nonce_size = 0;
    digest_ctx digest;
    CipherSuite* active_suite;
    active_suite = &suites[parameters->suite];

    header.type = content_type;
    header.version.major = TLS_VERSION_MAJOR;
    header.version.minor = TLS_VERSION_MINOR > 3 ? 3 : TLS_VERSION_MINOR;
    header.length = htons(content_len);

    if (parameters->key_done != 1) {
        send_buffer_size = content_len + 5;
        send_buffer = (unsigned char*)malloc(content_len + 5);
        send_buffer[0] = header.type;
        send_buffer[1] = header.version.major;
        send_buffer[2] = header.version.minor;
        memcpy(send_buffer + 3, &header.length, sizeof(short));
        memcpy(send_buffer + 5, content, content_len);

        if (send(connection, (void*)send_buffer, send_buffer_size, 0) < send_buffer_size) {
            return -1;
        }

        printf("send:%d", send_buffer_size);
        printf(",msg_type:%d", content_type);
        if (content_type == content_handshake) {
            printf(",handshake_type:%d", content[0]);
        }
        printf("\n");

        return 0;
    }

    if (TLS_VERSION_MINOR >= 2 && (active_suite->bulk_encrypt || active_suite->aead_encrypt)) {
        cbc_attack_mode = 1;
    }

    if (active_suite->new_digest) {
        int sequence_num;

        nonce_size = active_suite->IV_size - (active_suite->aead_encrypt ? 4 : 0);
        memset(mac_header, '\0', 8);
        sequence_num = htonl(parameters->seq_num);
        memcpy(mac_header + 4, &sequence_num, sizeof(int));

        header.type = content_type;
        header.version.major = TLS_VERSION_MAJOR;
        header.version.minor = TLS_VERSION_MINOR > 3 ? 3 : TLS_VERSION_MINOR;
        header.length = htons(content_len);
        mac_header[8] = header.type;
        mac_header[9] = header.version.major;
        mac_header[10] = header.version.minor;
        memcpy(mac_header + 11, &header.length, sizeof(short));
    }

    if (active_suite->new_digest && active_suite->hash_size) {
        // Allocate enough space for the 8-byte sequence number, the 5-byte pseudo header, and the content.
        unsigned char* mac_buffer = malloc(13 + content_len);
        memcpy(mac_buffer, mac_header, 13);

        mac = (unsigned char*)malloc(active_suite->hash_size);
        active_suite->new_digest(&digest);

        memcpy(mac_buffer + 13, content, content_len);
        hmac(&digest, parameters->MAC_secret, active_suite->hash_size, mac_buffer, 13 + content_len);
        memcpy(mac, digest.hash, active_suite->hash_size);

        free(mac_buffer);
    }

    if (active_suite->aead_encrypt) {
        send_buffer_size = content_len + active_suite->block_size;
    } else {
        send_buffer_size = content_len + active_suite->hash_size;
        if (active_suite->block_size) {
            padding_length = active_suite->block_size - (send_buffer_size % active_suite->block_size);
            send_buffer_size += padding_length;
        }
    }

    // Add space for the header, but only after computing padding
    send_buffer_size += 5;
    send_buffer_size += cbc_attack_mode ? nonce_size : 0;
    send_buffer = (unsigned char*)malloc(send_buffer_size);

    if (mac) {
        memcpy(send_buffer + send_buffer_size - (active_suite->hash_size + padding_length), mac, active_suite->hash_size);
        free(mac);
    }

    if (padding_length > 0) {
        unsigned char* padding;
        for (padding = send_buffer + send_buffer_size - 1; padding >= send_buffer + send_buffer_size - padding_length; padding--) {
            *padding = (padding_length - 1);
        }
    }

    header.length = htons(send_buffer_size - 5);
    send_buffer[0] = header.type;
    send_buffer[1] = header.version.major;
    send_buffer[2] = header.version.minor;
    memcpy(send_buffer + 3, &header.length, sizeof(short));

    if (cbc_attack_mode) {
        memset(send_buffer + 5, 0, nonce_size); //第一个随机明文分组
        memcpy(send_buffer + 5 + nonce_size, content, content_len);
    } else {
        memcpy(send_buffer + 5, content, content_len);
    }

    if (active_suite->bulk_encrypt || active_suite->aead_encrypt) {
        unsigned char* encrypted_buffer = (unsigned char*)malloc(send_buffer_size);
        int un_enc_size = 5;
        memcpy(encrypted_buffer, send_buffer, 5);

        /*
        tls1.1-1.1:
        The implicit Initialization Vector (IV) is replaced with an explicit IV to protect against CBC attacks
        对于tls1.1以上的版本，CBC模式下第一个分组可以加密也可以不加密，不加密时其存储的是IV向量，直接明文传输
        */
        if (TLS_VERSION_MINOR >= 2) { //不加密第一个数据分组，用来传输IV向量，供对方解密使用
            if (active_suite->bulk_encrypt) {
                memset(parameters->IV, 0, nonce_size); // 生成随机数，用于IV向量
                memcpy(encrypted_buffer + un_enc_size, parameters->IV, nonce_size);
                un_enc_size += nonce_size;
            } else {
                memset(parameters->IV + 4, 0, nonce_size); // 生成随机数，用于IV向量
                memcpy(encrypted_buffer + un_enc_size, parameters->IV + 4, nonce_size);
                un_enc_size += nonce_size;
            }
        }
        if (active_suite->bulk_encrypt) {
            active_suite->bulk_encrypt(
                send_buffer + un_enc_size,
                send_buffer_size - un_enc_size,
                encrypted_buffer + un_enc_size,
                parameters->IV,
                parameters->key
            );
        } else {
            active_suite->aead_encrypt(
                send_buffer + un_enc_size,
                send_buffer_size - un_enc_size - active_suite->block_size,
                encrypted_buffer + un_enc_size,
                parameters->IV,
                mac_header, 13,
                parameters->key
            );
        }
        free(send_buffer);
        send_buffer = encrypted_buffer;
    }

    if (send(connection, (void*)send_buffer, send_buffer_size, 0) < send_buffer_size) {
        return -1;
    }

    printf("send:%d", send_buffer_size);
    printf(",msg_type:%d", content_type);
    if (content_type == content_handshake) {
        printf(",handshake_type:%d", content[0]);
    }
    printf("\n");
    // show_hex(send_buffer, send_buffer_size, 1);

    parameters->seq_num++;

    free(send_buffer);

    return 0;
}

void build_iv(unsigned char* iv, uint64_t seq) {
    size_t i;
    for (i = 0; i < 8; i++) {
        iv[12 - 1 - i] ^= ((seq >> (i * 8)) & 0xFF);
    }
}

int send_tls3_message(
    int connection,
    int content_type,
    unsigned char* content,
    short content_len,
    ProtectionParameters* parameters
) {
    TLSPlaintext header;
    unsigned char* send_buffer;
    int send_buffer_size;
    digest_ctx digest;
    CipherSuite* active_suite;
    active_suite = &suites[parameters->suite];

    header.type = content_type;
    header.version.major = TLS_VERSION_MAJOR;
    header.version.minor = TLS_VERSION_MINOR > 3 ? 3 : TLS_VERSION_MINOR;
    header.length = htons(content_len);

    if (parameters->key_done != 1) {
        send_buffer_size = content_len + 5;
        send_buffer = (unsigned char*)malloc(content_len + 5);
        send_buffer[0] = header.type;
        send_buffer[1] = header.version.major;
        send_buffer[2] = header.version.minor;
        memcpy(send_buffer + 3, &header.length, sizeof(short));
        memcpy(send_buffer + 5, content, content_len);

        if (send(connection, (void*)send_buffer, send_buffer_size, 0) < send_buffer_size) {
            return -1;
        }

        printf("send:%d", send_buffer_size);
        printf(",msg_type:%d", content_type);
        if (content_type == content_handshake) {
            printf(",handshake_type:%d", content[0]);
        }
        printf("\n");

        return 0;
    }

    unsigned char* tmp = (unsigned char*)malloc(content_len + 1);
    memcpy(tmp, content, content_len);
    tmp[content_len] = parameters->tls3_keys.application_key ? 0x17 : 0x16; //tls3中，最后一个字节代表了真实record type
    content = tmp;
    content_len += 1;
    header.type = content_application_data;

    unsigned char* application_iv = parameters->tls3_keys.application_iv ? parameters->tls3_keys.application_iv : parameters->tls3_keys.handshake_iv;
    unsigned char* key = parameters->tls3_keys.application_key ? parameters->tls3_keys.application_key : parameters->tls3_keys.handshake_key;
    unsigned char iv[active_suite->IV_size];

    // printf("key:");
    // show_hex(key, active_suite->key_size, 1);
    // printf("iv:");
    // show_hex(application_iv, active_suite->IV_size, 1);

    send_buffer_size = 5 + content_len + active_suite->block_size;
    send_buffer = (unsigned char*)malloc(send_buffer_size);
    header.length = htons(send_buffer_size - 5);
    send_buffer[0] = header.type;
    send_buffer[1] = header.version.major;
    send_buffer[2] = header.version.minor;
    memcpy(send_buffer + 3, &header.length, sizeof(short));
    memcpy(send_buffer + 5, content, content_len);

    memcpy(iv, application_iv, active_suite->IV_size);
    build_iv(iv, parameters->seq_num);

    unsigned char* encrypted_buffer = (unsigned char*)malloc(send_buffer_size);
    int un_enc_size = 5;
    memcpy(encrypted_buffer, send_buffer, 5);

    active_suite->aead_encrypt(
        send_buffer + 5,
        send_buffer_size - 5 - active_suite->block_size,
        encrypted_buffer + 5,
        iv,
        send_buffer, 5,
        key
    );
    free(send_buffer);
    send_buffer = encrypted_buffer;

    if (send(connection, (void*)send_buffer, send_buffer_size, 0) < send_buffer_size) {
        return -1;
    }

    // printf("plaintext:");
    // show_hex(content, content_len, 1);
    // printf("encrypt:");
    // show_hex(send_buffer, send_buffer_size, 1);
    // unsigned char* decrypted_message;
    // int decrypted_length = tls3_decrypt(send_buffer, send_buffer + 5, send_buffer_size - 5, &decrypted_message, parameters);
    // printf("decrypt:");
    // show_hex(decrypted_message, decrypted_length, 1);

    printf("send:%d", send_buffer_size);
    printf(",msg_type:%d", content_type);
    if (content_type == content_handshake) {
        printf(",handshake_type:%d", content[0]);
    }
    printf("\n");
    // show_hex(send_buffer, send_buffer_size, 1);

    parameters->seq_num++;

    free(send_buffer);

    return 0;
}

int send_message(
    int connection,
    int content_type,
    unsigned char* content,
    short content_len,
    ProtectionParameters* parameters
) {
    if (TLS_VERSION_MINOR <= 3) {
        return send_tls2_message(connection, content_type, content, content_len, parameters);
    } else {
        return send_tls3_message(connection, content_type, content, content_len, parameters);
    }
}

int send_alert_message(
    int connection,
    int alert_code,
    ProtectionParameters* parameters
) {
    unsigned char buffer[2];

    // TODO support warnings
    buffer[0] = fatal;
    buffer[1] = alert_code;

    return send_message(connection, content_alert, buffer, 2, parameters);
}

int send_handshake_message(
    int connection,
    int msg_type,
    unsigned char* message,
    int message_len,
    TLSParameters* parameters
) {
    Handshake      record;
    short          send_buffer_size;
    unsigned char* send_buffer;
    int            response;
    int            skip_encrypt;

    record.msg_type = msg_type;
    record.length = htons(message_len) << 8; // To deal with 24-bits...
    send_buffer_size = message_len + 4; // space for the handshake header

    send_buffer = (unsigned char*)malloc(send_buffer_size);
    send_buffer[0] = record.msg_type;
    memcpy(send_buffer + 1, &record.length, 3);
    memcpy(send_buffer + 4, message, message_len);

    if (TLS_VERSION_MINOR >= 3) {
        update_digest(&parameters->sha256_handshake_digest, send_buffer, send_buffer_size);
        update_digest(&parameters->sha384_handshake_digest, send_buffer, send_buffer_size);
    } else {
        update_digest(&parameters->md5_handshake_digest, send_buffer, send_buffer_size);
        update_digest(&parameters->sha1_handshake_digest, send_buffer, send_buffer_size);
    }

    response = send_message(connection, content_handshake, send_buffer, send_buffer_size, &parameters->send_parameters);

    free(send_buffer);

    return response;
}

unsigned char* set_renegotiat_extension(int* out_len) {
    unsigned char* buffer = NULL;
    *out_len = 0;

    if (TLS_VERSION_MINOR >= 3) {
        buffer = (unsigned char*)malloc(5);
        memcpy(buffer, RENEGOTIATE_INF_EXT, 2);
        buffer[2] = 0x00;
        buffer[3] = 0x01;
        *out_len = 5;
    }

    return buffer;
}

unsigned char* set_session_ticket_extension(unsigned char* session_ticket, int session_ticket_length, int* out_len) {
    unsigned char* buffer = NULL;
    unsigned short ext_item_len = htons(session_ticket_length);
    *out_len = 0;

    if (TLS_VERSION_MINOR >= 3) {
        buffer = (unsigned char*)malloc(4 + session_ticket_length);
        memcpy(buffer, SESSION_TICKET_EXT, 2);
        memcpy(buffer + 2, &ext_item_len, 2);
        if (session_ticket_length > 0) {
            memcpy(buffer + 4, session_ticket, session_ticket_length);
        }
        *out_len = 4 + session_ticket_length;
    }

    return buffer;
}

unsigned char* set_tls_version_extension(int* out_len) {
    unsigned char* buffer = NULL;
    *out_len = 0;

    if (TLS_VERSION_MINOR >= 4) {
        buffer = (unsigned char*)malloc(5);
        memcpy(buffer, SUPPORT_VERSION_EXT, 2);
        buffer[3] = 0x02;
        buffer[4] = 0x03;
        buffer[5] = 0x04;
        *out_len = 6;
    }

    return buffer;
}

unsigned char* set_key_share_extension(int* out_len, TLSParameters* parameters) {
    unsigned char* buffer = NULL;
    unsigned char* tmp_buf = NULL;
    unsigned short x_len = huge_bytes(&private_ecc_25519_key.Q.x);
    unsigned short y_len = 0;
    unsigned short q_len = x_len + y_len;
    unsigned short ext_item_len = 4 + q_len;
    unsigned short ext_item_len_n = htons(ext_item_len);
    huge pub;

    q_len = htons(q_len);
    *out_len = 0;

    if (TLS_VERSION_MINOR >= 4) {
        buffer = (unsigned char*)malloc(4 + ext_item_len);
        tmp_buf = buffer;
        memcpy(tmp_buf, KEY_SHARE_EXT, 2);
        tmp_buf += 2;
        memcpy(tmp_buf, &ext_item_len_n, 2);
        tmp_buf += 2;
        memcpy(tmp_buf, KEY_SHARE_GROUP_X25519, 2);
        tmp_buf += 2;
        memcpy(tmp_buf, &q_len, 2);
        tmp_buf += 2;
        huge_set(&pub, 0);
        huge_copy(&pub, &private_ecc_25519_key.Q.x);
        huge_reverse(&pub);
        huge_unload(&pub, tmp_buf, x_len);
        tmp_buf += x_len;
        *out_len = 4 + ext_item_len;
    }

    return buffer;
}

unsigned char* set_server_hello_extensions(int* length, TLSParameters* parameters) {
    unsigned char* buffer = NULL;
    unsigned char* ext_buffer = NULL;
    unsigned char* item_ext_buffer = NULL;
    int ext_len = 0;
    int item_ext_len = 0;
    *length = 0;

    if (TLS_VERSION_MINOR == 3) {
        item_ext_buffer = set_renegotiat_extension(&item_ext_len);
        if (item_ext_buffer) {
            ext_len += item_ext_len;
            ext_buffer = malloc(ext_len + 2);
            memcpy(ext_buffer + ext_len + 2 - item_ext_len, item_ext_buffer, item_ext_len);
        }
    }

#ifdef USE_SESSION_TICKET
    // 恢复会话时，server_hello消息不需要再发送session_ticket，只有第一次完整连接需要发送一个空的session_ticket，
    // 空的session_ticket是用来告诉客户端其后续将发送一个NewSessionTicket来支持session_ticket机制
    if (parameters->session_ticket_length == 0) {
        item_ext_buffer = set_session_ticket_extension(parameters->session_ticket, parameters->session_ticket_length, &item_ext_len);
        if (item_ext_buffer) {
            ext_len += item_ext_len;
            ext_buffer = realloc(ext_buffer, ext_len + 2);
            memcpy(ext_buffer + ext_len + 2 - item_ext_len, item_ext_buffer, item_ext_len);
        }
    }
#endif

    item_ext_buffer = set_tls_version_extension(&item_ext_len);
    if (item_ext_buffer) {
        ext_len += item_ext_len;
        ext_buffer = realloc(ext_buffer, ext_len + 2);
        memcpy(ext_buffer + ext_len + 2 - item_ext_len, item_ext_buffer, item_ext_len);
    }

    item_ext_buffer = set_key_share_extension(&item_ext_len, parameters);
    if (item_ext_buffer) {
        ext_len += item_ext_len;
        ext_buffer = realloc(ext_buffer, ext_len + 2);
        memcpy(ext_buffer + ext_len + 2 - item_ext_len, item_ext_buffer, item_ext_len);
    }

    if (ext_len) {
        *length = ext_len + 2;
        unsigned short len = htons(ext_len);
        memcpy(ext_buffer, &len, 2);
    }

    return ext_buffer;
}

/**
 * Build and submit a TLS client hello handshake on the active
 * connection.  It is up to the caller of this function to wait
 * for the server reply.
 */
int send_client_hello(int connection, TLSParameters* parameters) {
    ClientHello       package;
    unsigned short    supported_suites[1];
    unsigned char     supported_compression_methods[1];
    int               ext_len = 0;
    int               send_buffer_size;
    unsigned char* ext_buffer;
    unsigned char* send_buffer;
    void* write_buffer;
    time_t            local_time;
    int               status = 1;

    package.client_version.major = TLS_VERSION_MAJOR;
    package.client_version.minor = TLS_VERSION_MINOR > 3 ? 3 : TLS_VERSION_MINOR;
    time(&local_time);
    package.random.gmt_unix_time = htonl(local_time);
    // TODO - actually make this random.
    // This is 28 bytes, but client random is 32 - the first four bytes of
    // "client random" are the GMT unix time computed above.
    memcpy(parameters->client_random, &package.random.gmt_unix_time, 4);
    memcpy(package.random.random_bytes, parameters->client_random + 4, 28);
    package.session_id_length = 0;
    package.session_id = NULL;
    // note that this is bytes, not count.
    package.cipher_suites_length = htons(2);
    supported_suites[0] = htons(TLS_RSA_WITH_3DES_EDE_CBC_SHA);
    package.cipher_suites = supported_suites;
    package.compression_methods_length = 1;
    supported_compression_methods[0] = 0;
    package.compression_methods = supported_compression_methods;

    // Compute the size of the ClientHello message after flattening.
    send_buffer_size =
        sizeof(ProtocolVersion) +
        sizeof(Random) +
        sizeof(unsigned char) +
        (sizeof(unsigned char) * package.session_id_length) +
        sizeof(unsigned short) +
        (sizeof(unsigned short) * 1) +
        sizeof(unsigned char) +
        sizeof(unsigned char) +
        ext_len;

    write_buffer = send_buffer = (unsigned char*)malloc(send_buffer_size);

    write_buffer = append_buffer(write_buffer, (void*)&package.client_version.major, 1);
    write_buffer = append_buffer(write_buffer, (void*)&package.client_version.minor, 1);
    write_buffer = append_buffer(write_buffer, (void*)&package.random.gmt_unix_time, 4);
    write_buffer = append_buffer(write_buffer, (void*)&package.random.random_bytes, 28);
    write_buffer = append_buffer(write_buffer, (void*)&package.session_id_length, 1);

    if (package.session_id_length > 0) {
        write_buffer = append_buffer(write_buffer, (void*)package.session_id, package.session_id_length);
    }

    write_buffer = append_buffer(write_buffer, (void*)&package.cipher_suites_length, 2);
    write_buffer = append_buffer(write_buffer, (void*)package.cipher_suites, 2);
    write_buffer = append_buffer(write_buffer, (void*)&package.compression_methods_length, 1);

    if (package.compression_methods_length > 0) {
        write_buffer = append_buffer(write_buffer, (void*)package.compression_methods, 1);
    }

    if (ext_len > 0) {
        write_buffer = append_buffer(write_buffer, (void*)ext_buffer, ext_len);
    }

    assert(((unsigned char*)write_buffer - send_buffer) == send_buffer_size);

    status = send_handshake_message(connection, client_hello, send_buffer, send_buffer_size, parameters);

    free(send_buffer);

    return status;
}

unsigned char* parse_client_hello_extensions(
    unsigned char* read_pos,
    int pdu_length,
    TLSParameters* parameters
) {
    if (pdu_length <= 0) {
        return read_pos;
    }

    unsigned char* start_pos = read_pos;
    unsigned char ext_type[2];
    unsigned short ext_len = 0;
    unsigned short ext_item_len = 0;

    read_pos = read_buffer((void*)&ext_len, (void*)read_pos, 2);
    ext_len = ntohs(ext_len);

    while (ext_len > 0 && read_pos - start_pos < pdu_length) {
        read_pos = read_buffer((void*)ext_type, (void*)read_pos, 2);
        read_pos = read_buffer((void*)&ext_item_len, (void*)read_pos, 2);
        ext_item_len = ntohs(ext_item_len);

        if (!memcmp(ext_type, SESSION_TICKET_EXT, 2)) {
            if (ext_item_len > 12 + 16) {
                unsigned char decrypted[ext_item_len - 12 - 16];
                if (aes_128_gcm_decrypt(read_pos + 12, ext_item_len - 12, decrypted, read_pos, (unsigned char*)"session_ticket", 14, session_key) >= 0) {
                    parameters->session_ticket_length = ext_item_len;
                    parameters->session_ticket = (unsigned char*)malloc(ext_item_len);
                    memcpy(parameters->session_ticket, read_pos, ext_item_len);
                    memcpy(parameters->master_secret, decrypted, MASTER_SECRET_LENGTH);
                }
            }
        }

        if (!memcmp(ext_type, KEY_SHARE_EXT, 2)) {
            unsigned short len = 0;
            unsigned short key_len = 0;
            unsigned char group[2];
            elliptic_curve curve;
            huge pub;

            read_pos += 2;
            while (len < ext_item_len) {
                read_pos = read_buffer((void*)group, (void*)read_pos, 2);
                read_pos = read_buffer((void*)&key_len, (void*)read_pos, 2);
                key_len = ntohs(key_len);
                len += key_len + 4;
                if (!memcmp(group, KEY_SHARE_GROUP_X25519, 2)) {
                    get_named_curve("x25519", &curve);
                    huge_load(&pub, read_pos, key_len);
                    huge_reverse(&pub);
                    // printf("pub:");
                    // show_hex(pub.rep, pub.size, HUGE_WORD_BYTES);
                    multiply_25519(&pub, &private_ecc_25519_key.d, &private_ecc_25519_key.curve.p);
                    huge_reverse(&pub);
                    // printf("private_key:");
                    // show_hex(private_ecc_25519_key.d.rep, private_ecc_25519_key.d.size, HUGE_WORD_BYTES);
                    huge_set(&parameters->key_share, 0);
                    huge_copy(&parameters->key_share, &pub);
                    // printf("secret:");
                    // show_hex(parameters->key_share.rep, parameters->key_share.size, HUGE_WORD_BYTES);
                }
            }

        }
        read_pos += ext_item_len;
    }

    return read_pos;
}

unsigned char* parse_client_hello(
    unsigned char* read_pos,
    int pdu_length,
    TLSParameters* parameters
) {
    int i;
    ClientHello hello;
    unsigned char* start_pos = read_pos;

    read_pos = read_buffer((void*)&hello.client_version.major, (void*)read_pos, 1);
    read_pos = read_buffer((void*)&hello.client_version.minor, (void*)read_pos, 1);
    read_pos = read_buffer((void*)&hello.random.gmt_unix_time, (void*)read_pos, 4);
    // *DON'T* put this in host order, since it's not used as a time!  Just
    // accept it as is
    read_pos = read_buffer((void*)hello.random.random_bytes, (void*)read_pos, 28);
    read_pos = read_buffer((void*)&hello.session_id_length, (void*)read_pos, 1);

    hello.session_id = NULL;
    if (hello.session_id_length > 0) {
        hello.session_id = (unsigned char*)malloc(hello.session_id_length);
        read_pos = read_buffer((void*)hello.session_id, (void*)read_pos, hello.session_id_length);

#if TLS_VERSION_MINOR == 4
        parameters->session_id_length = hello.session_id_length;
        parameters->session_id = (unsigned char*)malloc(parameters->session_id_length);
        memcpy(parameters->session_id, hello.session_id, parameters->session_id_length);
#else
#ifdef USE_SESSION_TICKET
        // 对于session_ticket机制来说，需要原样返回客户端传过来的session_id
        parameters->session_id_length = hello.session_id_length;
        parameters->session_id = (unsigned char*)malloc(parameters->session_id_length);
        memcpy(parameters->session_id, hello.session_id, parameters->session_id_length);
#else 
#ifdef USE_SESSION_ID
        parameters->session_id_length = hello.session_id_length;
        parameters->session_id = (unsigned char*)malloc(parameters->session_id_length);
        memcpy(parameters->session_id, hello.session_id, parameters->session_id_length);
        find_stored_session(parameters);
#endif
#endif
#endif
    }

    read_pos = read_buffer((void*)&hello.cipher_suites_length, (void*)read_pos, 2);
    hello.cipher_suites_length = ntohs(hello.cipher_suites_length);
    hello.cipher_suites = (unsigned short*)malloc(hello.cipher_suites_length);
    read_pos = read_buffer((void*)hello.cipher_suites, (void*)read_pos, hello.cipher_suites_length);
    read_pos = read_buffer((void*)&hello.compression_methods_length, (void*)read_pos, 1);
    hello.compression_methods = (unsigned char*)malloc(hello.compression_methods_length);
    read_pos = read_buffer((void*)hello.compression_methods, (void*)read_pos, hello.compression_methods_length);

    printf("cipher_suites:");
    for (i = 0; i < hello.cipher_suites_length / 2; i++) {
        hello.cipher_suites[i] = ntohs(hello.cipher_suites[i]);
        if (hello.cipher_suites[i] > 0 && hello.cipher_suites[i] < MAX_SUPPORTED_CIPHER_SUITE) {
            printf("%0.4x ", hello.cipher_suites[i]);
        }
        // if (hello.cipher_suites[i] < MAX_SUPPORTED_CIPHER_SUITE && suites[hello.cipher_suites[i]].bulk_encrypt != NULL) {
        //     parameters->recv_parameters.suite = hello.cipher_suites[i];
        //     parameters->send_parameters.suite = hello.cipher_suites[i];
        //     break;
        // }
    }
    printf("\n");

    // 0039 0038 0037 0036 0035 0033 0032 0031 0030 002f 0007 0005 0004 0016 0013 0010 000d 000a
    parameters->recv_parameters.suite = TLS_AES_256_GCM_SHA384;
    parameters->send_parameters.suite = TLS_AES_256_GCM_SHA384;

    if (i == MAX_SUPPORTED_CIPHER_SUITE) {
        return NULL;
    }

    parameters->got_client_hello = 1;
    memcpy((void*)parameters->client_random, &hello.random.gmt_unix_time, 4);
    memcpy((void*)(parameters->client_random + 4), (void*)hello.random.random_bytes, 28);

    free(hello.cipher_suites);
    free(hello.compression_methods);

    if (hello.session_id) {
        free(hello.session_id);
    }

    printf("client_random:");
    show_hex(parameters->client_random, 32, 1);

    read_pos = parse_client_hello_extensions(read_pos, pdu_length - (read_pos - start_pos), parameters);

    return read_pos;
}

int send_server_hello(int connection, TLSParameters* parameters) {
    ServerHello       package;
    int               ext_len = 0;
    int               send_buffer_size;
    unsigned char* ext_buffer;
    unsigned char* send_buffer;
    void* write_buffer;
    time_t            local_time;

    package.server_version.major = TLS_VERSION_MAJOR;
    package.server_version.minor = TLS_VERSION_MINOR > 3 ? 3 : TLS_VERSION_MINOR;
    time(&local_time);
    package.random.gmt_unix_time = htonl(local_time);
    package.random.gmt_unix_time = 1705734549;
    // TODO - actually make this random.
    // This is 28 bytes, but client random is 32 - the first four bytes of
    // "client random" are the GMT unix time computed above.
    memcpy(parameters->server_random, &package.random.gmt_unix_time, 4);
    for (int i = 0; i < 28; i++) {
        parameters->server_random[4 + i] = i + 1;
    }
    memcpy(package.random.random_bytes, parameters->server_random + 4, 28);
    package.session_id_length = parameters->session_id_length ? parameters->session_id_length : 32;
    package.cipher_suite = htons(parameters->send_parameters.suite);
    package.compression_method = 0;
    ext_buffer = set_server_hello_extensions(&ext_len, parameters);

    if (!parameters->session_id_length) {
        parameters->session_id = create_session_id();
        parameters->session_id_length = 32;
    }
    memcpy(package.session_id, parameters->session_id, parameters->session_id_length);

    printf("server_random:");
    show_hex(parameters->server_random, 32, 1);

    send_buffer_size =
        sizeof(ProtocolVersion) +
        sizeof(Random) +
        sizeof(unsigned char) +
        (sizeof(unsigned char) * package.session_id_length) +
        sizeof(unsigned short) +
        sizeof(unsigned char) +
        ext_len;

    write_buffer = send_buffer = (unsigned char*)malloc(send_buffer_size);

    write_buffer = append_buffer(write_buffer, (void*)&package.server_version.major, 1);
    write_buffer = append_buffer(write_buffer, (void*)&package.server_version.minor, 1);
    write_buffer = append_buffer(write_buffer, (void*)&package.random.gmt_unix_time, 4);
    write_buffer = append_buffer(write_buffer, (void*)&package.random.random_bytes, 28);
    write_buffer = append_buffer(write_buffer, (void*)&package.session_id_length, 1);

    if (package.session_id_length > 0) {
        write_buffer = append_buffer(write_buffer, (void*)package.session_id, package.session_id_length);
    }

    write_buffer = append_buffer(write_buffer, (void*)&package.cipher_suite, 2);
    write_buffer = append_buffer(write_buffer, (void*)&package.compression_method, 1);

    if (ext_len > 0) {
        write_buffer = append_buffer(write_buffer, (void*)ext_buffer, ext_len);
        free(ext_buffer);
    }

    assert(((unsigned char*)write_buffer - send_buffer) == send_buffer_size);

    printf("send_server_hello:");
    show_hex(send_buffer, send_buffer_size, 1);

    send_handshake_message(connection, server_hello, send_buffer, send_buffer_size, parameters);
    if (TLS_VERSION_MINOR > 3) {
        calculate_handshake_keys(parameters);
    }

    free(send_buffer);

    return 0;
}

unsigned char* parse_server_hello(
    unsigned char* read_pos,
    int pdu_length,
    TLSParameters* parameters
) {
    ServerHello hello;

    read_pos = read_buffer((void*)&hello.server_version.major, (void*)read_pos, 1);
    read_pos = read_buffer((void*)&hello.server_version.minor, (void*)read_pos, 1);
    read_pos = read_buffer((void*)&hello.random.gmt_unix_time, (void*)read_pos, 4);
    // *DON'T* put this in host order, since it's not used as a time!  Just
    // accept it as is
    read_pos = read_buffer((void*)hello.random.random_bytes, (void*)read_pos, 28);
    read_pos = read_buffer((void*)&hello.session_id_length, (void*)read_pos, 1);
    read_pos = read_buffer((void*)hello.session_id, (void*)read_pos, hello.session_id_length);
    read_pos = read_buffer((void*)&hello.cipher_suite, (void*)read_pos, 2);
    hello.cipher_suite = ntohs(hello.cipher_suite);

    // TODO check that these values were actually in the client hello
    // list.  
    parameters->recv_parameters.suite = hello.cipher_suite;
    parameters->send_parameters.suite = hello.cipher_suite;

    read_pos = read_buffer((void*)&hello.compression_method, (void*)read_pos, 1);
    if (hello.compression_method != 0) {
        fprintf(stderr, "Error, server wants compression.\n");
        return NULL;
    }

    // TODO - abort if there's more data here than in the spec (per section 7.4.1.2,
    // forward compatibility note)
    // TODO - abort if version < 3.1 with "protocol_version" alert error

    // 28 random bytes, but the preceding four bytes are the reported GMT unix time
    memcpy((void*)parameters->server_random, &hello.random.gmt_unix_time, 4);
    memcpy((void*)(parameters->server_random + 4), (void*)hello.random.random_bytes, 28);

    return read_pos;
}

int send_server_session_ticket(int connection, TLSParameters* parameters) {
    unsigned char* sign_out;
    unsigned char iv[12] = { 0 };
    unsigned char encrypted[MASTER_SECRET_LENGTH + 16];

    aes_128_gcm_encrypt(parameters->master_secret, MASTER_SECRET_LENGTH, encrypted, iv, (unsigned char*)"session_ticket", 14, session_key);

    unsigned short session_tikcet_len = sizeof(iv) + sizeof(encrypted);
    int send_buffer_size = session_tikcet_len + 6;
    unsigned char* send_bufer = (unsigned char*)malloc(send_buffer_size);
    unsigned char* buffer = send_bufer;

    memset(buffer, 0, send_buffer_size);
    buffer += 4;
    session_tikcet_len = htons(session_tikcet_len);
    memcpy(buffer, &session_tikcet_len, 2);
    buffer += 2;
    memcpy(buffer, iv, sizeof(iv));
    buffer += sizeof(iv);
    memcpy(buffer, encrypted, sizeof(encrypted));

    return send_handshake_message(connection, session_ticket, send_bufer, send_buffer_size, parameters);
}

int send_certificate(int connection, TLSParameters* parameters) {
    short send_buffer_size;
    unsigned char* send_buffer, * read_buffer;
    int certificate_file;
    struct stat certificate_stat;
    short cert_len;
    char cert_url[200] = { 0 };

    switch (parameters->send_parameters.suite) {
    case TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_DH_RSA_WITH_DES_CBC_SHA:
    case TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
    case TLS_DH_RSA_WITH_AES_128_CBC_SHA:
    case TLS_DH_RSA_WITH_AES_256_CBC_SHA:
        strcpy(cert_url, "./res/rsa_dhcert.pem");
        break;
    case TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_DH_DSS_WITH_DES_CBC_SHA:
    case TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
    case TLS_DH_DSS_WITH_AES_128_CBC_SHA:
    case TLS_DH_DSS_WITH_AES_256_CBC_SHA:
        strcpy(cert_url, "./res/dsa_dhcert.pem");
        break;
    case TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_DHE_DSS_WITH_DES_CBC_SHA:
    case TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
    case TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
    case TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
        strcpy(cert_url, "./res/dsa_cert.pem");
        break;
    case TLS_RSA_WITH_NULL_MD5:
    case TLS_RSA_WITH_NULL_SHA:
    case TLS_RSA_WITH_RC4_128_MD5:
    case TLS_RSA_WITH_RC4_128_SHA:
    case TLS_RSA_WITH_IDEA_CBC_SHA:
    case TLS_RSA_WITH_DES_CBC_SHA:
    case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
    case TLS_RSA_WITH_AES_128_CBC_SHA:
    case TLS_RSA_WITH_AES_256_CBC_SHA:
    case TLS_RSA_WITH_AES_128_GCM_SHA256:
    case TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_DHE_RSA_WITH_DES_CBC_SHA:
    case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
    case TLS_RSA_WITH_AES_256_GCM_SHA384:
    case TLS_AES_128_GCM_SHA256:
    case TLS_AES_256_GCM_SHA384:
        strcpy(cert_url, "./res/rsa_cert.pem");
        break;
    case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
    case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
        strcpy(cert_url, "./res/rsa_ecdhcert.pem");
        break;
    case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
    case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
        strcpy(cert_url, "./res/ecdsa_ecdhcert.pem");
        break;
    case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
    case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
        strcpy(cert_url, "./res/ecdsa_cert.pem");
        break;
    default:
        return 0;
    }

    if ((certificate_file = open(cert_url, O_RDONLY)) == -1) {
        perror("unable to load certificate file");
        return 1;
    }

    if (fstat(certificate_file, &certificate_stat) == -1) {
        perror("unable to stat certificate file");
        return 1;
    }

    unsigned char* pem_buffer;
    unsigned char* buffer;
    unsigned char* pos;
    int buffer_size;

    if (!(pem_buffer = load_file(cert_url, &buffer_size))) {
        perror("Unable to load file");
        return 0;
    }

    buffer = (unsigned char*)malloc(buffer_size);
    buffer_size = pem_decode(pem_buffer, buffer, NULL, NULL);
    free(pem_buffer);

    send_buffer_size = buffer_size + 6;
    if (TLS_VERSION_MINOR >= 4) {
        send_buffer_size += 3;
    }

    send_buffer = (unsigned char*)malloc(send_buffer_size);
    memset(send_buffer, '\0', send_buffer_size);

    pos = send_buffer;
    if (TLS_VERSION_MINOR >= 4) {
        pos += 1;
    }

    cert_len = buffer_size + 3;
    if (TLS_VERSION_MINOR >= 4) {
        cert_len += 2;
    }
    cert_len = htons(cert_len);
    memcpy((void*)(pos + 1), &cert_len, 2);
    pos += 3;

    cert_len = buffer_size;
    cert_len = htons(cert_len);
    memcpy((void*)(pos + 1), &cert_len, 2);
    pos += 3;

    memcpy(pos, buffer, buffer_size);

    send_handshake_message(connection, certificate, send_buffer, send_buffer_size, parameters);

    free(send_buffer);

    return 0;
}

int send_server_certificate_verify(int connection, TLSParameters* parameters) {
    CipherSuite* send_suite = &(suites[parameters->send_parameters.suite]);
    digest_ctx ctx, sha256;
    send_suite->new_digest(&ctx);
    new_sha256_digest(&sha256);

    unsigned char handshake_hash[ctx.result_size];
    int sign_in_len = 64 + 33 + 1 + ctx.result_size;
    unsigned char content[sign_in_len];
    unsigned char* pos = content;
    unsigned char sign_input[sha256.result_size];

    compute_handshake_hash(parameters, handshake_hash);
    memset(pos, 0x20, 64);
    pos += 64;
    memcpy(pos, (void*)"TLS 1.3, server CertificateVerify", 33);
    pos += 33;
    pos[0] = 0;
    pos += 1;
    memcpy(pos, handshake_hash, ctx.result_size);
    pos += ctx.result_size;

    digest_hash(&sha256, content, sign_in_len);
    memcpy(sign_input, sha256.hash, sha256.result_size);

    int pre_len = sizeof(SHA_256_DER_PRE);
    unsigned char* input = malloc(pre_len + sign_in_len);
    unsigned char* sign_out;
    memcpy(input, SHA_256_DER_PRE, pre_len);
    memcpy(input + pre_len, sign_input, sign_in_len);
    int sign_out_len = rsa_sign(&private_rsa_key, input, pre_len + sign_in_len, &sign_out, RSA_PKCS1_PADDING);

    int send_buffer_size = 2 + sign_out_len + 2;
    unsigned char send_buffer[send_buffer_size];
    pos = send_buffer;

    // enum {
    //   none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
    //   sha512(6), (255)
    // } HashAlgorithm;
    memset(pos, 4, 1);
    pos += 1;
    // enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) } SignatureAlgorithm;
    memset(pos, 1, 1);
    pos += 1;
    pre_len = htons(sign_out_len);
    memcpy(pos, &pre_len, 2);
    pos += 2;
    memcpy(pos, sign_out, sign_out_len);

    if (send_handshake_message(connection, certificate_verify, send_buffer, send_buffer_size, parameters)) {
        return -1;
    }

    return 0;
}

int send_server_hello_done(int connection, TLSParameters* parameters) {
    send_handshake_message(connection, server_hello_done, NULL, 0, parameters);

    return 0;
}

int rsa_key_exchange(
    rsa_key* public_key,
    unsigned char* premaster_secret,
    unsigned char** key_exchange_message
) {
    int i;
    unsigned char* encrypted_premaster_secret = NULL;
    int encrypted_length;

    // first two bytes are protocol version
    premaster_secret[0] = TLS_VERSION_MAJOR;
    premaster_secret[1] = TLS_VERSION_MINOR > 3 ? 3 : TLS_VERSION_MINOR;
    for (i = 2; i < MASTER_SECRET_LENGTH; i++) {
        // XXX SHOULD BE RANDOM!
        premaster_secret[i] = i;
    }

    encrypted_length = rsa_encrypt(public_key, premaster_secret, MASTER_SECRET_LENGTH, &encrypted_premaster_secret, RSA_PKCS1_PADDING);

    *key_exchange_message = (unsigned char*)malloc(encrypted_length + 2);
    (*key_exchange_message)[0] = 0;
    (*key_exchange_message)[1] = encrypted_length;
    memcpy((*key_exchange_message) + 2, encrypted_premaster_secret, encrypted_length);

    free(encrypted_premaster_secret);

    return encrypted_length + 2;
}

/**
 * Just compute Yc = g^a % p and return it in "key_exchange_message".  The
 * premaster secret is Ys ^ a % p.
 */
int dh_key_exchange(
    dh_key* server_dh_key,
    unsigned char* premaster_secret,
    unsigned char** key_exchange_message
) {
    huge Yc;
    huge Z;
    huge a;
    int message_size;
    short transmit_len;
    Yc.rep = NULL;
    Z.rep = NULL;

    // TODO obviously, make this random, and much longer
    huge_set(&a, 6);
    huge_copy(&Yc, &server_dh_key->g);
    huge_copy(&Z, &server_dh_key->Y);
    huge_mod_pow(&Yc, &a, &server_dh_key->p);
    huge_mod_pow(&Z, &a, &server_dh_key->p);

    // Now copy Z into premaster secret and Yc into key_exchange_message
    memcpy(premaster_secret, Z.rep, Z.size);
    message_size = Yc.size + 2;
    transmit_len = htons(Yc.size);
    *key_exchange_message = malloc(message_size);
    memcpy(*key_exchange_message, &transmit_len, 2);
    memcpy(*key_exchange_message + 2, Yc.rep, Yc.size);

    huge_free(&Yc);
    huge_free(&Z);
    huge_free(&a);

    return message_size;
}

/**
 * Send the client key exchange message, as detailed in section 7.4.7
 * Use the server's public key (if it has one) to encrypt a key. (or DH?)
 * Return true if this succeeded, false otherwise.
 */
int send_client_key_exchange(int connection, TLSParameters* parameters) {
    unsigned char* key_exchange_message;
    int key_exchange_message_len;
    unsigned char* premaster_secret;
    int premaster_secret_len;

    switch (parameters->send_parameters.suite) {
    case TLS_NULL_WITH_NULL_NULL:
        // XXX this is an error, exit here
        break;
    case TLS_RSA_WITH_NULL_MD5:
    case TLS_RSA_WITH_NULL_SHA:
    case TLS_RSA_EXPORT_WITH_RC4_40_MD5:
    case TLS_RSA_WITH_RC4_128_MD5:
    case TLS_RSA_WITH_RC4_128_SHA:
    case TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5:
    case TLS_RSA_WITH_IDEA_CBC_SHA:
    case TLS_RSA_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_RSA_WITH_DES_CBC_SHA:
    case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
    case TLS_RSA_WITH_AES_128_CBC_SHA:
    case TLS_RSA_WITH_AES_256_CBC_SHA:
        premaster_secret_len = MASTER_SECRET_LENGTH;
        premaster_secret = malloc(premaster_secret_len);
        key_exchange_message_len = rsa_key_exchange(&parameters->server_public_key.rsa_public_key, premaster_secret, &key_exchange_message);
        break;
    case TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_DH_DSS_WITH_DES_CBC_SHA:
    case TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
    case TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_DH_RSA_WITH_DES_CBC_SHA:
    case TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
    case TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_DHE_DSS_WITH_DES_CBC_SHA:
    case TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
    case TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_DHE_RSA_WITH_DES_CBC_SHA:
    case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
    case TLS_DH_anon_EXPORT_WITH_RC4_40_MD5:
    case TLS_DH_anon_WITH_RC4_128_MD5:
    case TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_DH_anon_WITH_DES_CBC_SHA:
    case TLS_DH_anon_WITH_3DES_EDE_CBC_SHA:
    case TLS_DH_DSS_WITH_AES_128_CBC_SHA:
    case TLS_DH_RSA_WITH_AES_128_CBC_SHA:
    case TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
    case TLS_DH_anon_WITH_AES_128_CBC_SHA:
    case TLS_DH_DSS_WITH_AES_256_CBC_SHA:
    case TLS_DH_RSA_WITH_AES_256_CBC_SHA:
    case TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
    case TLS_DH_anon_WITH_AES_256_CBC_SHA:
        premaster_secret_len = parameters->server_dh_key.p.size;
        premaster_secret = malloc(premaster_secret_len);
        key_exchange_message_len = dh_key_exchange(&parameters->server_dh_key, premaster_secret, &key_exchange_message);
        break;
    default:
        return 0;
    }

    if (send_handshake_message(connection, client_key_exchange, key_exchange_message, key_exchange_message_len, parameters)) {
        free(key_exchange_message);
        return 0;
    }

    free(key_exchange_message);

    // Now, turn the premaster secret into an actual master secret (the
    // server side will do this concurrently).
    compute_master_secret(premaster_secret, premaster_secret_len, parameters);

    // XXX - for security, should also "purge" the premaster secret from
    // memory.
    calculate_keys(parameters);

    free(premaster_secret);

    return 1;
}


/**
 * By the time this is called, "read_pos" points at an RSA encrypted (unless
 * RSA isn't used for key exchange) premaster secret.  All this routine has to
 * do is decrypt it.  See "privkey.c" for details.
 * TODO expand this to support Diffie-Hellman key exchange
 */
unsigned char* parse_client_key_exchange(
    unsigned char* read_pos,
    int pdu_length,
    TLSParameters* parameters
) {
    int premaster_secret_length;
    unsigned char* premaster_secret;
    huge Yc;
    point pt;

    switch (parameters->send_parameters.suite) {
    case TLS_RSA_WITH_NULL_MD5: //RSA密钥交换
    case TLS_RSA_WITH_NULL_SHA:
    case TLS_RSA_EXPORT_WITH_RC4_40_MD5:
    case TLS_RSA_WITH_RC4_128_MD5:
    case TLS_RSA_WITH_RC4_128_SHA:
    case TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5:
    case TLS_RSA_WITH_IDEA_CBC_SHA:
    case TLS_RSA_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_RSA_WITH_DES_CBC_SHA:
    case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
    case TLS_RSA_WITH_AES_128_CBC_SHA:
    case TLS_RSA_WITH_AES_256_CBC_SHA:
    case TLS_RSA_WITH_AES_128_GCM_SHA256:
    case TLS_RSA_WITH_AES_256_GCM_SHA384:
        switch (parameters->send_parameters.suite) {
        case TLS_RSA_EXPORT_WITH_RC4_40_MD5:
        case TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5:
        case TLS_RSA_EXPORT_WITH_DES40_CBC_SHA:
            // Skip over the two length bytes, since length is already known anyway
            premaster_secret_length = rsa_decrypt(&private_rsa_export_key, read_pos + 2, pdu_length - 2, &premaster_secret, RSA_PKCS1_PADDING);
        default:
            // Skip over the two length bytes, since length is already known anyway
            premaster_secret_length = rsa_decrypt(&private_rsa_key, read_pos + 2, pdu_length - 2, &premaster_secret, RSA_PKCS1_PADDING);
            break;
        }

        printf("premaster_secret:");
        show_hex(premaster_secret, premaster_secret_length, 1);

        if (premaster_secret_length <= 0) {
            fprintf(stderr, "Unable to decrypt premaster secret.\n");
            return NULL;
        }
        // Now use the premaster secret to compute the master secret.  Don't forget
        // that the first two bytes of the premaster secret are the version 0x03 0x01
        // These are part of the premaster secret (8.1.1 states that the premaster
        // secret for RSA is exactly 48 bytes long).
        compute_master_secret(premaster_secret, premaster_secret_length > MASTER_SECRET_LENGTH ? MASTER_SECRET_LENGTH : premaster_secret_length, parameters);
        break;
    case TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA: //静态DH密钥交换
    case TLS_DH_RSA_WITH_DES_CBC_SHA:
    case TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA:
    case TLS_DH_RSA_WITH_AES_128_CBC_SHA:
    case TLS_DH_RSA_WITH_AES_256_CBC_SHA:
    case TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_DH_DSS_WITH_DES_CBC_SHA:
    case TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA:
    case TLS_DH_DSS_WITH_AES_128_CBC_SHA:
    case TLS_DH_DSS_WITH_AES_256_CBC_SHA:
        huge_load(&Yc, read_pos + 2, pdu_length - 2);
        huge_mod_pow(&Yc, &dh_priv_key.Y, &dh_priv_key.p);
        premaster_secret_length = huge_bytes(&Yc);
        premaster_secret = (unsigned char*)malloc(premaster_secret_length);
        huge_unload(&Yc, premaster_secret, premaster_secret_length);

        printf("premaster_secret:");
        show_hex(premaster_secret, premaster_secret_length, 1);

        compute_master_secret(premaster_secret, premaster_secret_length, parameters);
        break;
    case TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA: //动态DH密钥交换
    case TLS_DHE_RSA_WITH_DES_CBC_SHA:
    case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
    case TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_DHE_DSS_WITH_DES_CBC_SHA:
    case TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
    case TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
    case TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
    case TLS_DH_anon_EXPORT_WITH_RC4_40_MD5:
    case TLS_DH_anon_WITH_RC4_128_MD5:
    case TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_DH_anon_WITH_DES_CBC_SHA:
    case TLS_DH_anon_WITH_3DES_EDE_CBC_SHA:
    case TLS_DH_anon_WITH_AES_128_CBC_SHA:
    case TLS_DH_anon_WITH_AES_256_CBC_SHA:
        huge_load(&Yc, read_pos + 2, pdu_length - 2);
        huge_mod_pow(&Yc, &dh_priv, &dh_tmp_key.p);
        premaster_secret_length = huge_bytes(&Yc);
        premaster_secret = (unsigned char*)malloc(premaster_secret_length);
        huge_unload(&Yc, premaster_secret, premaster_secret_length);

        printf("premaster_secret:");
        show_hex(premaster_secret, premaster_secret_length, 1);

        compute_master_secret(premaster_secret, premaster_secret_length, parameters);
        break;
    case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA:
    case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA:
    case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA:
    case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA:
    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
    case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
    case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
        huge_load(&pt.x, read_pos + 2, (pdu_length - 2) / 2);
        huge_load(&pt.y, read_pos + 2 + (pdu_length - 2) / 2, (pdu_length - 1) / 2);
        multiply_point(&pt, &private_ecc_key.d, &private_ecc_key.curve.a, &private_ecc_key.curve.p);
        premaster_secret_length = huge_bytes(&pt.x);
        premaster_secret = (unsigned char*)malloc(premaster_secret_length);
        huge_unload(&pt.x, premaster_secret, premaster_secret_length);

        printf("premaster_secret:");
        show_hex(premaster_secret, premaster_secret_length, 1);

        compute_master_secret(premaster_secret, premaster_secret_length, parameters);
        break;
    default:
        return NULL;
    }

    calculate_keys(parameters);

    return read_pos + pdu_length;
}

int send_server_key_exchange_with_dh(int connection, TLSParameters* parameters, int sign_algorithm) {
    unsigned char* key_exchange_message;
    unsigned char* buffer;
    short key_exchange_message_len;
    short length = 0;
    int p_size = huge_bytes(&dh_tmp_key.p);
    int g_size = huge_bytes(&dh_tmp_key.g);
    int Y_size = huge_bytes(&dh_tmp_key.Y);
    int dh_len = p_size + g_size + Y_size + 6;
    int hash_input_len = RANDOM_LENGTH * 2 + dh_len;
    int sign_in_len = 36;
    int sign_out_len = 0;

    unsigned char dh_input[dh_len];
    unsigned char hash_input[hash_input_len];
    unsigned char sign_input[sign_in_len];
    unsigned char* sign_out;

    memset(dh_input, 0, dh_len);
    memset(hash_input, 0, hash_input_len);
    memset(sign_input, 0, sign_in_len);

    digest_ctx md5, sha1, sha256;
    new_md5_digest(&md5);
    new_sha1_digest(&sha1);
    new_sha256_digest(&sha256);

    // ServerDHParams-begin
    // struct {
    //     opaque dh_p<1..2^16-1>;
    //     opaque dh_g<1..2^16-1>;
    //     opaque dh_Ys<1..2^16-1>;
    // } ServerDHParams
    buffer = dh_input;
    buffer[1] = p_size;
    buffer += 2;
    huge_unload(&dh_tmp_key.p, buffer, p_size);
    buffer += p_size;

    buffer[1] = g_size;
    buffer += 2;
    huge_unload(&dh_tmp_key.g, buffer, g_size);
    buffer += g_size;

    buffer[1] = Y_size;
    buffer += 2;
    huge_unload(&dh_tmp_key.Y, buffer, Y_size);
    // ServerDHParams-end

    if (sign_algorithm) {
        // hash-begin
        // MD5(ClientHello.random + ServerHello.random + ServerParams)
        // SHA(ClientHello.random + ServerHello.random + ServerParams)
        buffer = hash_input;
        memcpy(buffer, parameters->client_random, RANDOM_LENGTH);
        buffer += RANDOM_LENGTH;

        memcpy(buffer, parameters->server_random, RANDOM_LENGTH);
        buffer += RANDOM_LENGTH;

        memcpy(buffer, dh_input, dh_len);

        // hash-end
        if (TLS_VERSION_MINOR >= 3) {
            digest_hash(&sha256, hash_input, hash_input_len);
            memcpy(sign_input, sha256.hash, sha256.result_size);
            sign_in_len = 32;
        } else if (sign_algorithm == 1) { //rsa_sign
            // digitally-signed struct {
            //     opaque md5_hash[16];
            //     opaque sha_hash[20];
            // };
            digest_hash(&md5, hash_input, hash_input_len);
            digest_hash(&sha1, hash_input, hash_input_len);
            memcpy(sign_input, md5.hash, md5.result_size);
            memcpy(sign_input + md5.result_size, sha1.hash, sha1.result_size);
            sign_in_len = 36;
        } else if (sign_algorithm == 2) { //dsa_sign
            // digitally-signed struct {
            //     opaque sha_hash[20];
            // };
            digest_hash(&sha1, hash_input, hash_input_len);
            memcpy(sign_input, sha1.hash, sha1.result_size);
            sign_in_len = 20;
        }
    }

    // digitally-signed-begin
    if (sign_algorithm == 1) { //rsa_sign
        int pre_len = sizeof(SHA_256_DER_PRE);
        unsigned char* input = malloc(pre_len + sign_in_len);
        memcpy(input, SHA_256_DER_PRE, pre_len);
        memcpy(input + pre_len, sign_input, sign_in_len);
        sign_out_len = rsa_sign(&private_rsa_key, input, pre_len + sign_in_len, &sign_out, RSA_PKCS1_PADDING);
    } else if (sign_algorithm == 2) { //dsa_sign
        int r_len = 0, s_len = 0;
        unsigned char* r;
        unsigned char* s;
        dsa_signature signature;
        huge_set(&signature.r, 0);
        huge_set(&signature.s, 0);

        dsa_sign(&private_dsa_key.params, &private_dsa_key.key, sign_input, sign_in_len, &signature);

        r_len = huge_bytes(&signature.r);
        s_len = huge_bytes(&signature.s);
        r = (unsigned char*)malloc(r_len);
        s = (unsigned char*)malloc(s_len);
        huge_unload(&signature.r, r, r_len);
        huge_unload(&signature.s, s, s_len);
        /*
        tls1.0-4.7:
        Dss-Sig-Value  ::=  SEQUENCE  {
            r       INTEGER,
            s       INTEGER
        }
        */
        //ASN.1整数编码有符号位，最高位为符号位
        int r_sign = (r[0] & 0x80 ? 1 : 0);
        int s_sign = (s[0] & 0x80 ? 1 : 0);
        sign_out_len = r_len + s_len + 6 + r_sign + s_sign;
        sign_out = (unsigned char*)malloc(sign_out_len);
        memset(sign_out, 0, sign_out_len);
        buffer = sign_out;

        buffer[0] = ASN1_SEQUENCE_OF;
        buffer[1] = sign_out_len - 2;
        buffer += 2;

        buffer[0] = ASN1_INTEGER;
        buffer[1] = r_len + r_sign;
        buffer += 2 + r_sign;
        memcpy(buffer, r, r_len);
        buffer += r_len;

        buffer[0] = ASN1_INTEGER;
        buffer[1] = s_len + s_sign;
        buffer += 2 + s_sign;
        memcpy(buffer, s, s_len);
    }
    // digitally-signed-end

    key_exchange_message_len = dh_len + sign_out_len + 2;
    key_exchange_message_len += TLS_VERSION_MINOR >= 3 && sign_algorithm ? 2 : 0; //SignatureAndHashAlgorithm
    key_exchange_message = (unsigned char*)malloc(key_exchange_message_len);

    buffer = key_exchange_message;
    memcpy(buffer, dh_input, dh_len);
    buffer += dh_len;

    if (sign_out_len) {
        if (TLS_VERSION_MINOR >= 3) {
            // enum {
            //   none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
            //   sha512(6), (255)
            // } HashAlgorithm;
            memset(buffer, 4, 1);
            buffer += 1;
            // enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) } SignatureAlgorithm;
            memset(buffer, sign_algorithm, 1);
            buffer += 1;
        }
        length = htons(sign_out_len);
        memcpy(buffer, &length, 2);
        buffer += 2;
        memcpy(buffer, sign_out, sign_out_len);
    }

    if (send_handshake_message(connection, server_key_exchange, key_exchange_message, key_exchange_message_len, parameters)) {
        free(key_exchange_message);
        return 1;
    }

    free(key_exchange_message);

    return 0;
}

int send_server_key_exchange_with_rsa(int connection, TLSParameters* parameters) {
    if (huge_bytes(private_rsa_key.p) <= EXPORT_RSA_BITS / 8) {
        return 0;
    }
    unsigned char* key_exchange_message;
    unsigned char* buffer;
    short key_exchange_message_len;
    short length = 0;
    int sign_out_len = 0;
    int p_size = huge_bytes(private_rsa_export_key.p);
    int pub_size = huge_bytes(private_rsa_export_key.pub);
    int rsa_len = p_size + pub_size + 4;
    int hash_input_len = RANDOM_LENGTH * 2 + rsa_len;

    unsigned char rsa_input[rsa_len];
    unsigned char hash_input[hash_input_len];
    unsigned char sign_input[36];
    unsigned char* sign_out;

    memset(rsa_input, 0, rsa_len);
    memset(hash_input, 0, hash_input_len);
    memset(sign_input, 0, 36);

    digest_ctx md5, sha1;
    new_md5_digest(&md5);
    new_sha1_digest(&sha1);

    // ServerRSAParams-begin
    // struct {
    //     opaque rsa_modulus<1..2^16-1>;
    //     opaque rsa_exponent<1..2^16-1>;
    // } ServerRSAParams
    buffer = rsa_input;
    buffer[1] = p_size;
    buffer += 2;
    huge_unload(private_rsa_export_key.p, buffer, p_size);
    buffer += p_size;

    buffer[1] = pub_size;
    buffer += 2;
    huge_unload(private_rsa_export_key.pub, buffer, pub_size);
    // ServerRSAParams-end

    // hash-begin
    // MD5(ClientHello.random + ServerHello.random + ServerParams)
    // SHA(ClientHello.random + ServerHello.random + ServerParams)
    buffer = hash_input;
    memcpy(buffer, parameters->client_random, RANDOM_LENGTH);
    buffer += RANDOM_LENGTH;

    memcpy(buffer, parameters->server_random, RANDOM_LENGTH);
    buffer += RANDOM_LENGTH;

    memcpy(buffer, rsa_input, rsa_len);

    digest_hash(&md5, hash_input, hash_input_len);
    digest_hash(&sha1, hash_input, hash_input_len);
    // hash-end

    // digitally-signed struct {
    //     opaque md5_hash[16];
    //     opaque sha_hash[20];
    // };
    memcpy(sign_input, md5.hash, md5.result_size);
    memcpy(sign_input + md5.result_size, sha1.hash, sha1.result_size);
    sign_out_len = rsa_sign(&private_rsa_key, sign_input, 36, &sign_out, RSA_PKCS1_PADDING);

    key_exchange_message_len = rsa_len + sign_out_len + 2;
    key_exchange_message = (unsigned char*)malloc(key_exchange_message_len);

    buffer = key_exchange_message;
    memcpy(buffer, rsa_input, rsa_len);
    buffer += rsa_len;

    length = htons(sign_out_len);
    memcpy(buffer, &length, 2);
    buffer += 2;
    memcpy(buffer, sign_out, sign_out_len);

    if (send_handshake_message(connection, server_key_exchange, key_exchange_message, key_exchange_message_len, parameters)) {
        free(key_exchange_message);
        return 1;
    }

    free(key_exchange_message);

    return 0;
}

int send_server_key_exchange_with_ecdh(int connection, TLSParameters* parameters, int sign_algorithm) {
    unsigned char* key_exchange_message;
    unsigned char* buffer;
    short key_exchange_message_len;
    short length = 0;
    int p_size = huge_bytes(&private_ecc_key.Q.x) + huge_bytes(&private_ecc_key.Q.y) + 1;
    int ecdh_len = p_size + 4;
    int hash_input_len = RANDOM_LENGTH * 2 + ecdh_len;
    int sign_in_len = 36;
    int sign_out_len = 0;

    unsigned char ecdh_input[ecdh_len];
    unsigned char hash_input[hash_input_len];
    unsigned char sign_input[sign_in_len];
    unsigned char* sign_out;

    memset(ecdh_input, 0, ecdh_len);
    memset(hash_input, 0, hash_input_len);
    memset(sign_input, 0, sign_in_len);

    digest_ctx md5, sha1, sha256;
    new_md5_digest(&md5);
    new_sha1_digest(&sha1);
    new_sha256_digest(&sha256);

    // ServerDHParams-begin
    // enum { explicit_prime (1), explicit_char2 (2), named_curve (3), reserved(248..255) } ECCurveType;
    // enum {
    //     sect163k1 (1), sect163r1 (2), sect163r2 (3),
    //     sect193r1 (4), sect193r2 (5), sect233k1 (6),
    //     sect233r1 (7), sect239k1 (8), sect283k1 (9),
    //     sect283r1 (10), sect409k1 (11), sect409r1 (12),
    //     sect571k1 (13), sect571r1 (14), secp160k1 (15),
    //     secp160r1 (16), secp160r2 (17), secp192k1 (18),
    //     secp192r1 (19), secp224k1 (20), secp224r1 (21),
    //     secp256k1 (22), secp256r1 (23), secp384r1 (24),
    //     secp521r1 (25),
    //     reserved (0xFE00..0xFEFF),
    //     arbitrary_explicit_prime_curves(0xFF01),
    //     arbitrary_explicit_char2_curves(0xFF02),
    //     (0xFFFF)
    // } NamedCurve;
    // struct {
    //     ECCurveType    curve_type;
    //     select (curve_type) {
    //         case explicit_prime:...
    //         case explicit_char2:...
    //         case named_curve:
    //             NamedCurve namedcurve;
    //     };
    // } ECParameters;
    // struct {
    //     opaque point <1..2^8-1>;
    // } ECPoint;
    // struct {
    //     ECParameters    curve_params;
    //     ECPoint         public;
    // } ServerECDHParams;
    buffer = ecdh_input;
    buffer[0] = 3;
    if (!memcmp(private_ecc_key.curve_oid, SECP192K1_OID, sizeof(SECP192K1_OID))) {
        buffer[2] = 18;
    } else if (!memcmp(private_ecc_key.curve_oid, SECP192R1_OID, sizeof(SECP192R1_OID))) {
        buffer[2] = 19;
    } else if (!memcmp(private_ecc_key.curve_oid, SECP256R1_OID, sizeof(SECP256R1_OID))) {
        buffer[2] = 23;
    }
    buffer += 3;
    buffer[0] = p_size;
    buffer++;
    buffer[0] = 4;
    buffer++;
    huge_unload(&private_ecc_key.Q.x, buffer, huge_bytes(&private_ecc_key.Q.x));
    buffer += huge_bytes(&private_ecc_key.Q.x);
    huge_unload(&private_ecc_key.Q.y, buffer, huge_bytes(&private_ecc_key.Q.y));
    // ServerDHParams-end

    if (sign_algorithm) {
        // hash-begin
        // MD5(ClientHello.random + ServerHello.random + ServerParams)
        // SHA(ClientHello.random + ServerHello.random + ServerParams)
        buffer = hash_input;
        memcpy(buffer, parameters->client_random, RANDOM_LENGTH);
        buffer += RANDOM_LENGTH;

        memcpy(buffer, parameters->server_random, RANDOM_LENGTH);
        buffer += RANDOM_LENGTH;

        memcpy(buffer, ecdh_input, ecdh_len);

        // hash-end
        if (TLS_VERSION_MINOR >= 3) {
            digest_hash(&sha256, hash_input, hash_input_len);
            memcpy(sign_input, sha256.hash, sha256.result_size);
            sign_in_len = 32;
        } else if (sign_algorithm == 1) { //rsa_sign
            // digitally-signed struct {
            //     opaque md5_hash[16];
            //     opaque sha_hash[20];
            // };
            digest_hash(&md5, hash_input, hash_input_len);
            digest_hash(&sha1, hash_input, hash_input_len);
            memcpy(sign_input, md5.hash, md5.result_size);
            memcpy(sign_input + md5.result_size, sha1.hash, sha1.result_size);
            sign_in_len = 36;
        } else if (sign_algorithm == 3) { //ecdsa_sign
            // digitally-signed struct {
            //     opaque sha_hash[20];
            // };
            digest_hash(&sha1, hash_input, hash_input_len);
            memcpy(sign_input, sha1.hash, sha1.result_size);
            sign_in_len = 20;
        }
    }

    // digitally-signed-begin
    if (sign_algorithm == 1) { //rsa_sign
        int pre_len = sizeof(SHA_256_DER_PRE);
        unsigned char* input = malloc(pre_len + sign_in_len);
        memcpy(input, SHA_256_DER_PRE, pre_len);
        memcpy(input + pre_len, sign_input, sign_in_len);
        sign_out_len = rsa_sign(&private_rsa_key, input, pre_len + sign_in_len, &sign_out, RSA_PKCS1_PADDING);
    } else if (sign_algorithm == 3) { //ecdsa_sign
        int r_len = 0, s_len = 0;
        unsigned char* r;
        unsigned char* s;
        ecdsa_signature signature;
        huge_set(&signature.r, 0);
        huge_set(&signature.s, 0);

        ecdsa_sign(&private_ecdsa_key.curve, &private_ecdsa_key, sign_input, sign_in_len, &signature);

        r_len = huge_bytes(&signature.r);
        s_len = huge_bytes(&signature.s);
        r = (unsigned char*)malloc(r_len);
        s = (unsigned char*)malloc(s_len);
        huge_unload(&signature.r, r, r_len);
        huge_unload(&signature.s, s, s_len);
        /*
        tls1.0-4.7:
        Ecdsa-Sig-Value  ::=  SEQUENCE  {
            r       INTEGER,
            s       INTEGER
        }
        */
        //ASN.1整数编码有符号位，最高位为符号位
        int r_sign = (r[0] & 0x80 ? 1 : 0);
        int s_sign = (s[0] & 0x80 ? 1 : 0);
        sign_out_len = r_len + s_len + 6 + r_sign + s_sign;
        sign_out = (unsigned char*)malloc(sign_out_len);
        memset(sign_out, 0, sign_out_len);
        buffer = sign_out;

        buffer[0] = ASN1_SEQUENCE_OF;
        buffer[1] = sign_out_len - 2;
        buffer += 2;

        buffer[0] = ASN1_INTEGER;
        buffer[1] = r_len + r_sign;
        buffer += 2 + r_sign;
        memcpy(buffer, r, r_len);
        buffer += r_len;

        buffer[0] = ASN1_INTEGER;
        buffer[1] = s_len + s_sign;
        buffer += 2 + s_sign;
        memcpy(buffer, s, s_len);
    }
    // digitally-signed-end

    key_exchange_message_len = ecdh_len + sign_out_len + 2;
    key_exchange_message_len += TLS_VERSION_MINOR >= 3 && sign_algorithm ? 2 : 0; //SignatureAndHashAlgorithm
    key_exchange_message = (unsigned char*)malloc(key_exchange_message_len);

    buffer = key_exchange_message;
    memcpy(buffer, ecdh_input, ecdh_len);
    buffer += ecdh_len;

    if (sign_out_len) {
        if (TLS_VERSION_MINOR >= 3) {
            // enum {
            //   none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
            //   sha512(6), (255)
            // } HashAlgorithm;
            memset(buffer, 4, 1);
            buffer += 1;
            // enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) } SignatureAlgorithm;
            memset(buffer, sign_algorithm, 1);
            buffer += 1;
        }
        length = htons(sign_out_len);
        memcpy(buffer, &length, 2);
        buffer += 2;
        memcpy(buffer, sign_out, sign_out_len);
    }

    if (send_handshake_message(connection, server_key_exchange, key_exchange_message, key_exchange_message_len, parameters)) {
        free(key_exchange_message);
        return 1;
    }

    free(key_exchange_message);

    return 0;
}

// Server key exchange message
int send_server_key_exchange(int connection, TLSParameters* parameters) {
    switch (parameters->send_parameters.suite) {
    case TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_DHE_RSA_WITH_DES_CBC_SHA:
    case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
        return send_server_key_exchange_with_dh(connection, parameters, 1);
    case TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_DHE_DSS_WITH_DES_CBC_SHA:
    case TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
    case TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
    case TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
        return send_server_key_exchange_with_dh(connection, parameters, 2);
    case TLS_DH_anon_EXPORT_WITH_RC4_40_MD5:
    case TLS_DH_anon_WITH_RC4_128_MD5:
    case TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA:
    case TLS_DH_anon_WITH_DES_CBC_SHA:
    case TLS_DH_anon_WITH_3DES_EDE_CBC_SHA:
    case TLS_DH_anon_WITH_AES_128_CBC_SHA:
    case TLS_DH_anon_WITH_AES_256_CBC_SHA:
        return send_server_key_exchange_with_dh(connection, parameters, 0);
    case TLS_RSA_EXPORT_WITH_RC4_40_MD5:
    case TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5:
    case TLS_RSA_EXPORT_WITH_DES40_CBC_SHA:
        return send_server_key_exchange_with_rsa(connection, parameters);
    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
        return send_server_key_exchange_with_ecdh(connection, parameters, 1);
    case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
    case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
        return send_server_key_exchange_with_ecdh(connection, parameters, 3);
    default:
        return 0;
    }
}

int send_change_cipher_spec(int connection, TLSParameters* parameters) {
    unsigned char send_buffer[1];
    send_buffer[0] = 1;

    send_message(connection, content_change_cipher_spec, send_buffer, 1, &parameters->send_parameters);

    parameters->send_parameters.seq_num = 0;
    parameters->send_parameters.key_done = 1;

    return 1;
}

int send_encrypted_extensions(int connection, TLSParameters* parameters) {
    unsigned char send_bufer[2] = { 0 };
    int send_buffer_size = 2;

    return send_handshake_message(connection, encrypted_extensions, send_bufer, send_buffer_size, parameters);
}

int send_finished(int connection, TLSParameters* parameters) {
    CipherSuite* send_suite = &(suites[parameters->send_parameters.suite]);
    int verify_data_len = TLS_VERSION_MINOR <= 3 ? VERIFY_DATA_LEN : send_suite->hash_size;
    unsigned char verify_data[64] = { 0 };

    if (TLS_VERSION_MINOR <= 3) {
        compute_verify_data(
            parameters->connection_end == connection_end_client ? (unsigned char*)"client finished" : (unsigned char*)"server finished",
            parameters, verify_data
        );
    } else {
        compute_tls3_verify_data(parameters->send_parameters.tls3_keys.finished_key, verify_data, parameters);
    }

    send_handshake_message(connection, finished, verify_data, verify_data_len, parameters);

    if (TLS_VERSION_MINOR > 3) {
        calculate_application_keys(parameters);
        parameters->send_parameters.seq_num = 0;
    }

    return 1;
}

int send_server_pong(int connection, TLSParameters* parameters) {
    unsigned char send_bufer[4] = { 0x70, 0x6f, 0x6e, 0x67 };
    int send_buffer_size = 4;

    return send_message(connection, content_application_data, send_bufer, send_buffer_size, &parameters->send_parameters);
}

unsigned char* parse_finished(
    unsigned char* read_pos,
    int pdu_length,
    TLSParameters* parameters
) {
    CipherSuite* send_suite = &(suites[parameters->send_parameters.suite]);
    int verify_data_len = TLS_VERSION_MINOR <= 3 ? VERIFY_DATA_LEN : send_suite->hash_size;
    unsigned char verify_data[64] = { 0 }; //最大64字节

    parameters->peer_finished = 1;

    if (TLS_VERSION_MINOR <= 3) {
        compute_verify_data(
            parameters->connection_end == connection_end_client ? (unsigned char*)"server finished" : (unsigned char*)"client finished",
            parameters, verify_data
        );
    } else {
        compute_tls3_verify_data(parameters->recv_parameters.tls3_keys.finished_key, verify_data, parameters);
        parameters->recv_parameters.seq_num = 0;
    }

    if (memcmp(read_pos, verify_data, verify_data_len)) {
        return NULL;
    }

    return read_pos + pdu_length;
}

void report_alert(Alert* alert) {
    printf("Alert - ");

    switch (alert->level) {
    case warning:
        printf("Warning: ");
        break;
    case fatal:
        printf("Fatal: ");
        break;
    default:
        printf("UNKNOWN ALERT TYPE %d (!!!): ", alert->level);
        break;
    }

    switch (alert->description) {
    case close_notify:
        printf("Close notify\n");
        break;
    case unexpected_message:
        printf("Unexpected message\n");
        break;
    case bad_record_mac:
        printf("Bad Record Mac\n");
        break;
    case decryption_failed:
        printf("Decryption Failed\n");
        break;
    case record_overflow:
        printf("Record Overflow\n");
        break;
    case decompression_failure:
        printf("Decompression Failure\n");
        break;
    case handshake_failure:
        printf("Handshake Failure\n");
        break;
    case bad_certificate:
        printf("Bad Certificate\n");
        break;
    case unsupported_certificate:
        printf("Unsupported Certificate\n");
        break;
    case certificate_revoked:
        printf("Certificate Revoked\n");
        break;
    case certificate_expired:
        printf("Certificate Expired\n");
        break;
    case certificate_unknown:
        printf("Certificate Unknown\n");
        break;
    case illegal_parameter:
        printf("Illegal Parameter\n");
        break;
    case unknown_ca:
        printf("Unknown CA\n");
        break;
    case access_denied:
        printf("Access Denied\n");
        break;
    case decode_error:
        printf("Decode Error\n");
        break;
    case decrypt_error:
        printf("Decrypt Error\n");
        break;
    case export_restriction:
        printf("Export Restriction\n");
        break;
    case protocol_version:
        printf("Protocol Version\n");
        break;
    case insufficient_security:
        printf("Insufficient Security\n");
        break;
    case internal_error:
        printf("Internal Error\n");
        break;
    case user_canceled:
        printf("User canceled\n");
        break;
    case no_renegotiation:
        printf("No renegotiation\n");
        break;
    default:
        printf("UNKNOWN ALERT DESCRIPTION %d (!!!)\n", alert->description);
        break;
    }
}

/**
 * Decrypt a message and verify its MAC according to the active cipher spec
 * (as given by "parameters").  Free the space allocated by encrypted message
 * and allocate new space for the decrypted message (if decrypting is "identity",
 * then decrypted will point to encrypted).  The caller must always issue a
 * "free decrypted_message".
 * Return the length of the message, or -1 if the MAC doesn't verify.  The return
 * value will almost always be different than "encrypted_length", since it strips
 * off the MAC if present as well as bulk cipher padding (if a block cipher
 * algorithm is being used).
 */
int tls2_decrypt(
    unsigned char* header, // needed for MAC verification
    unsigned char* encrypted_message,
    short encrypted_length,
    unsigned char** decrypted_message,
    ProtectionParameters* parameters
) {
    short decrypted_length;
    digest_ctx digest;
    unsigned char* mac_buffer;
    int sequence_number;
    short length;
    CipherSuite* active_suite = &(suites[parameters->suite]);
    unsigned char dec_msg[encrypted_length];
    unsigned char* buffer = dec_msg;

    if (parameters->key_done != 1) {
        decrypted_length = encrypted_length;
        *decrypted_message = malloc(decrypted_length);
        memcpy(*decrypted_message, encrypted_message, encrypted_length);

        return decrypted_length;
    }

    memset(dec_msg, 0, encrypted_length);
    if (active_suite->bulk_decrypt) {
        // tls1.1-1.1:
        // The implicit Initialization Vector (IV) is replaced with an explicit IV to protect against CBC attacks
        // 对于tls1.1以上的版本来说，CBC模式下第一个分组块可以当作秘文来解码，也可以当作明文来存储IV向量
        if (TLS_VERSION_MINOR >= 2) { //第一额分组块当作明文，存储了IV向量
            memcpy(parameters->IV, encrypted_message, active_suite->IV_size);
            encrypted_message += active_suite->IV_size;
            encrypted_length -= active_suite->IV_size;
        }
        active_suite->bulk_decrypt(encrypted_message, encrypted_length, dec_msg, parameters->IV, parameters->key);
        decrypted_length = encrypted_length;
        // Strip off padding
        if (active_suite->block_size) {
            decrypted_length -= dec_msg[encrypted_length - 1] + 1;
        }
        // if (TLS_VERSION_MINOR >= 2) { //第一个分组快当作秘文解码后需要被丢弃
        //     decrypted_length -= active_suite->IV_size;
        //     buffer += active_suite->IV_size;
        // }
        *decrypted_message = malloc(decrypted_length);
        memcpy(*decrypted_message, buffer, decrypted_length);
    } else if (active_suite->aead_decrypt) {
        int nonce_size = active_suite->IV_size - 4;
        unsigned char mac_header[13];
        decrypted_length = encrypted_length - active_suite->block_size;

        if (TLS_VERSION_MINOR >= 2) { //第一块分组块当作明文，存储了8个byte的IV向量
            memcpy(parameters->IV + 4, encrypted_message, nonce_size);
            encrypted_message += nonce_size;
            encrypted_length -= nonce_size;
            decrypted_length -= nonce_size;
        }

        memset(mac_header, 0x0, 13);
        sequence_number = htonl(parameters->seq_num);
        memcpy(mac_header + 4, &sequence_number, sizeof(int));

        memcpy(mac_header + 8, header, 3);
        length = htons(decrypted_length);
        memcpy(mac_header + 11, &length, 2);

        if (active_suite->aead_decrypt(encrypted_message, encrypted_length, dec_msg, parameters->IV, mac_header, 13, parameters->key)) {
            return -1;
        }

        *decrypted_message = malloc(decrypted_length);
        memcpy(*decrypted_message, buffer, decrypted_length);
    } else {
        // Do nothing, no bulk cipher algorithm chosen.
        // Still have to memcpy so that "free" in caller is consistent
        decrypted_length = encrypted_length;
        *decrypted_message = malloc(decrypted_length);
        memcpy(*decrypted_message, encrypted_message, encrypted_length);
    }

    // Now, verify the MAC (if the active cipher suite includes one)
    if (active_suite->new_digest && active_suite->hash_size) {
        active_suite->new_digest(&digest);
        decrypted_length -= (digest.result_size);

        // Allocate enough space for the 8-byte sequence number, the TLSPlainText 
        // header, and the fragment (e.g. the decrypted message).
        mac_buffer = malloc(13 + decrypted_length);
        memset(mac_buffer, 0x0, 13 + decrypted_length);
        sequence_number = htonl(parameters->seq_num);
        memcpy(mac_buffer + 4, &sequence_number, sizeof(int));

        // Copy first three bytes of header; last two bytes reflected the
        // message length, with MAC attached.  Since the MAC was computed
        // by the other side before it was attached (obviously), that MAC
        // was computed using the original length.
        memcpy(mac_buffer + 8, header, 3);
        length = htons(decrypted_length);
        memcpy(mac_buffer + 11, &length, 2);
        memcpy(mac_buffer + 13, *decrypted_message, decrypted_length);

        hmac(&digest, parameters->MAC_secret, digest.result_size, mac_buffer, decrypted_length + 13);

        if (memcmp(digest.hash, (*decrypted_message) + decrypted_length, digest.result_size)) {
            return -1;
        }

        free(mac_buffer);
    }

    return decrypted_length;
}

int tls3_decrypt(
    unsigned char* header,
    unsigned char* encrypted_message,
    short encrypted_length,
    unsigned char** decrypted_message,
    ProtectionParameters* parameters
) {
    short decrypted_length;
    digest_ctx digest;
    unsigned char* mac_buffer;
    int sequence_number;
    short length;
    CipherSuite* active_suite = &(suites[parameters->suite]);
    unsigned char dec_msg[encrypted_length];
    unsigned char* application_iv = parameters->tls3_keys.application_iv ? parameters->tls3_keys.application_iv : parameters->tls3_keys.handshake_iv;
    unsigned char* key = parameters->tls3_keys.application_key ? parameters->tls3_keys.application_key : parameters->tls3_keys.handshake_key;
    unsigned char iv[active_suite->IV_size];

    if (parameters->key_done != 1) {
        decrypted_length = encrypted_length;
        *decrypted_message = malloc(decrypted_length);
        memcpy(*decrypted_message, encrypted_message, encrypted_length);
        return decrypted_length;
    }

    memset(dec_msg, 0, encrypted_length);
    memcpy(iv, application_iv, active_suite->IV_size);
    build_iv(iv, parameters->seq_num);

    if (active_suite->aead_decrypt(encrypted_message, encrypted_length, dec_msg, iv, header, 5, key)) {
        return -1;
    }

    decrypted_length = encrypted_length - active_suite->block_size;
    header[0] = dec_msg[decrypted_length - 1]; //tls3最后一个字节代表了真实record type
    decrypted_length -= 1;
    *decrypted_message = malloc(decrypted_length);
    memcpy(*decrypted_message, dec_msg, decrypted_length);

    return decrypted_length;
}

int tls_decrypt(
    unsigned char* header, // needed for MAC verification
    unsigned char* encrypted_message,
    short encrypted_length,
    unsigned char** decrypted_message,
    ProtectionParameters* parameters
) {
    if (TLS_VERSION_MINOR <= 3) {
        return tls2_decrypt(header, encrypted_message, encrypted_length, decrypted_message, parameters);
    } else {
        return tls3_decrypt(header, encrypted_message, encrypted_length, decrypted_message, parameters);
    }
}
/**
 * Read a TLS packet off of the connection (assuming there's one waiting) and try
 * to update the security parameters based on the type of message received.  If
 * the read times out, or if an alert is received, return an error code; return 0
 * on success.
 * TODO - assert that the message received is of the type expected (for example,
 * if a server hello is expected but not received, this is a fatal error per
 * section 7.3).  returns -1 if an error occurred (this routine will have sent an
 * appropriate alert). Otherwise, return the number of bytes read if the packet
 * includes application data; 0 if the packet was a handshake.  -1 also indicates
 * that an alert was received.
 */
int receive_tls_msg(
    int connection,
    unsigned char* buffer,
    int bufsz,
    TLSParameters* parameters
) {
    TLSPlaintext  message;
    unsigned char* read_pos, * msg_buf, * decrypted_message, * encrypted_message;
    unsigned char header[5];  // size of TLSPlaintext
    int bytes_read, accum_bytes;
    int decrypted_length;

    // STEP 1 - read off the TLS Record layer
    // First, check to see if there's any data left over from a previous read.
    // If there is, pass that back up.
    // This means that if the caller isn't quick about reading available data,
    // TLS alerts can be missed.
    if (parameters->unread_buffer != NULL) {
        decrypted_message = parameters->unread_buffer;
        decrypted_length = parameters->unread_length;
        parameters->unread_buffer = NULL;
        parameters->unread_length = 0;

        message.type = content_application_data;
    } else {
        if (recv(connection, header, 5, 0) <= 0) {
            // No data available; it's up to the caller whether this is an error or not.
            return -1;
        }

        message.type = header[0];
        message.version.major = header[1];
        message.version.minor = header[2];
        memcpy(&message.length, header + 3, 2);
        message.length = htons(message.length);
        encrypted_message = (unsigned char*)malloc(message.length);

        // keep looping & appending until all bytes are accounted for
        accum_bytes = 0;
        msg_buf = encrypted_message;
        while (accum_bytes < message.length) {
            if ((bytes_read = recv(connection, (void*)msg_buf, message.length - accum_bytes, 0)) <= 0) {
                int status;
                perror("While reading a TLS packet");

                if ((status = send_alert_message(connection, illegal_parameter, &parameters->send_parameters))) {
                    free(msg_buf);
                    return status;
                }
                return -1;
            }
            accum_bytes += bytes_read;
            msg_buf += bytes_read;
        }

        printf("recv:%d", message.length);
        printf(",msg_type:%d", message.type);
        if (message.type != content_handshake) {
            printf("\n");
        }
        // show_hex(encrypted_message, message.length, 1);

        // If a cipherspec is active, all of "encrypted_message" will be encrypted.  
        // Must decrypt it before continuing.  This will change the message length 
        // in all cases, since decrypting also involves verifying a MAC (unless the 
        // active cipher spec is NULL_WITH_NULL_NULL).
        decrypted_message = NULL;
        decrypted_length = tls_decrypt(header, encrypted_message, message.length, &decrypted_message, &parameters->recv_parameters);
        message.type = header[0]; //tls3中真实record type藏在数据尾部最后一个字节

        free(encrypted_message);

        if (decrypted_length < 0) {
            send_alert_message(connection, bad_record_mac, &parameters->send_parameters);
            return -1;
        }
        parameters->recv_parameters.seq_num++;
    }

    read_pos = decrypted_message;

    if (message.type == content_handshake) {
        while ((read_pos - decrypted_message) < decrypted_length) {
            Handshake handshake;
            unsigned char* handshake_msg_start = read_pos;

            // Now, read the handshake type and length of the next packet
            // TODO - this fails if the read, above, only got part of the message
            read_pos = read_buffer((void*)&handshake.msg_type, (void*)read_pos, 1);
            handshake.length = read_pos[0] << 16 | read_pos[1] << 8 | read_pos[2];
            read_pos += 3;

            printf(",handshake_type:%d\n", handshake.msg_type);

            // TODO check for negative or unreasonably long length
            // Now, depending on the type, read in and process the packet itself.
            switch (handshake.msg_type) {
            case server_hello: // Client-side messages
                read_pos = parse_server_hello(read_pos, handshake.length, parameters);
                if (read_pos == NULL)  /* error occurred */
                {
                    free(msg_buf);
                    send_alert_message(connection, illegal_parameter, &parameters->send_parameters);
                    return -1;
                }
                break;
            case certificate:
                read_pos = parse_x509_chain(read_pos, handshake.length, &parameters->server_public_key);
                if (read_pos == NULL) {
                    printf("Rejected, bad certificate\n");
                    send_alert_message(connection, bad_certificate, &parameters->send_parameters);
                    return -1;
                }
                break;
            case server_hello_done:
                parameters->server_hello_done = 1;
                break;
            case finished:
            {
                read_pos = parse_finished(read_pos, handshake.length, parameters);
                if (read_pos == NULL) {
                    send_alert_message(connection, illegal_parameter, &parameters->send_parameters);
                    return -1;
                }
            }
            break;
            case client_hello: // Server-side messages
                if (parse_client_hello(read_pos, handshake.length, parameters) == NULL) {
                    send_alert_message(connection, illegal_parameter, &parameters->send_parameters);
                    return -1;
                }
                read_pos += handshake.length;
                break;
            case client_key_exchange:
                read_pos = parse_client_key_exchange(read_pos, handshake.length, parameters);
                if (read_pos == NULL) {
                    send_alert_message(connection, illegal_parameter, &parameters->send_parameters);
                    return -1;
                }
                break;
            default:
                printf("Ignoring unrecognized handshake message %d\n", handshake.msg_type);
                // Silently ignore any unrecognized types per section 6
                // TODO However, out-of-order messages should result in a fatal alert
                // per section 7.4
                read_pos += handshake.length;
                break;
            }
            if (TLS_VERSION_MINOR >= 3) {
                update_digest(&parameters->sha256_handshake_digest, handshake_msg_start, handshake.length + 4);
                update_digest(&parameters->sha384_handshake_digest, handshake_msg_start, handshake.length + 4);
            } else {
                update_digest(&parameters->md5_handshake_digest, handshake_msg_start, handshake.length + 4);
                update_digest(&parameters->sha1_handshake_digest, handshake_msg_start, handshake.length + 4);
            }
        }
    } else if (message.type == content_alert) {
        while ((read_pos - decrypted_message) < decrypted_length) {
            Alert alert;

            read_pos = read_buffer((void*)&alert.level, (void*)read_pos, 1);
            read_pos = read_buffer((void*)&alert.description, (void*)read_pos, 1);

            report_alert(&alert);

            if (alert.level == fatal) {
                return -1;
            }
        }
    } else if (message.type == content_change_cipher_spec) {
        while ((read_pos - decrypted_message) < decrypted_length) {
            unsigned char change_cipher_spec_type;

            read_pos = read_buffer((void*)&change_cipher_spec_type, (void*)read_pos, 1);

            if (change_cipher_spec_type != 1) {
                printf("Error - received message ChangeCipherSpec, but type != 1\n");
                exit(0);
            } else {
                parameters->recv_parameters.seq_num = 0;
                parameters->recv_parameters.key_done = 1;
            }
        }
    } else if (message.type == content_application_data) {
        if (decrypted_length <= bufsz) {
            memcpy(buffer, decrypted_message, decrypted_length);
        } else {
            unsigned char ping[4] = { 0x70, 0x69, 0x6e, 0x67 };
            if (TLS_VERSION_MINOR >= 4 && !memcmp(decrypted_message, ping, 4)) {
                parameters->peer_ping = 1;
            } else {
                memcpy(buffer, decrypted_message, bufsz);
                parameters->unread_length = decrypted_length - bufsz;
                parameters->unread_buffer = malloc(parameters->unread_length);
                memcpy(parameters->unread_buffer, decrypted_message + bufsz, parameters->unread_length);
                decrypted_length = bufsz;
            }

        }
    } else {
        // Ignore content types not understood, per section 6 of the RFC.
        printf("Ignoring non-recognized content type %d\n", message.type);
    }

    free(decrypted_message);

    return decrypted_length;
}

int tls_connect(int connection, TLSParameters* parameters) {
    init_parameters(parameters);
    parameters->connection_end = connection_end_client;
    new_md5_digest(&parameters->md5_handshake_digest);
    new_sha1_digest(&parameters->sha1_handshake_digest);
    new_sha256_digest(&parameters->sha256_handshake_digest);
    new_sha384_digest(&parameters->sha384_handshake_digest);

    // Step 1. Send the TLS handshake "client hello" message
    if (send_client_hello(connection, parameters) < 0) {
        perror("Unable to send client hello");
        return 1;
    }

    // Step 2. Receive the server hello response
    parameters->server_hello_done = 0;
    while (!parameters->server_hello_done) {
        if (receive_tls_msg(connection, NULL, 0, parameters) < 0) {
            perror("Unable to receive server hello");
            return 2;
        }
    }

    // Step 3. Send client key exchange, change cipher spec (7.1) and encrypted 
    // handshake message
    if (!(send_client_key_exchange(connection, parameters))) {
        perror("Unable to send client key exchange");
        return 3;
    }

    if (!(send_change_cipher_spec(connection, parameters))) {
        perror("Unable to send client change cipher spec");
        return 4;
    }

    // This message will be encrypted using the newly negotiated keys
    if (!(send_finished(connection, parameters))) {
        perror("Unable to send client finished");
        return 5;
    }

    parameters->peer_finished = 0;
    while (!parameters->peer_finished) {
        if (receive_tls_msg(connection, NULL, 0, parameters) < 0) {
            perror("Unable to receive server finished");
            return 6;
        }
    }

    return 0;
}

int tls2_accept(int connection, TLSParameters* parameters) {
    int is_resume = 0;

    // The client sends the first message
    parameters->got_client_hello = 0;
    while (!parameters->got_client_hello) {
        if (receive_tls_msg(connection, NULL, 0, parameters) < 0) {
            perror("Unable to receive client hello");
            send_alert_message(connection, handshake_failure, &parameters->send_parameters);
            return 1;
        }
    }

#ifdef USE_SESSION_TICKET
    is_resume = parameters->session_ticket_length > 0 ? 1 : 0;
#else
#ifdef USE_SESSION_ID
    is_resume = parameters->session_id_length > 0 ? 1 : 0;
#endif
#endif

    if (send_server_hello(connection, parameters)) {
        send_alert_message(connection, handshake_failure, &parameters->send_parameters);
        return 2;
    }

    if (is_resume) {
        printf("master_secret:");
        show_hex(parameters->master_secret, MASTER_SECRET_LENGTH, 1);

        calculate_keys(parameters);
        if (!(send_change_cipher_spec(connection, parameters))) {
            perror("Unable to send client change cipher spec");
            send_alert_message(connection, handshake_failure, &parameters->send_parameters);
            return 6;
        }

        if (!(send_finished(connection, parameters))) {
            perror("Unable to send client finished");
            send_alert_message(connection, handshake_failure, &parameters->send_parameters);
            return 7;
        }

        parameters->peer_finished = 0;
        while (!parameters->peer_finished) {
            if (receive_tls_msg(connection, NULL, 0, parameters) < 0) {
                perror("Unable to receive client finished");
                send_alert_message(connection, handshake_failure, &parameters->send_parameters);
                return 5;
            }
        }
    } else {
        if (send_certificate(connection, parameters)) {
            send_alert_message(connection, handshake_failure, &parameters->send_parameters);
            return 3;
        }

        if (send_server_key_exchange(connection, parameters)) {
            send_alert_message(connection, handshake_failure, &parameters->send_parameters);
            return 2;
        }

        if (send_server_hello_done(connection, parameters)) {
            send_alert_message(connection, handshake_failure, &parameters->send_parameters);
            return 4;
        }

        parameters->peer_finished = 0;
        while (!parameters->peer_finished) {
            if (receive_tls_msg(connection, NULL, 0, parameters) < 0) {
                perror("Unable to receive client finished");
                send_alert_message(connection, handshake_failure, &parameters->send_parameters);
                return 5;
            }
        }

#ifdef USE_SESSION_TICKET
        if (parameters->session_ticket_length == 0) {
            send_server_session_ticket(connection, parameters);
        }
#endif
        if (!(send_change_cipher_spec(connection, parameters))) {
            perror("Unable to send client change cipher spec");
            send_alert_message(connection, handshake_failure, &parameters->send_parameters);
            return 6;
        }

        if (!(send_finished(connection, parameters))) {
            perror("Unable to send client finished");
            send_alert_message(connection, handshake_failure, &parameters->send_parameters);
            return 7;
        }

#ifdef USE_SESSION_ID
        remember_session(parameters);
#endif
    }

    // Handshake is complete; now ready to start sending encrypted data
    return 0;
    }

int tls3_accept(int connection, TLSParameters* parameters) {
    // The client sends the first message
    parameters->got_client_hello = 0;
    while (!parameters->got_client_hello) {
        if (receive_tls_msg(connection, NULL, 0, parameters) < 0) {
            perror("Unable to receive client hello");
            send_alert_message(connection, handshake_failure, &parameters->send_parameters);
            return 1;
        }
    }

    if (send_server_hello(connection, parameters)) {
        send_alert_message(connection, handshake_failure, &parameters->send_parameters);
        return 2;
    }

    if (!(send_change_cipher_spec(connection, parameters))) {
        perror("Unable to send client change cipher spec");
        send_alert_message(connection, handshake_failure, &parameters->send_parameters);
        return 3;
    }

    if (send_encrypted_extensions(connection, parameters)) {
        perror("Unable to send encrypted extensions");
        send_alert_message(connection, handshake_failure, &parameters->send_parameters);
        return 4;
    }

    if (send_certificate(connection, parameters)) {
        send_alert_message(connection, handshake_failure, &parameters->send_parameters);
        return 5;
    }

    if ((send_server_certificate_verify(connection, parameters))) {
        perror("Unable to send certificate_verify");
        send_alert_message(connection, handshake_failure, &parameters->send_parameters);
        return 6;
    }

    if (!(send_finished(connection, parameters))) {
        perror("Unable to send client finished");
        send_alert_message(connection, handshake_failure, &parameters->send_parameters);
        return 7;
    }

    parameters->peer_finished = 0;
    while (!parameters->peer_finished) {
        if (receive_tls_msg(connection, NULL, 0, parameters) < 0) {
            perror("Unable to receive client finished");
            send_alert_message(connection, handshake_failure, &parameters->send_parameters);
            return 8;
        }
    }

    parameters->peer_ping = 0;
    while (!parameters->peer_ping) {
        if (receive_tls_msg(connection, NULL, 0, parameters) < 0) {
            perror("Unable to receive client ping");
            send_alert_message(connection, handshake_failure, &parameters->send_parameters);
            return 9;
        }
    }

    send_server_pong(connection, parameters);

    return 0;
}

int tls_accept(int connection, TLSParameters* parameters) {
    init_parameters(parameters);
    parameters->connection_end = connection_end_server;

    new_md5_digest(&parameters->md5_handshake_digest);
    new_sha1_digest(&parameters->sha1_handshake_digest);
    new_sha256_digest(&parameters->sha256_handshake_digest);
    new_sha384_digest(&parameters->sha384_handshake_digest);

    if (TLS_VERSION_MINOR <= 3) {
        return tls2_accept(connection, parameters);
    } else {
        return tls3_accept(connection, parameters);
    }
}

int tls_send(int connection,
    unsigned char* application_data,
    int length,
    int options,
    TLSParameters* parameters
) {
    send_message(connection, content_application_data, application_data, length, &parameters->send_parameters);
    return length;
}

int tls_recv(int connection, unsigned char* target_buffer, int buffer_size, int options,
    TLSParameters* parameters) {
    int bytes_decrypted = 0;

    bytes_decrypted = receive_tls_msg(connection, target_buffer, buffer_size, parameters);

    return bytes_decrypted;
}

void free_protection_parameters(ProtectionParameters* parameters) {
    if (parameters->MAC_secret) {
        free(parameters->MAC_secret);
    }
    if (parameters->key) {
        free(parameters->key);
    }
    if (parameters->IV) {
        free(parameters->IV);
    }
    if (parameters->tls3_keys.handshake_key) {
        free(parameters->tls3_keys.handshake_key);
    }
    if (parameters->tls3_keys.handshake_iv) {
        free(parameters->tls3_keys.handshake_iv);
    }
    if (parameters->tls3_keys.finished_key) {
        free(parameters->tls3_keys.finished_key);
    }
    if (parameters->tls3_keys.application_key) {
        free(parameters->tls3_keys.application_key);
    }
    if (parameters->tls3_keys.application_iv) {
        free(parameters->tls3_keys.application_iv);
    }
}

int tls_shutdown(int connection, TLSParameters* parameters) {
    send_alert_message(connection, close_notify, &parameters->send_parameters);
    if (parameters->unread_buffer) {
        free(parameters->unread_buffer);
    }
    if (parameters->session_ticket) {
        free(parameters->session_ticket);
    }
    if (parameters->session_id) {
        free(parameters->session_id);
    }
    if (parameters->handshake_secret) {
        free(parameters->handshake_secret);
    }
    free_protection_parameters(&parameters->send_parameters);
    free_protection_parameters(&parameters->recv_parameters);

    return 1;
}
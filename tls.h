#ifndef TLS_H
#define TLS_H

#include "digest.h"
#include "x509.h"
#include "dh.h"

#define EXPORT_RSA_BITS 512

typedef enum {
	TLS_NULL_WITH_NULL_NULL = 0x0000,
	TLS_RSA_WITH_NULL_MD5 = 0x0001,
	TLS_RSA_WITH_NULL_SHA = 0x0002,
	TLS_RSA_EXPORT_WITH_RC4_40_MD5 = 0x0003,
	TLS_RSA_WITH_RC4_128_MD5 = 0x0004,
	TLS_RSA_WITH_RC4_128_SHA = 0x0005,
	TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = 0x0006,
	TLS_RSA_WITH_IDEA_CBC_SHA = 0x0007,
	TLS_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x0008,
	TLS_RSA_WITH_DES_CBC_SHA = 0x0009,
	TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000A,
	TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA = 0x000B,
	TLS_DH_DSS_WITH_DES_CBC_SHA = 0x000C,
	TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = 0x000D,
	TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x000E,
	TLS_DH_RSA_WITH_DES_CBC_SHA = 0x000F,
	TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = 0x0010,
	TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = 0x0011,
	TLS_DHE_DSS_WITH_DES_CBC_SHA = 0x0012,
	TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0x0013,
	TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x0014,
	TLS_DHE_RSA_WITH_DES_CBC_SHA = 0x0015,
	TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x0016,
	TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 = 0x0017,
	TLS_DH_anon_WITH_RC4_128_MD5 = 0x0018,
	TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA = 0x0019,
	TLS_DH_anon_WITH_DES_CBC_SHA = 0x001A,
	TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = 0x001B,

	// 1C & 1D were used by SSLv3 to describe Fortezza suites
	// End of list of algorithms defined by RFC 2246

	// These are all defined in RFC 4346 (v1.1), not 2246 (v1.0)
	TLS_KRB5_WITH_DES_CBC_SHA = 0x001E,
	TLS_KRB5_WITH_3DES_EDE_CBC_SHA = 0x001F,
	TLS_KRB5_WITH_RC4_128_SHA = 0x0020,
	TLS_KRB5_WITH_IDEA_CBC_SHA = 0x0021,
	TLS_KRB5_WITH_DES_CBC_MD5 = 0x0022,
	TLS_KRB5_WITH_3DES_EDE_CBC_MD5 = 0x0023,
	TLS_KRB5_WITH_RC4_128_MD5 = 0x0024,
	TLS_KRB5_WITH_IDEA_CBC_MD5 = 0x0025,
	TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA = 0x0026,
	TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA = 0x0027,
	TLS_KRB5_EXPORT_WITH_RC4_40_SHA = 0x0028,
	TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 = 0x0029,
	TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 = 0x002A,
	TLS_KRB5_EXPORT_WITH_RC4_40_MD5 = 0x002B,

	// TLS_AES ciphersuites - RFC 3268
	TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F,
	TLS_DH_DSS_WITH_AES_128_CBC_SHA = 0x0030,
	TLS_DH_RSA_WITH_AES_128_CBC_SHA = 0x0031,
	TLS_DHE_DSS_WITH_AES_128_CBC_SHA = 0x0032,
	TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033,
	TLS_DH_anon_WITH_AES_128_CBC_SHA = 0x0034,
	TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,
	TLS_DH_DSS_WITH_AES_256_CBC_SHA = 0x0036,
	TLS_DH_RSA_WITH_AES_256_CBC_SHA = 0x0037,
	TLS_DHE_DSS_WITH_AES_256_CBC_SHA = 0x0038,
	TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039,
	TLS_DH_anon_WITH_AES_256_CBC_SHA = 0x003A,

	// tls1.2 - GCM
	TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009C,
	TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009D,

	// tsl1.3
	TLS_AES_128_GCM_SHA256 = 0x1301,
	TLS_AES_256_GCM_SHA384 = 0x1302,

	// tls1.2 - ECC
	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = 0xC004,
	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = 0xC005,

	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xC009,
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xC00A,

	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = 0xC00E,
	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = 0xC00F,

	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xC013,
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xC014,

	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xC028,

	MAX_SUPPORTED_CIPHER_SUITE = 0xFFFF
} CipherSuiteIdentifier;


typedef	void (*encrypt_func)(unsigned char* plaintext, int plaintext_len, unsigned char ciphertext[], void* iv, unsigned char* key);
typedef	void (*decrypt_func)(unsigned char* ciphertext, int ciphertext_len, unsigned char plaintext[], void* iv, unsigned char* key);
typedef	int  (*aead_encrypt_func)(unsigned char* plaintext, int plaintext_len, unsigned char ciphertext[], void* iv, unsigned char* add, int addLen, unsigned char* key);
typedef	int  (*aead_decrypt_func)(unsigned char* ciphertext, int ciphertext_len, unsigned char plaintext[], void* iv, unsigned char* add, int addLen, unsigned char* key);


typedef struct {
	CipherSuiteIdentifier id;

	int    min_version;
	int    block_size;
	int    IV_size;
	int    key_size;
	int    hash_size;

	encrypt_func bulk_encrypt;
	decrypt_func bulk_decrypt;
	void (*new_digest)(digest_ctx* context);

	aead_encrypt_func aead_encrypt;
	aead_decrypt_func aead_decrypt;

}
CipherSuite;

typedef struct {
	unsigned char* handshake_key;
	unsigned char* handshake_iv;
	unsigned char* finished_key;
	unsigned char* application_key;
	unsigned char* application_iv;
	unsigned char* early_data_key;
	unsigned char* early_data_iv;
	unsigned char* resumption_master_secret;
}
Tls3Keys;

typedef struct {
	unsigned char* MAC_secret;
	unsigned char* key;
	unsigned char* IV;
	CipherSuiteIdentifier suite;
	unsigned long  seq_num;
	Tls3Keys tls3_keys;
	int key_done; //密钥是否协商完成
}
ProtectionParameters;

#define TLS_VERSION_MAJOR 3
#define TLS_VERSION_MINOR 4

#define MASTER_SECRET_LENGTH  48
typedef unsigned char master_secret_type[MASTER_SECRET_LENGTH];

#define RANDOM_LENGTH 32
typedef unsigned char random_type[RANDOM_LENGTH];

typedef enum { connection_end_client, connection_end_server } ConnectionEnd;

typedef struct {
	ConnectionEnd         connection_end;
	master_secret_type    master_secret;
	random_type           client_random;
	random_type           server_random;

	ProtectionParameters  send_parameters;
	ProtectionParameters  recv_parameters;

	// RSA public key, if supplied
	public_key_info       server_public_key;

	// DH public key, if supplied (either in a certificate or ephemerally)
	// Note that a server can legitimately have an RSA key for signing and 
	// a DH key for key exchange (e.g. DHE_RSA)
	dh_key                server_dh_key;
	huge				  key_share;

	int                   got_client_hello;
	int                   server_hello_done;
	int                   peer_finished;
	int                   peer_early_data;

	digest_ctx            md5_handshake_digest;
	digest_ctx            sha1_handshake_digest;
	digest_ctx            sha256_handshake_digest;
	digest_ctx            sha384_handshake_digest;
	int					  session_id_length;
	int					  session_ticket_length;
	int                   unread_length;
	int                   early_data_length;
	unsigned char* session_ticket;
	unsigned char* session_id;
	unsigned char* unread_buffer;
	unsigned char* handshake_secret;
	unsigned char* tls3_master_secret;
	unsigned char* tls3_psk_secret;
	unsigned char* early_data;
}
TLSParameters;

/** This lists the type of higher-level TLS protocols that are defined */
typedef enum {
	content_change_cipher_spec = 20,
	content_alert = 21,
	content_handshake = 22,
	content_application_data = 23
}
ContentType;

typedef enum { warning = 1, fatal = 2 } AlertLevel;

/**
 * Enumerate all of the error conditions specified by TLS.
 */
typedef enum {
	close_notify = 0,
	unexpected_message = 10,
	bad_record_mac = 20,
	decryption_failed = 21,
	record_overflow = 22,
	decompression_failure = 30,
	handshake_failure = 40,
	bad_certificate = 42,
	unsupported_certificate = 43,
	certificate_revoked = 44,
	certificate_expired = 45,
	certificate_unknown = 46,
	illegal_parameter = 47,
	unknown_ca = 48,
	access_denied = 49,
	decode_error = 50,
	decrypt_error = 51,
	export_restriction = 60,
	protocol_version = 70,
	insufficient_security = 71,
	internal_error = 80,
	user_canceled = 90,
	no_renegotiation = 100
}
AlertDescription;

typedef struct {
	unsigned char level;
	unsigned char description;
}
Alert;

typedef struct {
	unsigned char major, minor;
}
ProtocolVersion;

/**
 * Each packet to be encrypted is first inserted into one of these structures.
 */
typedef struct {
	unsigned char   type;
	ProtocolVersion version;
	unsigned short  length;
}
TLSPlaintext;

typedef struct {
	unsigned int  gmt_unix_time;
	unsigned char  random_bytes[28];
}
Random;

/**
 * Handshake message types (section 7.4)
 */
typedef enum {
	hello_request = 0,
	client_hello = 1,
	server_hello = 2,
	session_ticket = 4,
	end_of_early_data = 5,
	encrypted_extensions = 8,
	certificate = 11,
	server_key_exchange = 12,
	certificate_request = 13,
	server_hello_done = 14,
	certificate_verify = 15,
	client_key_exchange = 16,
	finished = 20
}
HandshakeType;

/**
 * Handshake record definition (section 7.4)
 */
typedef struct {
	unsigned char         msg_type;
	unsigned int        length;       // 24 bits(!)
}
Handshake;

/**
 * Section 7.4.1.2
 */
typedef struct {
	ProtocolVersion client_version;
	Random random;
	unsigned char session_id_length;
	unsigned char* session_id;
	unsigned short cipher_suites_length;
	unsigned short* cipher_suites;
	unsigned char compression_methods_length;
	unsigned char* compression_methods;
}
ClientHello;

typedef struct {
	ProtocolVersion   server_version;
	Random            random;
	unsigned char     session_id_length;
	unsigned char     session_id[32]; // technically, this len should be dynamic.
	unsigned short    cipher_suite;
	unsigned char     compression_method;
}
ServerHello;

/**
 * Negotiate an TLS channel on an already-established connection
 * (or die trying).
 * @return 1 if successful, 0 if not.
 */
int tls_connect(int connection, TLSParameters* parameters);

int tls_accept(int connection, TLSParameters* parameters);

/**
 * Send data over an established TLS channel.  tls_connect must already
 * have been called with this socket as a parameter.
 */
int tls_send(int connection,
	unsigned char* application_data,
	int length,
	int options,
	TLSParameters* parameters
);
/**
 * Received data from an established TLS channel.
 */
int tls_recv(int connection,
	unsigned char* target_buffer,
	int buffer_size,
	int options,
	TLSParameters* parameters
);

/**
 * Orderly shutdown of the TLS channel (note that the socket itself will
 * still be open after this is called).
 */
int tls_shutdown(int connection, TLSParameters* parameters);

#endif

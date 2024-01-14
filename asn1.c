#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "base64.h"
#include "asn1.h"
#include "hex.h"

#define check_asn_len(length) if((length)<=0){break;}

static char* tag_names[] = {
    "BER",          // 0
    "BOOLEAN",        // 1
    "INTEGER",        // 2
    "BIT STRING",       // 3
    "OCTET STRING",      // 4
    "NULL",          // 5
    "OBJECT IDENTIFIER",   // 6
    "ObjectDescriptor",    // 7
    "INSTANCE OF, EXTERNAL", // 8
    "REAL",          // 9
    "ENUMERATED",       // 10
    "EMBEDDED PPV",      // 11
    "UTF8String",       // 12
    "RELATIVE-OID",      // 13
    "undefined(14)",     // 14
    "undefined(15)",     // 15
    "SEQUENCE, SEQUENCE OF", // 16
    "SET, SET OF",      // 17
    "NumericString",     // 18
    "PrintableString",    // 19
    "TeletexString, T61String", // 20
    "VideotexString",     // 21
    "IA5String",       // 22
    "UTCTime",        // 23
    "GeneralizedTime",    // 24
    "GraphicString",     // 25
    "VisibleString, ISO64String", // 26
    "GeneralString",     // 27
    "UniversalString",    // 28
    "CHARACTER STRING",    // 29
    "BMPString"        // 30
};

int asn1parse(
    unsigned char* buffer,
    int length,
    struct asn1struct* top_level_token
) {
    unsigned int byte_len = 0;
    unsigned int tag = 0;
    unsigned long tag_len = 0;
    unsigned char* start;
    struct asn1struct* token;

    token = top_level_token;
    token->children = NULL;
    token->next = NULL;

    while (length > 0) {
        start = buffer;
        tag = *buffer;
        buffer++;
        length--;
        check_asn_len(length);

        if ((tag & 0x1f) == 0x1f) {
            tag = 0;
        }

        tag_len = *buffer;
        buffer++;
        length--;
        check_asn_len(length + 1); //此处length可以为0，内容可能为NULL

        if (tag_len & 0x80) {
            int len_byte = tag_len & 0x7f;
            tag_len = 0;
            if (len_byte) { //长编码
                while (len_byte > 0 && length > 0) {
                    tag_len <<= 8;
                    tag_len |= *buffer;
                    buffer++;
                    length--;
                    len_byte--;
                }
                check_asn_len(length + 1); //此处length可以为0，内容可能为NULL
            } else { //不定长度
                break;
            }
        }

        token->constructed = tag & 0x20;
        token->tag_class = (tag & 0xc0) >> 6;
        token->tag = tag & 0x1f;
        token->length = tag_len;
        token->data = buffer;

        if (tag & 0x20) { //复合类型
            token->length += buffer - start;
            if (tag_len > length) { //解析错误
                return 0;
            }
            token->children = (struct asn1struct*)malloc(sizeof(struct asn1struct));
            asn1parse(buffer, tag_len, token->children);
        }

        buffer += tag_len;
        length -= tag_len;

        if (length > 0) {
            token->next = (struct asn1struct*)malloc(sizeof(struct asn1struct));
            token = token->next;
        }

    }
    return 0;
}

void asn1free(struct asn1struct* node) {
    if (!node) {
        return;
    }

    asn1free(node->children);
    free(node->children);
    asn1free(node->next);
    free(node->next);
}

void asn1show(int depth, struct asn1struct* certificate) {
    struct asn1struct* token = certificate;

    while (token) {
        for (int i = 0; i < depth; i++) {
            printf(" ");
        }
        switch (token->tag_class) {
        case ASN1_CLASS_UNIVERSAL:
            printf("%s", tag_names[token->tag]);
            break;
        case ASN1_CLASS_APPLICATION:
            printf("application");
            break;
        case ASN1_CONTEXT_SPECIFIC:
            printf("context");
            break;
        case ASN1_PRIVATE:
            printf("private");
            break;
        }
        printf(" (%d:%d) ", token->tag, token->length);
        if (token->tag_class == ASN1_CLASS_UNIVERSAL) {
            switch (token->tag) {
            case ASN1_INTEGER:
                break;
            case ASN1_BIT_STRING:
            case ASN1_OCTET_STRING:
            case ASN1_OBJECT_IDENTIFIER:
            {
                for (int i = 0; i < token->length; i++) {
                    printf("%.02x ", token->data[i]);
                }
            }
            break;
            case ASN1_NUMERIC_STRING:
            case ASN1_PRINTABLE_STRING:
            case ASN1_TELETEX_STRING:
            case ASN1_VIDEOTEX_STRING:
            case ASN1_IA5_STRING:
            case ASN1_UTC_TIME:
            case ASN1_GENERALIZED_TIME:
            case ASN1_GRAPHIC_STRING:
            case ASN1_VISIBLE_STRING:
            case ASN1_GENERAL_STRING:
            case ASN1_UNIVERSAL_STRING:
            case ASN1_CHARACTER_STRING:
            case ASN1_BMP_STRING:
            case ASN1_UTF8_STRING:
            {
                char* str_val = (char*)malloc(token->length + 1);
                strncpy(str_val, (char*)token->data, token->length);
                str_val[token->length] = 0;
                printf(" %s", str_val);
                free(str_val);
            }
            break;
            default:
                break;
            }
        }

        printf("\n");
        if (token->children) {
            asn1show(depth + 1, token->children);
        }
        token = token->next;
    }
}

int pem_decode(unsigned char* pem_buffer, unsigned char* der_buffer) {
    int size = 0;
    if (strncmp((const char*)pem_buffer, "-----BEGIN", 10)) {
        printf("pem_decode fail\n"); //不是PEM格式文件
        return 0;
    }
    pem_buffer = (unsigned char*)strchr((const char*)pem_buffer, '\n') + 1;
    while (strncmp((const char*)pem_buffer, "-----END", 8)) {
        unsigned char* end = (unsigned char*)strchr((const char*)pem_buffer, '\n');
        int len = end - pem_buffer;
        if (*(end - 1) == '\r') { //兼容\r\n
            len--;
        }
        // show_hex(pem_buffer, len, 1);
        len = base64_decode(pem_buffer, len, der_buffer);
        // show_hex(der_buffer, len, 1);
        pem_buffer = end + 1;
        der_buffer += len;
        size += len;
    }

    return size;
}

#define TEST_ASN1
#ifdef TEST_ASN1
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
int main() {
    struct stat certificate_file_stat;
    int certificate_file = open("/Users/lisong/Downloads/rootCA.crt", O_RDONLY);
    fstat(certificate_file, &certificate_file_stat);

    unsigned char* pem_buffer = (unsigned char*)malloc(certificate_file_stat.st_size);
    read(certificate_file, (void*)pem_buffer, certificate_file_stat.st_size);

    unsigned char* buffer = (unsigned char*)malloc(certificate_file_stat.st_size);
    int buffer_size = pem_decode(pem_buffer, buffer);
    // show_hex(pem_buffer, certificate_file_stat.st_size, 1);
    // show_hex(buffer, buffer_size, 1);

    struct asn1struct certificate;
    asn1parse(buffer, buffer_size, &certificate);
    asn1show(0, &certificate);
    asn1free(&certificate);
}
#endif
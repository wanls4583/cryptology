#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "hkdf.h"
#include "sha.h"
#include "hmac.h"
#include "hex.h"

void HKDF_extract(
    unsigned char* salt, int salt_len,
    unsigned char* key, int key_len,
    unsigned char* PRK,
    digest_ctx ctx
) {
    digest_ctx tmp;
    copy_digest(&tmp, &ctx);

    hmac(&tmp, salt, salt_len, key, key_len);
    memcpy(PRK, tmp.hash, tmp.result_size);
    free_digest(&tmp);

    // printf("PRK:");
    // show_hex(PRK, tmp.result_size, 1);
}

void HKDF_expand(
    unsigned char* key, int key_len,
    unsigned char* info, int info_len,
    unsigned char* out, int out_len,
    digest_ctx ctx
) {
    digest_ctx tmp;

    unsigned char T[ctx.result_size];
    unsigned char data[ctx.result_size + info_len + 1];
    unsigned char* buffer;

    memset(T, 0, ctx.result_size);
    memset(data, 0, ctx.result_size + info_len + 1);

    int i = 1;
    while (out_len > 0) {
        copy_digest(&tmp, &ctx);
        buffer = data;
        if (i > 1) {
            memcpy(data, T, ctx.result_size);
            buffer += ctx.result_size;
        }
        memcpy(buffer, info, info_len);
        buffer += info_len;
        buffer[0] = i;
        buffer += 1;

        hmac(&tmp, key, key_len, data, (int)(buffer - data));
        memcpy(T, tmp.hash, ctx.result_size);
        memcpy(out, T, out_len > ctx.result_size ? ctx.result_size : out_len);
        out += ctx.result_size;
        out_len -= ctx.result_size;
        i++;
    }

    free_digest(&tmp);
}

// HKDF-Expand-Label(Secret, Label, Context, Length) = HKDF-Expand(Secret, HkdfLabel, Length)
// Where HkdfLabel is specified as:
// struct {
//     uint16 length = Length;
//     opaque label<7..255> = "tls13 " + Label;
//     opaque context<0..255> = Context;
// } HkdfLabel;
void HKDF_expand_label(
    unsigned char* secret, int secret_len,
    unsigned char* label, int label_len,
    unsigned char* context, int context_len,
    unsigned char* out, int out_len,
    digest_ctx ctx
) {
    int hkdf_label_len = 2 + 1 + 6 + label_len + 1 + context_len;
    unsigned char hkdf_label[hkdf_label_len];
    unsigned char* buffer = hkdf_label;
    int s_len = htons(out_len);

    memcpy(buffer, &s_len, 2);
    buffer += 2;
    buffer[0] = 6 + label_len;
    buffer += 1;
    memcpy(buffer, (void*)"tls13 ", 6);
    buffer += 6;
    memcpy(buffer, label, label_len);
    buffer += label_len;
    buffer[0] = context_len;
    buffer += 1;
    memcpy(buffer, context, context_len);

    // printf("hkdf_label:");
    // show_hex(hkdf_label, hkdf_label_len, 1);

    HKDF_expand(secret, secret_len, hkdf_label, hkdf_label_len, out, out_len, ctx);
}

void derive_secret(
    unsigned char* secret, int secret_len,
    unsigned char* label, int label_len,
    unsigned char* message, int message_len,
    unsigned char* out, int out_len,
    digest_ctx ctx
) {
    digest_ctx tmp;
    copy_digest(&tmp, &ctx);

    digest_hash(&tmp, message, message_len);
    HKDF_expand_label(secret, secret_len, label, label_len, tmp.hash, tmp.result_size, out, out_len, ctx);

    free_digest(&tmp);
}

void HKDF(
    unsigned char* key, int key_len,
    unsigned char* salt, int salt_len,
    unsigned char* info, int info_len,
    unsigned char* out, int out_len,
    digest_ctx ctx
) {
    unsigned char PRK[ctx.result_size];

    HKDF_extract(salt, salt_len, key, key_len, PRK, ctx);
    HKDF_expand(PRK, sizeof(PRK), info, info_len, out, out_len, ctx);
}

#define TEST_HKDF
#ifdef TEST_HKDF
#include "digest.h"
#include "sha.h"
#include "aes.h"

void test1() {
    unsigned char* key, * salt, * info;
    unsigned char out[1000];
    int key_len, salt_len, info_len;
    digest_ctx ctx;
    new_sha256_digest(&ctx);

    key_len = hex_decode((unsigned char*)"0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", &key);
    salt_len = hex_decode((unsigned char*)"0x000102030405060708090a0b0c", &salt);
    info_len = hex_decode((unsigned char*)"0xf0f1f2f3f4f5f6f7f8f9", &info);

    HKDF(key, key_len, salt, salt_len, info, info_len, out, 42, ctx);
    // 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
    show_hex(out, 42, 1);

    key_len = hex_decode((unsigned char*)"0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f", &key);
    salt_len = hex_decode((unsigned char*)"0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf", &salt);
    info_len = hex_decode((unsigned char*)"0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", &info);

    HKDF(key, key_len, salt, salt_len, info, info_len, out, 82, ctx);
    // b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87
    show_hex(out, 82, 1);

    key_len = hex_decode((unsigned char*)"0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", &key);

    HKDF(key, key_len, NULL, 0, NULL, 0, out, 42, ctx);
    // 8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8
    show_hex(out, 42, 1);
}

void build_iv(unsigned char* iv, uint64_t seq) {
    size_t i;
    for (i = 0; i < 8; i++) {
        iv[12 - 1 - i] ^= ((seq >> (i * 8)) & 0xFF);
    }
}

void enc_and_dec(unsigned char* data, int data_len, unsigned char* server_handshake_key, unsigned char* server_handshake_iv, int seq_num) {
    unsigned char header[5] = { 0x17, 0x03, 0x03, 0x00, 0x00 };
    unsigned short len = htons(data_len + 16);
    memcpy(header + 3, &len, 2);
    len = data_len + 16;

    unsigned char iv[12];
    unsigned char* encrypted_message = (unsigned char*)malloc(len);

    memcpy(iv, server_handshake_iv, 12);
    build_iv(iv, seq_num);
    aes_256_gcm_encrypt(data, data_len, encrypted_message, iv, header, 5, server_handshake_key);
    printf("encrypt:");
    show_hex(encrypted_message, len, 1);

    unsigned char dec_msg[data_len];
    int encrypted_length = len;
    int decrypted_length = data_len;

    memset(dec_msg, 0, data_len);
    memcpy(iv, server_handshake_iv, 12);
    build_iv(iv, seq_num);
    aes_256_gcm_decrypt(encrypted_message, encrypted_length, dec_msg, iv, header, 5, server_handshake_key);
    printf("decrypt:");
    show_hex(dec_msg, sizeof(dec_msg), 1);
}

void test2() {
    int share_secret_len = 0;
    unsigned char* tmp;
    unsigned char hs_data[10000] = { 0 };
    unsigned char* hs_buffer = hs_data;
    int hs_len = 0;

    digest_ctx ctx;
    new_sha384_digest(&ctx);

    char client_hello[] = "010000f40303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000813021303130100ff010000a30000001800160000136578616d706c652e756c666865696d2e6e6574000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000016000000170000000d001e001c040305030603080708080809080a080b080408050806040105010601002b0003020304002d00020101003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254";
    char server_hello[] = "020000760303707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff130200002e002b0002030400330024001d00209fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b615";
    unsigned char* hello = (unsigned char*)malloc(strlen(client_hello) + strlen(server_hello) + 2);
    int hello_len = 0;
    memcpy(hello, (void*)"0x", 2);
    memcpy(hello + 2, client_hello, strlen(client_hello));
    memcpy(hello + 2 + strlen(client_hello), server_hello, strlen(server_hello));
    hello_len = hex_decode(hello, &tmp);
    hello = tmp;
    memcpy(hs_buffer, hello, hello_len);
    hs_buffer += hello_len;
    hs_len += hello_len;

    unsigned char* shared_secret;
    unsigned char zero_key[ctx.result_size];
    unsigned char early_secret[ctx.result_size];
    unsigned char derived_secret[ctx.result_size];
    unsigned char handshake_secret[ctx.result_size];
    unsigned char client_handshake_traffic_secret[ctx.result_size];
    unsigned char server_handshake_traffic_secret[ctx.result_size];
    unsigned char client_handshake_key[32];
    unsigned char server_handshake_key[32];
    unsigned char client_handshake_iv[12];
    unsigned char server_handshake_iv[12];
    unsigned char client_finished_key[48];
    unsigned char server_finished_key[48];

    share_secret_len = hex_decode((unsigned char*)"0xdf4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624", &shared_secret);
    memset(zero_key, 0, ctx.result_size);

    HKDF_extract(NULL, 0, zero_key, ctx.result_size, early_secret, ctx);
    printf("early_secret:");
    // 7ee8206f5570023e6dc7519eb1073bc4e791ad37b5c382aa10ba18e2357e716971f9362f2c2fe2a76bfd78dfec4ea9b5
    show_hex(early_secret, ctx.result_size, 1);

    derive_secret(early_secret, ctx.result_size, (unsigned char*)"derived", 7, NULL, 0, derived_secret, ctx.result_size, ctx);
    printf("derived_secret:");
    // 1591dac5cbbf0330a4a84de9c753330e92d01f0a88214b4464972fd668049e93e52f2b16fad922fdc0584478428f282b
    show_hex(derived_secret, ctx.result_size, 1);

    HKDF_extract(derived_secret, ctx.result_size, shared_secret, share_secret_len, handshake_secret, ctx);
    printf("handshake_secret:");
    // bdbbe8757494bef20de932598294ea65b5e6bf6dc5c02a960a2de2eaa9b07c929078d2caa0936231c38d1725f179d299
    show_hex(handshake_secret, ctx.result_size, 1);

    derive_secret(handshake_secret, ctx.result_size, (unsigned char*)"c hs traffic", 12, hello, hello_len, client_handshake_traffic_secret, ctx.result_size, ctx);
    printf("client_handshake_traffic_secret:");
    // db89d2d6df0e84fed74a2288f8fd4d0959f790ff23946cdf4c26d85e51bebd42ae184501972f8d30c4a3e4a3693d0ef0
    show_hex(client_handshake_traffic_secret, ctx.result_size, 1);

    derive_secret(handshake_secret, ctx.result_size, (unsigned char*)"s hs traffic", 12, hello, hello_len, server_handshake_traffic_secret, ctx.result_size, ctx);
    printf("server_handshake_traffic_secret:");
    // 23323da031634b241dd37d61032b62a4f450584d1f7f47983ba2f7cc0cdcc39a68f481f2b019f9403a3051908a5d1622
    show_hex(server_handshake_traffic_secret, ctx.result_size, 1);

    HKDF_expand_label(client_handshake_traffic_secret, ctx.result_size, (unsigned char*)"key", 3, NULL, 0, client_handshake_key, 32, ctx);
    printf("client_handshake_key:");
    // 1135b4826a9a70257e5a391ad93093dfd7c4214812f493b3e3daae1eb2b1ac69
    show_hex(client_handshake_key, 32, 1);

    HKDF_expand_label(server_handshake_traffic_secret, ctx.result_size, (unsigned char*)"key", 3, NULL, 0, server_handshake_key, 32, ctx);
    printf("server_handshake_key:");
    // 9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f
    show_hex(server_handshake_key, 32, 1);

    HKDF_expand_label(client_handshake_traffic_secret, ctx.result_size, (unsigned char*)"iv", 2, NULL, 0, client_handshake_iv, 12, ctx);
    printf("client_handshake_iv:");
    // 4256d2e0e88babdd05eb2f27
    show_hex(client_handshake_iv, 12, 1);

    HKDF_expand_label(server_handshake_traffic_secret, ctx.result_size, (unsigned char*)"iv", 2, NULL, 0, server_handshake_iv, 12, ctx);
    printf("server_handshake_iv:");
    // 9563bc8b590f671f488d2da3
    show_hex(server_handshake_iv, 12, 1);

    HKDF_expand_label(client_handshake_traffic_secret, ctx.result_size, (unsigned char*)"finished", 8, NULL, 0, client_finished_key, 48, ctx);
    printf("client_finished_key:");
    // 096d2782cdc1e9493ebba79c892a60bc14179584ab4679d834e1daef44b522a614bb61b98d27d78e2f85dac2e4beedfb
    show_hex(client_finished_key, 48, 1);

    HKDF_expand_label(server_handshake_traffic_secret, ctx.result_size, (unsigned char*)"finished", 8, NULL, 0, server_finished_key, 48, ctx);
    printf("server_finished_key:");
    // 23e073033202055ca66455ecde694079e5197a6bdff80d65b4c1e934d0f8e7f5f187ed32a86e1d10918bca30d289f796
    show_hex(server_finished_key, 48, 1);

    unsigned char* data;
    int data_len = 0;

    // server_encrypted_extensions
    printf("\nserver_encrypted_extensions:\n");
    data_len = hex_decode((unsigned char*)"0x08000002000016", &data);
    memcpy(hs_buffer, data, data_len - 1);
    hs_buffer += data_len - 1;
    hs_len += data_len - 1;
    // 6be02f9da7c2dc9ddef56f2468b90adfa25101ab0344ae
    enc_and_dec(data, data_len, server_handshake_key, server_handshake_iv, 0);

    // server_certificate
    printf("\nserver_certificate:\n");
    data_len = hex_decode((unsigned char*)"0x0b00032e0000032a0003253082032130820209a0030201020208155a92adc2048f90300d06092a864886f70d01010b05003022310b300906035504061302555331133011060355040a130a4578616d706c65204341301e170d3138313030353031333831375a170d3139313030353031333831375a302b310b3009060355040613025553311c301a060355040313136578616d706c652e756c666865696d2e6e657430820122300d06092a864886f70d01010105000382010f003082010a0282010100c4803606bae7476b089404eca7b691043ff792bc19eefb7d74d7a80d001e7b4b3a4ae60fe8c071fc73e7024c0dbcf4bdd11d396bba70464a13e94af83df3e10959547bc955fb412da3765211e1f3dc776caa53376eca3aecbec3aab73b31d56cb6529c8098bcc9e02818e20bf7f8a03afd1704509ece79bd9f39f1ea69ec47972e830fb5ca95de95a1e60422d5eebe527954a1e7bf8a86f6466d0d9f16951a4cf7a04692595c1352f2549e5afb4ebfd77a37950144e4c026874c653e407d7d23074401f484ffd08f7a1fa05210d1f4f0d5ce79702932e2cabe701fdfad6b4bb71101f44bad666a11130fe2ee829e4d029dc91cdd6716dbb9061886edc1ba94210203010001a3523050300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030206082b06010505070301301f0603551d23041830168014894fde5bcc69e252cf3ea300dfb197b81de1c146300d06092a864886f70d01010b05000382010100591645a69a2e3779e4f6dd271aba1c0bfd6cd75599b5e7c36e533eff3659084324c9e7a504079d39e0d42987ffe3ebdd09c1cf1d914455870b571dd19bdf1d24f8bb9a11fe80fd592ba0398cde11e2651e618ce598fa96e5372eef3d248afde17463ebbfabb8e4d1ab502a54ec0064e92f7819660d3f27cf209e667fce5ae2e4ac99c7c93818f8b2510722dfed97f32e3e9349d4c66c9ea6396d744462a06b42c6d5ba688eac3a017bddfc8e2cfcad27cb69d3ccdca280414465d3ae348ce0f34ab2fb9c618371312b191041641c237f11a5d65c844f0404849938712b959ed685bc5c5dd645ed19909473402926dcb40e3469a15941e8e2cca84bb6084636a0000016", &data);
    memcpy(hs_buffer, data, data_len - 1);
    hs_buffer += data_len - 1;
    hs_len += data_len - 1;
    // baf00a9be50f3f2307e726edcbdacbe4b18616449d46c6207af6e9953ee5d2411ba65d31feaf4f78764f2d693987186cc01329c187a5e4608e8d27b318e98dd94769f7739ce6768392caca8dcc597d77ec0d1272233785f6e69d6f43effa8e7905edfdc4037eee5933e990a7972f206913a31e8d04931366d3d8bcd6a4a4d647dd4bd80b0ff863ce3554833d744cf0e0b9c07cae726dd23f9953df1f1ce3aceb3b7230871e92310cfb2b098486f43538f8e82d8404e5c6c25f66a62ebe3c5f26232640e20a769175ef83483cd81e6cb16e78dfad4c1b714b04b45f6ac8d1065ad18c13451c9055c47da300f93536ea56f531986d6492775393c4ccb095467092a0ec0b43ed7a0687cb470ce350917b0ac30c6e5c24725a78c45f9f5f29b6626867f6f79ce054273547b36df030bd24af10d632dba54fc4e890bd0586928c0206ca2e28e44e227a2d5063195935df38da8936092eef01e84cad2e49d62e470a6c7745f625ec39e4fc23329c79d1172876807c36d736ba42bb69b004ff55f93850dc33c1f98abb92858324c76ff1eb085db3c1fc50f74ec04442e622973ea70743418794c388140bb492d6294a0540e5a59cfae60ba0f14899fca71333315ea083a68e1d7c1e4cdc2f56bcd6119681a4adbc1bbf42afd806c3cbd42a076f545dee4e118d0b396754be2b042a685dd4727e89c0386a94d3cd6ecb9820e9d49afeed66c47e6fc243eabebbcb0b02453877f5ac5dbfbdf8db1052a3c994b224cd9aaaf56b026bb9efa2e01302b36401ab6494e7018d6e5b573bd38bcef023b1fc92946bbca0209ca5fa926b4970b1009103645cb1fcfe552311ff730558984370038fd2cce2a91fc74d6f3e3ea9f843eed356f6f82d35d03bc24b81b58ceb1a43ec9437e6f1e50eb6f555e321fd67c8332eb1b832aa8d795a27d479c6e27d5a61034683891903f66421d094e1b00a9a138d861e6f78a20ad3e1580054d2e305253c713a02fe1e28deee7336246f6ae34331806b46b47b833c39b9d31cd300c2a6ed831399776d07f570eaf0059a2c68a5f3ae16b617404af7b7231a4d942758fc020b3f23ee8c15e36044cfd67cd640993b16207597fbf385ea7a4d99e8d456ff83d41f7b8b4f069b028a2a63a919a70e3a10e3084158faa5bafa30186c6b2f238eb530c73e
    enc_and_dec(data, data_len, server_handshake_key, server_handshake_iv, 1);

    // server_certificate_verify
    printf("\nserver_certificate_verify:\n");
    data_len = hex_decode((unsigned char*)"0x0f000104080401005cbb24c0409332daa920bbabbdb9bd50170be49cfbe0a4107fca6ffb1068e65f969e6de7d4f9e56038d67c69c031403a7a7c0bcc8683e65721a0c72cc6634019ad1d3ad265a812615ba36380372084f5daec7e63d3f4933f27227419a611034644dcdbc7be3e74ffac473faaadde8c2fc65f3265773e7e62de33861fa705d19c506e896c8d82f5bcf35fece259b71538115e9c8cfba62e49bb8474f58587b11b8ae317c633e9c76c791d466284ad9c4ff735a6d2e963b59bbca440a307091a1b4e46bcc7a2f9fb2f1c898ecb19918be4121d7e8ed04cd50c9a59e987980107bbbf299c232e7fdbe10a4cfdae5c891c96afdff94b54ccd2bc19d3cdaa6644859c16", &data);
    memcpy(hs_buffer, data, data_len - 1);
    hs_buffer += data_len - 1;
    hs_len += data_len - 1;
    // 73719fce07ec2f6d3bba0292a0d40b2770c06a271799a53314f6f77fc95c5fe7b9a4329fd9548c670ebeea2f2d5c351dd9356ef2dcd52eb137bd3a676522f8cd0fb7560789ad7b0e3caba2e37e6b4199c6793b3346ed46cf740a9fa1fec414dc715c415c60e575703ce6a34b70b5191aa6a61a18faff216c687ad8d17e12a7e99915a611bfc1a2befc15e6e94d784642e682fd17382a348c301056b940c9847200408bec56c81ea3d7217ab8e85a88715395899c90587f72e8ddd74b26d8edc1c7c837d9f2ebbc260962219038b05654a63a0b12999b4a8306a3ddcc0e17c53ba8f9c80363f7841354d291b4ace0c0f330c0fcd5aa9deef969ae8ab2d98da88ebb6ea80a3a11f00ea296a3232367ff075e1c66dd9cbedc4713
    enc_and_dec(data, data_len, server_handshake_key, server_handshake_iv, 2);

    unsigned char server_hs_hash[ctx.result_size];
    digest_hash(&ctx, hs_data, hs_len);
    memcpy(server_hs_hash, ctx.hash, ctx.result_size);
    new_sha384_digest(&ctx);
    printf("\nserver_hs_hash:");
    // e50a22307719ae4a157cebd424331b060490c351244e15d8d6375518a74c555b0ebca6a7929e6acfc4845d4f6ec0b9b9
    show_hex(server_hs_hash, ctx.result_size, 1);

    unsigned char server_verify_data[ctx.result_size];
    hmac(&ctx, server_finished_key, ctx.result_size, server_hs_hash, ctx.result_size);
    memcpy(server_verify_data, ctx.hash, ctx.result_size);
    new_sha384_digest(&ctx);
    printf("server_verify_data:");
    // 7e30eeccb6b23be6c6ca363992e842da877ee64715ae7fc0cf87f9e5032182b5bb48d1e33f9979055a160c8dbbb1569c
    show_hex(server_verify_data, ctx.result_size, 1);

    // server_handshake_finished
    printf("\nserver_handshake_finished:\n");
    data_len = 4 + ctx.result_size + 1;
    data = (unsigned char*)malloc(data_len);
    memset(data, 0, data_len);
    data[0] = 0x14;
    data[3] = ctx.result_size;
    data[data_len - 1] = 0x16;
    memcpy(data + 4, server_verify_data, ctx.result_size);
    memcpy(hs_buffer, data, data_len - 1);
    hs_buffer += data_len - 1;
    hs_len += data_len - 1;
    // 140000307e30eeccb6b23be6c6ca363992e842da877ee64715ae7fc0cf87f9e5032182b5bb48d1e33f9979055a160c8dbbb1569c16
    enc_and_dec(data, data_len, server_handshake_key, server_handshake_iv, 2);

    unsigned char master_secret[ctx.result_size];
    unsigned char client_application_traffic_secret[ctx.result_size];
    unsigned char server_application_traffic_secret[ctx.result_size];
    unsigned char client_application_key[32];
    unsigned char server_application_key[32];
    unsigned char client_application_iv[12];
    unsigned char server_application_iv[12];

    derive_secret(handshake_secret, ctx.result_size, (unsigned char*)"derived", 7, NULL, 0, derived_secret, ctx.result_size, ctx);
    printf("\nderived_secret:");
    // be3a8cdfcd10e46d3fe5d2902568518993ae43f2fb7c5438cde4776d1bc220242041a83f388266fd07b0177bf29e9486
    show_hex(derived_secret, ctx.result_size, 1);

    HKDF_extract(derived_secret, ctx.result_size, zero_key, ctx.result_size, master_secret, ctx);
    printf("master_secret:");
    // 2931209e1b7840e16d0d6bfd4bda1102f3a984f1162dc450f9606654f45bd55d9cb8857a8d14b59b98d7250fee55d3c3
    show_hex(master_secret, ctx.result_size, 1);

    derive_secret(master_secret, ctx.result_size, (unsigned char*)"c ap traffic", 12, hs_data, hs_len, client_application_traffic_secret, ctx.result_size, ctx);
    printf("client_application_traffic_secret:");
    // 9e47af27cb60d818a9ea7d233cb5ed4cc525fcd74614fb24b0ee59acb8e5aa7ff8d88b89792114208fec291a6fa96bad
    show_hex(client_application_traffic_secret, ctx.result_size, 1);

    derive_secret(master_secret, ctx.result_size, (unsigned char*)"s ap traffic", 12, hs_data, hs_len, server_application_traffic_secret, ctx.result_size, ctx);
    printf("server_application_traffic_secret:");
    // 86c967fd7747a36a0685b4ed8d0e6b4c02b4ddaf3cd294aa44e9f6b0183bf911e89a189ba5dfd71fccffb5cc164901f8
    show_hex(server_application_traffic_secret, ctx.result_size, 1);

    HKDF_expand_label(client_application_traffic_secret, ctx.result_size, (unsigned char*)"key", 3, NULL, 0, client_application_key, 32, ctx);
    printf("client_application_key:");
    // de2f4c7672723a692319873e5c227606691a32d1c59d8b9f51dbb9352e9ca9cc
    show_hex(client_application_key, 32, 1);

    HKDF_expand_label(server_application_traffic_secret, ctx.result_size, (unsigned char*)"key", 3, NULL, 0, server_application_key, 32, ctx);
    printf("server_application_key:");
    // 01f78623f17e3edcc09e944027ba3218d57c8e0db93cd3ac419309274700ac27
    show_hex(server_application_key, 32, 1);

    HKDF_expand_label(client_application_traffic_secret, ctx.result_size, (unsigned char*)"iv", 2, NULL, 0, client_application_iv, 12, ctx);
    printf("client_application_iv:");
    // bb007956f474b25de902432f
    show_hex(client_application_iv, 12, 1);

    HKDF_expand_label(server_application_traffic_secret, ctx.result_size, (unsigned char*)"iv", 2, NULL, 0, server_application_iv, 12, ctx);
    printf("server_application_iv:");
    // 196a750b0c5049c0cc51a541
    show_hex(server_application_iv, 12, 1);

    unsigned char client_hs_hash[ctx.result_size];
    digest_hash(&ctx, hs_data, hs_len);
    memcpy(client_hs_hash, ctx.hash, ctx.result_size);
    new_sha384_digest(&ctx);
    printf("\nclient_hs_hash:");
    // fa6800169a6baac19159524fa7b9721b41be3c9db6f3f93fa5ff7e3db3ece204d2b456c51046e40ec5312c55a86126f5
    show_hex(client_hs_hash, ctx.result_size, 1);

    unsigned char client_verify_data[ctx.result_size];
    hmac(&ctx, client_finished_key, ctx.result_size, client_hs_hash, ctx.result_size);
    memcpy(client_verify_data, ctx.hash, ctx.result_size);
    new_sha384_digest(&ctx);
    printf("client_verify_data:");
    // bff56a671b6c659d0a7c5dd18428f58bdd38b184a3ce342d9fde95cbd5056f7da7918ee320eab7a93abd8f1c02454d27
    show_hex(client_verify_data, ctx.result_size, 1);

    // client_handshake_finished
    printf("\nclient_handshake_finished:\n");
    data_len = 4 + ctx.result_size + 1;
    data = (unsigned char*)malloc(data_len);
    memset(data, 0, data_len);
    data[0] = 0x14;
    data[3] = ctx.result_size;
    data[data_len - 1] = 0x16;
    memcpy(data + 4, client_verify_data, ctx.result_size);
    memcpy(hs_buffer, data, data_len - 1);
    hs_buffer += data_len - 1;
    hs_len += data_len - 1;
    // 9ff9b063175177322a46dd9896f3c3bb820ab51743ebc25fdadd53454b73deb54cc7248d411a18bccf657a960824e9a19364837c350a69a88d4bf635c85eb874aebc9dfde8
    enc_and_dec(data, data_len, client_handshake_key, client_handshake_iv, 0);

    // client_application_data
    printf("\nclient_application_data:\n");
    data_len = hex_decode((unsigned char*)"0x70696e6717", &data);
    // 828139cb7b73aaabf5b82fbf9a2961bcde10038a32
    enc_and_dec(data, data_len, client_application_key, client_application_iv, 0);

    // server_application_data
    printf("\nserver_application_data:\n");
    data_len = hex_decode((unsigned char*)"0x706f6e6717", &data);
    // 0cda85f1447ae23fa66d56f4c5408482b1b1d4c998
    // enc_and_dec(data, data_len, server_application_key, server_application_iv, 2);
    // 4c42e2abb32a3378837169e86584a161f735d77a44
    enc_and_dec(data, data_len, server_application_key, server_application_iv, 0);
}

int main() {
    // test1();
    test2();

    return 0;
}
#endif
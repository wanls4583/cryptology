#include "base64.h"

static char* base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static int unbase64[] =
{
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, 52,
	53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, 0, -1, -1, -1,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1,
	26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
	42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, -1
};

void base64_encode(unsigned char* input, int len, unsigned char* output) {
	unsigned char c = 0;
	int i = 0, j = 0, end;

	while (i <= len - 3) {
		output[j++] = (input[i] & 0xfc) >> 2;
		output[j++] = (input[i] & 0x03) << 4 | (input[i + 1] & 0xf0) >> 4;
		output[j++] = (input[i + 1] & 0x0f) << 2 | (input[i + 2] & 0xc0) >> 6;
		output[j++] = input[i + 2] & 0x3f;
		i += 3;
	}

	end = j;
	len -= i;

	if (len == 1) {
		output[j++] = (input[i] & 0xfc) >> 2;
		output[j++] = ((input[i] & 0x03) << 4);
		end = j;
		output[j++] = '=';
		output[j++] = '=';
	} else if (len == 2) {
		output[j++] = (input[i] & 0xfc) >> 2;
		output[j++] = ((input[i] & 0x03) << 4) | ((input[i + 1] & 0xf0) >> 4);
		output[j++] = (input[i + 1] & 0x0f) << 2;
		end = j;
		output[j++] = '=';
	}

	for (i = 0; i < end; i++) {
		output[i] = base64[output[i]];
	}

	output[j] = 0;
}

int base64_decode(unsigned char* input, int len, unsigned char* output) {
	int i = 0, j = 0;
	while (i < len - 4) {
		output[j++] = unbase64[input[i]] << 2 | (unbase64[input[i + 1]] & 0xf0) >> 4;
		output[j++] = (unbase64[input[i + 1]] & 0x0f) << 4 | (unbase64[input[i + 2]] & 0xfc) >> 2;
		output[j++] = (unbase64[input[i + 2]] & 0x03) << 6 | unbase64[input[i + 3]];
		i += 4;
	}
	if (input[len - 1] == '=') {
		if (input[len - 2] == '=') {
			output[j++] = unbase64[input[i]] << 2 | (unbase64[input[i + 1]] & 0xf0) >> 4;
		} else {
			output[j++] = unbase64[input[i]] << 2 | (unbase64[input[i + 1]] & 0xf0) >> 4;
			output[j++] = (unbase64[input[i + 1]] & 0x0f) << 4 | (unbase64[input[i + 2]] & 0xfc) >> 2;
		}
	} else {
		output[j++] = unbase64[input[i]] << 2 | (unbase64[input[i + 1]] & 0xf0) >> 4;
		output[j++] = (unbase64[input[i + 1]] & 0x0f) << 4 | (unbase64[input[i + 2]] & 0xfc) >> 2;
		output[j++] = (unbase64[input[i + 2]] & 0x03) << 6 | unbase64[input[i + 3]];
	}
	output[j] = 0;

	return j;
}

// #define TEST_BASE64
#ifdef TEST_BASE64
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
int main() {
	unsigned char* s1[] = {
		(unsigned char*)"a",
		(unsigned char*)"ab",
		(unsigned char*)"abc",
		(unsigned char*)"abcd"
	};
	unsigned char enc[100];
	unsigned char dec[100];

	for (int i = 0; i < 4; i++) {
		memset(enc, 0, 100);
		base64_encode(s1[i], strlen((char*)s1[i]), enc);
		printf("%s\n", enc);

		memset(dec, 0, 100);
		base64_decode(enc, strlen((char*)enc), dec);
		printf("%s\n", dec);
	}

	return 0;
}
#endif

typedef u_int32_t huge_word;
#define huge_hton htonl
#define HUGE_WORD_BYTES (sizeof(huge_word))
#define HUGE_WORD_BITS (HUGE_WORD_BYTES*8)
#define HUGE_WORD_MAX ((u_int64_t)4294967296)
#define HUGE_WORD_HIGH_BIT 0x80000000
typedef struct huge {
    int size;
    int sign;
    huge_word* rep;
} huge;

int  huge_compare(huge* a, huge* b);
void huge_set(huge* h, unsigned int val);
void huge_copy(huge* a, huge* b);
void huge_load(huge* h, unsigned char* c, int length);
void huge_unload(huge* h, unsigned char* c, int length);
void huge_load_words(huge* h, huge_word* words, int length);
void huge_unload_words(huge* h, huge_word* words, int length);
void huge_free(huge* h);
void huge_swap(huge* a, huge* b);
void huge_contract(huge* h);
void huge_left_shift(huge* h, int size);
void huge_right_shift(huge* h, int size);
void huge_add(huge* a, huge* b);
void huge_subtract(huge* a, huge* b);
void huge_multiply_word(huge* a, huge_word word);
void huge_multiply(huge* a, huge* b);
void huge_divide(huge* dividend, huge* divisor, huge* quotient);
void huge_mod_pow(huge* a, huge* e, huge* n);
void huge_inverse_mul(huge* h, huge* p);
void huge_inverse_neg(huge* h, huge* p);
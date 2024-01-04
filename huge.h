
typedef u_int32_t u_word;
#define WORD_BYTES (sizeof(u_word))
#define WORD_BITS (WORD_BYTES*8)
#define WORD_MAX 4294967296
#define WORD_HIGH_BIT 0x80000000
typedef struct huge {
    int size;
    int sign;
    u_word* rep;
} huge;

int compare(huge* a, huge* b);
void set_huge(huge* h, unsigned int val);
void copy_huge(huge* a, huge* b);
void load_huge(huge* h, unsigned char* c, int length);
void load_words(huge* h, u_word* words, int length);
void unload_huge(huge* h, u_word* words, int length);
void free_huge(huge* h);
void swap_huge_rep(huge* a, huge* b);
void contract(huge* h);
void left_shift(huge* h, int size);
void right_shift(huge* h, int size);
void add(huge* a, huge* b);
void subtract(huge* a, huge* b);
void multiply(huge* a, huge* b);
void mod_pow(huge* a, huge* e, huge* n);
void divide(huge* dividend, huge* divisor, huge* quotient);
void inv(huge* h, huge* p);
void negativeInv(huge* h, huge* p);
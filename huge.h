typedef struct huge {
    int size;
    int sign;
    unsigned char* rep;
} huge;

int compare(huge* a, huge* b);
void set_huge(huge* h, unsigned int val);
void copy_huge(huge* a, huge* b);
void load_huge(huge* h, unsigned char* c, int length);
void unload_huge(huge* h, unsigned char* bytes, int length);
void free_huge(huge* h);
void swap_huge_rep(huge* a, huge* b);
void contract(huge* h);
void left_shift(huge* h);
void right_shift(huge* h);
void add(huge* a, huge* b);
void subtract(huge* a, huge* b);
void multiply( huge *a, huge *b );
void mod_pow( huge *a, huge *e, huge *n);
void divide( huge *dividend, huge *divisor, huge *quotient );
void inv(huge* h, huge* p);
void negativeInv(huge* h, huge* p);
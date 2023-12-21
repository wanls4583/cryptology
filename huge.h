typedef struct huge {
    int size;
    int sign;
    unsigned char* rep;
} huge;

int compare(huge* a, huge* b);
void copy_huge(huge* a, huge* b);
void load_huge(huge* h, unsigned char* c, int length);
void unload_huge(huge* h, unsigned char* bytes, int length);
void free_huge(huge* h);
void swap_huge_rep(huge* a, huge* b);
void contract(huge* h);
void add(huge* a, huge* b);
void subtract(huge* a, huge* b);
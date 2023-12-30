#ifndef DIGEST_H
#define DIGEST_H

int digest_hash(
  unsigned char* input,
  int len,
  unsigned int* hash,
  void (*block_operate)(const unsigned char* input, unsigned int hash[]),
  void (*block_finalize)(unsigned char* block, int length),
  int digest_block_size,
  int digest_input_block_size
);

typedef struct {
  int digest_block_size;
  int digest_input_block_size;
  int word_size;

  unsigned int* hash;
  unsigned long long* hash_64;
  int hash_len;
  int hash_result_len;
  unsigned int input_len;

  void (*block_operate)(const unsigned char* input, unsigned int hash[]);
  void (*block_finalize)(unsigned char* block, int length);

  // Temporary storage
  unsigned char* block;
  int block_len;
}
digest_ctx;

void update_digest(digest_ctx* context, const unsigned char* input, int input_len);
void finalize_digest(digest_ctx* context);

#endif

#ifndef DIGEST_H
#define DIGEST_H

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
  void (*block_operate_512)(const unsigned char* input, unsigned long long hash[]);
  void (*block_finalize)(unsigned char* block, int length);

  // Temporary storage
  unsigned char* block;
  int block_len;
}
digest_ctx;

int digest_hash(digest_ctx* context, unsigned char* input, int len);
void update_digest(digest_ctx* context, unsigned char* input, int input_len);
void finalize_digest(digest_ctx* context);

#endif

#ifndef DIGEST_H
#define DIGEST_H

typedef struct {
  int digest_block_size;
  int digest_input_block_size;
  int word_size;

  void* hash;
  int hash_len;
  int hash_result_len;
  unsigned int input_len;

  void (*block_operate)(const unsigned char* input, void * hash);
  void (*block_finalize)(unsigned char* block, int length);

  // Temporary storage
  unsigned char* block;
  int block_len;
}
digest_ctx;

typedef void (*block_operate)(const unsigned char* input, void * hash);

int digest_hash(digest_ctx* context, unsigned char* input, int len);
void update_digest(digest_ctx* context, unsigned char* input, int input_len);
void finalize_digest(digest_ctx* context);

#endif

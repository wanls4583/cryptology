#ifndef DIGEST_H
#define DIGEST_H

typedef u_int64_t u64;
typedef u_int32_t u32;
typedef u_int8_t u8;

typedef struct {
  int digest_block_size;
  int digest_input_block_size;

  void* hash;
  unsigned char* input;
  int hash_size;
  int word_size;
  int result_size;
  u32 input_len;

  void (*block_operate)(const u8* input, void* hash);
  void (*block_finalize)(u8* block, int length);

  // Temporary storage
  u8* block;
  int block_len;
}
digest_ctx;

typedef void (*block_operate)(const u8* input, void* hash);

void show_hash(void* hash, int result_size);
int digest_hash(digest_ctx* context, u8* input, int len);
void update_digest(digest_ctx* context, u8* input, int input_len);
void finalize_digest(digest_ctx* context);
void copy_digest(digest_ctx* target, digest_ctx* src);
void free_digest(digest_ctx* ctx);

#endif

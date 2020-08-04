#pragma once
#include <stdint.h>

#define MGM_128_BLOCK_SIZE 16
#define MGM_128_KEY_SIZE 32
#define ROUNDS 10
#define MGM_128_DEPLOYED_KEY_SIZE (ROUNDS * MGM_128_BLOCK_SIZE)
#define MGM_128_CTX_SIZE 309
#define ENCRYPT 1
#define DECRYPT 2

extern const uint8_t permutation[256]; //use in REF_MODE
extern const uint8_t linear[MGM_128_BLOCK_SIZE]; //use in REF_MODE
extern const uint8_t iter_const[512] __attribute__((aligned(16)));

//bitmask used in SSE mode
extern const uint8_t bitmask[MGM_128_BLOCK_SIZE] __attribute__((aligned(16)));

extern const uint8_t tableLS[MGM_128_BLOCK_SIZE*256*MGM_128_BLOCK_SIZE] __attribute__((aligned(16)));

typedef struct {
    uint8_t key[MGM_128_KEY_SIZE];
    uint8_t deployedKey[MGM_128_DEPLOYED_KEY_SIZE];
    uint8_t gamma[MGM_128_BLOCK_SIZE];
    uint8_t gammaCounter[MGM_128_BLOCK_SIZE];
    uint8_t macCounter[MGM_128_BLOCK_SIZE];
    uint64_t macHash[2];
    uint8_t lastBlock[MGM_128_BLOCK_SIZE];
    uint8_t nonce[MGM_128_BLOCK_SIZE];
    uint64_t dataSize;
    uint64_t associatedSize;
    uint32_t unusedGamma;
    uint8_t mode; //1 == encrypt, 2 == decrypt
} MGM128Ctx;

MGM128Ctx *mgm_128_ctx_create_init(uint8_t key[MGM_128_KEY_SIZE], uint8_t nonce[MGM_128_BLOCK_SIZE]);
void mgm_128_ctx_clean(MGM128Ctx *ctx);
int mgm_128_update_associated(MGM128Ctx *ctx, const uint8_t *associated, uint64_t size);
int mgm_128_encrypt(MGM128Ctx *ctx, uint8_t *in, uint8_t *out, uint64_t size);
int mgm_128_decrypt(MGM128Ctx *ctx, uint8_t *in, uint8_t *out, uint64_t size);
int mgm_128_finalize(MGM128Ctx *ctx, uint8_t mac[MGM_128_BLOCK_SIZE]);

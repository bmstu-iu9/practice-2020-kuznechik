#include "mgm128.h"
#include <memory.h>
#include <stdlib.h>

#ifdef SSE_MODE
#include "mgm128_sse.h"
#elif defined (NEON_MODE)
#include "mgm128_neon.h"
#else
#include "mgm128_ref.h"
#endif

#define MIN(x, y) ((x)<(y) ? (x) : (y))

static void mgm_128_deploy_key(MGM128Ctx *ctx) {
    memcpy(ctx->deployedKey, ctx->key, MGM_128_KEY_SIZE);
    uint8_t key0[MGM_128_BLOCK_SIZE];
    uint8_t key1[MGM_128_BLOCK_SIZE];
    for (uint8_t i = 0; i < 4; i++) {
        memcpy(key0, &ctx->deployedKey[MGM_128_BLOCK_SIZE*2*i], MGM_128_BLOCK_SIZE);
        memcpy(key1, &ctx->deployedKey[MGM_128_BLOCK_SIZE*2*i + MGM_128_BLOCK_SIZE], MGM_128_BLOCK_SIZE);
        for (uint8_t j = 0; j < 8; j++) {
           func_F(&iter_const[MGM_128_BLOCK_SIZE*8*i + MGM_128_BLOCK_SIZE*j], key0, key1);
        }
        memcpy(&ctx->deployedKey[MGM_128_BLOCK_SIZE*2*(i+1)], key0, MGM_128_BLOCK_SIZE);
        memcpy(&ctx->deployedKey[MGM_128_BLOCK_SIZE*2*(i+1) + MGM_128_BLOCK_SIZE], key1, MGM_128_BLOCK_SIZE);
    }
}

static void mgm_128_generate_next_encrypt_block(MGM128Ctx *ctx, uint8_t *inBuf,
                                                      uint8_t *outBuf)
{
    //ecnrypt part
    mgm_128_encrypt_block(ctx->deployedKey, ctx->gammaCounter, ctx->gamma);
    func_X(outBuf, inBuf, ctx->gamma);
    //mac part
    mgm_128_generate_next_mac_block(ctx, outBuf);
}

static void mgm_128_generate_next_decrypt_block(MGM128Ctx *ctx, uint8_t *inBuf,
                                                      uint8_t *outBuf)
{
    //mac part
    mgm_128_generate_next_mac_block(ctx, inBuf);
    //decrypt part
    mgm_128_encrypt_block(ctx->deployedKey, ctx->gammaCounter, ctx->gamma);
    func_X(outBuf, inBuf, ctx->gamma);
}

static int mgm_128_update(MGM128Ctx *ctx, uint8_t *plain,
                              uint8_t *cipher, uint64_t bufSize)
{
    uint8_t *inBuf;
    uint8_t *outBuf;
    void (*update_block)(MGM128Ctx *, uint8_t *, uint8_t *);

    if(!(ctx->mode == DECRYPT || ctx->mode == ENCRYPT))
    {
        return -1;
    }

    if (ctx->mode == ENCRYPT) {
        inBuf = plain;
        outBuf = cipher;
        update_block = &mgm_128_generate_next_encrypt_block;
    } else {
        inBuf = cipher;
        outBuf = plain;
        update_block = &mgm_128_generate_next_decrypt_block;
    }

    ctx->dataSize += bufSize;

    //ctx->gammaCounter contains current encrypt block-counter
    //processing the last-first data block
    if (ctx->unusedGamma > 0) {
        uint64_t firstBlockSize = MIN(bufSize, ctx->unusedGamma);
        memcpy(&ctx->lastBlock[MGM_128_BLOCK_SIZE - ctx->unusedGamma], inBuf, firstBlockSize);
        inBuf += firstBlockSize;
        bufSize -= firstBlockSize;
        //calculate first block, that contains unused part
        //ecnrypt part
        for (uint8_t i = 0;i < firstBlockSize; i++) {
            outBuf[i] = ctx->lastBlock[MGM_128_BLOCK_SIZE-ctx->unusedGamma + i] ^ ctx->gamma[MGM_128_BLOCK_SIZE-ctx->unusedGamma + i];
        }
        if (ctx->mode == ENCRYPT) {
            memcpy(&ctx->lastBlock[MGM_128_BLOCK_SIZE-ctx->unusedGamma], outBuf, firstBlockSize);
        }

        if (ctx->unusedGamma > firstBlockSize) {
            ctx->unusedGamma -= firstBlockSize;
            return  0;
        }

        //mac part
        mgm_128_generate_next_mac_block(ctx, ctx->lastBlock);
        outBuf += ctx->unusedGamma;
        ctx->unusedGamma = 0;
        incr_right(ctx->gammaCounter); //Y_(i-1) --->Y_i
    }

    uint8_t remainder = bufSize % MGM_128_BLOCK_SIZE;
    uint64_t buf128Size = bufSize / MGM_128_BLOCK_SIZE;

    for (uint64_t i = 0; i < buf128Size; i++) {
        update_block(ctx, inBuf, outBuf);
        incr_right(ctx->gammaCounter); //Y_(i-1) --->Y_i
        inBuf += MGM_128_BLOCK_SIZE;
        outBuf += MGM_128_BLOCK_SIZE;
    }

    //last block part
    if (remainder) {
        ctx->unusedGamma = MGM_128_BLOCK_SIZE - remainder;
        if (ctx->mode == DECRYPT) {
            //save encrypted last block for mac before decryption
            memcpy(ctx->lastBlock, inBuf, remainder);
        }
        //ecnrypt part
        mgm_128_encrypt_block(ctx->deployedKey, ctx->gammaCounter, ctx->gamma);
        for (uint8_t j = 0; j < remainder; j++) {
            outBuf[j] = inBuf[j] ^ ctx->gamma[j];
        }
        if (ctx->mode == ENCRYPT) {
            //save encrypted last block for mac after ecnryption
            memcpy(ctx->lastBlock, outBuf, remainder);
        }
    }

    return 0;
}

static void mgm_128_prepare(MGM128Ctx *ctx) {
    memcpy(ctx->macCounter, ctx->nonce, MGM_128_BLOCK_SIZE);
    ctx->macCounter[0] = ctx->macCounter[0] | 0x80; // == 1 || N
    mgm_128_encrypt_block(ctx->deployedKey, ctx->macCounter, ctx->macCounter);

    memcpy(ctx->gammaCounter, ctx->nonce, MGM_128_BLOCK_SIZE);
    ctx->gammaCounter[0] = ctx->gammaCounter[0] & 0x7F; // == 0 || N
    mgm_128_encrypt_block(ctx->deployedKey, ctx->gammaCounter, ctx->gammaCounter);

    ctx->macHash[0] = 0;
    ctx->macHash[1] = 0;
}

MGM128Ctx *mgm_128_ctx_create_init(uint8_t key[MGM_128_KEY_SIZE], uint8_t nonce[MGM_128_BLOCK_SIZE]) {
    MGM128Ctx *ctx = (MGM128Ctx*)calloc(1, MGM_128_CTX_SIZE);
    if (!ctx) {
        return NULL;
    }
    memcpy(ctx->key, key, MGM_128_KEY_SIZE);
    memcpy(ctx->nonce, nonce, MGM_128_BLOCK_SIZE);
    mgm_128_deploy_key(ctx);
    mgm_128_prepare(ctx);
    return ctx;
}

void mgm_128_ctx_clean(MGM128Ctx *ctx) {
    if (ctx) {
        free(ctx);
    }
}

int mgm_128_update_associated(MGM128Ctx *ctx, const uint8_t* associated, uint64_t assSize)
{

    if (ctx == NULL || associated == NULL || assSize == 0) {
        return -1;
    }

    if (ctx->mode == ENCRYPT || ctx->mode == DECRYPT) {
        return -2;
    }

    ctx->associatedSize += assSize;

    //processing the last-first data block
    if (ctx->unusedGamma > 0) {
        uint64_t firtsBlockSize = MIN(assSize, ctx->unusedGamma);
        memcpy(&ctx->lastBlock[MGM_128_BLOCK_SIZE - ctx->unusedGamma], associated, firtsBlockSize);
        associated += firtsBlockSize;
        assSize -= firtsBlockSize;
        if (ctx->unusedGamma > firtsBlockSize) {
            ctx->unusedGamma -= firtsBlockSize;
            return 0;
        }
        //calculate first block, that contains unused part

        mgm_128_generate_next_mac_block(ctx, ctx->lastBlock);
        ctx->unusedGamma = 0;
    }

    uint8_t remainder = assSize % MGM_128_BLOCK_SIZE;
    uint64_t block128Size = assSize/MGM_128_BLOCK_SIZE;

    //calculate mac
    for (uint64_t i = 0; i < block128Size; i++) {
        mgm_128_generate_next_mac_block(ctx, associated);
        associated += MGM_128_BLOCK_SIZE;
    }

    //last block part
    if (remainder) {
        //save last block for mac
        memcpy(ctx->lastBlock, associated, remainder);
        ctx->unusedGamma = MGM_128_BLOCK_SIZE - remainder;
    }

    return 0;
}

int mgm_128_finalize(MGM128Ctx *ctx, uint8_t mac[MGM_128_BLOCK_SIZE])
{

    if (ctx == NULL) {
        return -1;
    }

    if (ctx->dataSize == 0) {
        return -2;
    }

    if (ctx->unusedGamma > 0) {
        //mac part
        for (int i = MGM_128_BLOCK_SIZE-ctx->unusedGamma; i < MGM_128_BLOCK_SIZE; i++) {
            ctx->lastBlock[i] = 0;
        }
        mgm_128_generate_next_mac_block(ctx, ctx->lastBlock);
        ctx->unusedGamma = 0;
    }

    //calculate last mac block
    mgm_128_finalize_last_block(ctx);
    memcpy(mac, ctx->macHash, MGM_128_BLOCK_SIZE);

    return 0;
}

int mgm_128_encrypt(MGM128Ctx *ctx, uint8_t *in, uint8_t *out, uint64_t size)
{
    if (ctx == NULL || in == NULL || out == NULL || size == 0) {
        return -1;
    }

    //associated data last block part
    if (!ctx->mode && ctx->unusedGamma > 0) {
        for (int i = MGM_128_BLOCK_SIZE-ctx->unusedGamma; i < MGM_128_BLOCK_SIZE; i++) {
            ctx->lastBlock[i] = 0;
        }
        mgm_128_generate_next_mac_block(ctx, ctx->lastBlock);
        ctx->unusedGamma = 0;
    }

    ctx->mode = ENCRYPT;
    return mgm_128_update(ctx, in, out, size);
}

int mgm_128_decrypt(MGM128Ctx *ctx, uint8_t *in, uint8_t *out, uint64_t size)
{
    if (ctx == NULL || in == NULL || out == NULL || size == 0) {
        return -1;
    }

    //associated data last block part
    if (!ctx->mode && ctx->unusedGamma > 0) {
        for (int i = MGM_128_BLOCK_SIZE-ctx->unusedGamma; i < MGM_128_BLOCK_SIZE; i++) {
            ctx->lastBlock[i] = 0;
        }
        mgm_128_generate_next_mac_block(ctx, ctx->lastBlock);
        ctx->unusedGamma = 0;
    }

    ctx->mode = DECRYPT;
    return mgm_128_update(ctx, out, in, size);
}

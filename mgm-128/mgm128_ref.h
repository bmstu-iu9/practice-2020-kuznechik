#pragma once
#include <string.h>
#include "mgm128.h"

static inline void func_X(uint8_t out[MGM_128_BLOCK_SIZE],
            const uint8_t var1[MGM_128_BLOCK_SIZE],
            const uint8_t var2[MGM_128_BLOCK_SIZE])
{
    uint64_t *out_64 = (uint64_t*)out;
    uint64_t *var1_64 = (uint64_t*)var1;
    uint64_t *var2_64 = (uint64_t*)var2;
    out_64[0] = var1_64[0] ^ var2_64[0];
    out_64[1] = var1_64[1] ^ var2_64[1];
}

// multiplication f(x) = x^8 + x^7 + x^6 + x + 1
uint8_t multiplication_gf_8(uint8_t a, uint8_t b) {
    uint8_t x;
    x = 0;
    while (b) {
        if (b & 1) {
            x = x  ^ a;
        }
        a = (a << 1) ^ (a & 0x80 ? 0xC3 : 0x00);
        b = b >> 1;
    }
    return x;
}

inline static void func_S(uint8_t a[MGM_128_BLOCK_SIZE]) {
    for (uint8_t i = 0; i < MGM_128_BLOCK_SIZE; i++) {
        a[i] = permutation[a[i]];
    }
}

inline static void func_L(uint8_t a[MGM_128_BLOCK_SIZE]) {
    for (uint8_t j = 0; j < MGM_128_BLOCK_SIZE; j++) {
        uint8_t x = a[15];
        for (int8_t i = 14; i >= 0; i--) {
            a[i+1] = a[i];
            x = x ^ multiplication_gf_8(linear[i], a[i]);
        }
        a[0] = x;
    }
}

static void mgm_128_encrypt_block(const uint8_t deployed_key[MGM_128_DEPLOYED_KEY_SIZE],
                           const uint8_t in[MGM_128_BLOCK_SIZE],
                           uint8_t out[MGM_128_BLOCK_SIZE])
{
    const uint8_t *round_key = deployed_key;
    memcpy(out, in, MGM_128_BLOCK_SIZE);
    // X[K10]LSX[K9]...LSX[K1](a)
    for (int i = 0; i < ROUNDS-1; i++, round_key += MGM_128_BLOCK_SIZE) {
        func_X(out, out, round_key);
        func_S(out);
        func_L(out);
    }
    func_X(out, out, round_key);
}


inline static void func_F(uint8_t k[MGM_128_BLOCK_SIZE], //  ---> (f(a1) + a0, a1)
                          uint8_t a1[MGM_128_BLOCK_SIZE],
                          uint8_t a0[MGM_128_BLOCK_SIZE])
{
    uint8_t out1[MGM_128_BLOCK_SIZE];
    memcpy(out1, a1, MGM_128_BLOCK_SIZE);
    func_X(a1, a1, k);
    func_S(a1);
    func_L(a1);
    func_X(a1, a1, a0);
    memcpy(a0, out1, MGM_128_BLOCK_SIZE);
}


// multiplication mod f(x) = x^128 + x^7 + x^2 + x + 1
inline static void multiplication_gf_128(uint64_t* a, uint64_t* b, uint64_t* x) {
    x[0] = 0;
    x[1] = 0;
    uint64_t pow2_63 = 0x8000000000000000; // == 2^63
    uint64_t bitFlag;
    while (b[1] || b[0]) {
        if (b[1] & 1) {
            x[0] = x[0]  ^ a[0];
            x[1] = x[1]  ^ a[1];
        }
        bitFlag = a[1] & pow2_63;
        a[1] = (a[1] << 1) ^ (a[0] & pow2_63 ? 0x87 : 0x00); //0x87 ~ x^7 + x^2 + x + 1
        a[0] = (a[0] << 1) | (bitFlag ? 0x01 : 0x00);
        bitFlag = b[0] & 0x01;
        b[1] = (b[1] >> 1) | (bitFlag ? pow2_63 : 0x00);
        b[0] = b[0] >> 1;
    }
}

inline static void str_to_num_128(uint8_t *val) {
    uint64_t a = 0;
    uint64_t b = 0;
    for (uint8_t i = 0; i < 8; i++) {
        uint64_t x = ((uint64_t)val[i]) << (64-(i+1)*8);
        a += x;
        x = ((uint64_t)val[i + 8]) << (64-(i+1)*8);
        b += x;
    }
    ((uint64_t*)val)[0] = a;
    ((uint64_t*)val)[1] = b;
}

inline static void num_to_str_128(uint8_t *val) {
    uint64_t a = ((uint64_t*)val)[0];
    uint64_t b = ((uint64_t*)val)[1];
    for (uint8_t i = 0; i < 8; i++) {
        val[i] = a >> (64-(i+1) * 8);
        val[i + 8] = b >> (64-(i+1) * 8);
    }
}


inline static void incr_right(uint8_t *val) {
    for (int8_t i = MGM_128_BLOCK_SIZE-1; i >= MGM_128_BLOCK_SIZE/2; i--) {
        if (val[i] == 0xFF) {
            val[i] = 0;
        } else {
            val[i] += 1;
            return;
        }
    }
}

inline static void incr_left(uint8_t *val) {
    for (int8_t i = MGM_128_BLOCK_SIZE/2-1; i >= 0; i--) {
        if (val[i] == 0xFF) {
            val[i] = 0;
        } else {
            val[i] += 1;
            return;
        }
    }
}

static void mgm_128_generate_next_mac_block(MGM128Ctx *ctx, const uint8_t* in) {
    uint8_t block[MGM_128_BLOCK_SIZE];
    memcpy(block, in, MGM_128_BLOCK_SIZE);
    uint64_t x[2];
    mgm_128_encrypt_block(ctx->deployedKey, ctx->macCounter, ctx->gamma);
    str_to_num_128(block);
    str_to_num_128(ctx->gamma);
    multiplication_gf_128((uint64_t*)block, (uint64_t*)ctx->gamma, x);
    ctx->macHash[0] = ctx->macHash[0] ^ x[0];
    ctx->macHash[1] = ctx->macHash[1] ^ x[1];
    incr_left(ctx->macCounter);
}

static void mgm_128_finalize_last_block(MGM128Ctx *ctx) {
    uint64_t x[2];
    ((uint64_t*)ctx->lastBlock)[0] = ctx->associatedSize * 8;
    ((uint64_t*)ctx->lastBlock)[1] = ctx->dataSize * 8;
    mgm_128_encrypt_block(ctx->deployedKey, ctx->macCounter, ctx->gamma);
    str_to_num_128(ctx->gamma);
    multiplication_gf_128((uint64_t*)ctx->lastBlock, (uint64_t*)ctx->gamma, x);
    ctx->macHash[0] = ctx->macHash[0] ^ x[0];
    ctx->macHash[1] = ctx->macHash[1] ^ x[1];

    //calculate imitation
    num_to_str_128((uint8_t*)ctx->macHash);
    mgm_128_encrypt_block(ctx->deployedKey, (uint8_t*)ctx->macHash, (uint8_t*)ctx->macHash);
}

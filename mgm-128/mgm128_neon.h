#include "mgm128.h"
#include <arm_neon.h>
#include <string.h>

inline static void func_X(uint8_t out[MGM_128_BLOCK_SIZE],
                     const uint8_t var1[MGM_128_BLOCK_SIZE],
                     const uint8_t var2[MGM_128_BLOCK_SIZE])
{
    uint64_t *out_64 = (uint64_t*)out;
    uint64_t *var1_64 = (uint64_t*)var1;
    uint64_t *var2_64 = (uint64_t*)var2;
    out_64[0] = var1_64[0] ^ var2_64[0];
    out_64[1] = var1_64[1] ^ var2_64[1];
}

inline static void func_LS(uint8_t a[MGM_128_BLOCK_SIZE])
{
    const uint64_t *b0 = (uint64_t*)&tableLS[a[0]*MGM_128_BLOCK_SIZE + 0x0000];
    const uint64_t *b1 = (uint64_t*)&tableLS[a[0]*MGM_128_BLOCK_SIZE + 0x1000];
    const uint64_t *b2 = (uint64_t*)&tableLS[a[0]*MGM_128_BLOCK_SIZE + 0x2000];
    const uint64_t *b3 = (uint64_t*)&tableLS[a[0]*MGM_128_BLOCK_SIZE + 0x3000];
    const uint64_t *b4 = (uint64_t*)&tableLS[a[0]*MGM_128_BLOCK_SIZE + 0x4000];
    const uint64_t *b5 = (uint64_t*)&tableLS[a[0]*MGM_128_BLOCK_SIZE + 0x5000];
    const uint64_t *b6 = (uint64_t*)&tableLS[a[0]*MGM_128_BLOCK_SIZE + 0x6000];
    const uint64_t *b7 = (uint64_t*)&tableLS[a[0]*MGM_128_BLOCK_SIZE + 0x7000];
    const uint64_t *b8 = (uint64_t*)&tableLS[a[0]*MGM_128_BLOCK_SIZE + 0x8000];
    const uint64_t *b9 = (uint64_t*)&tableLS[a[0]*MGM_128_BLOCK_SIZE + 0x9000];
    const uint64_t *b10 = (uint64_t*)&tableLS[a[0]*MGM_128_BLOCK_SIZE + 0xA000];
    const uint64_t *b11 = (uint64_t*)&tableLS[a[0]*MGM_128_BLOCK_SIZE + 0xB000];
    const uint64_t *b12 = (uint64_t*)&tableLS[a[0]*MGM_128_BLOCK_SIZE + 0xC000];
    const uint64_t *b13 = (uint64_t*)&tableLS[a[0]*MGM_128_BLOCK_SIZE + 0xD000];
    const uint64_t *b14 = (uint64_t*)&tableLS[a[0]*MGM_128_BLOCK_SIZE + 0xE000];
    const uint64_t *b15 = (uint64_t*)&tableLS[a[0]*MGM_128_BLOCK_SIZE + 0xF000];
    uint64_t *a64 = (uint64_t*)a;
    a64[0] = b0[0]^b1[0]^b2[0]^b3[0]^b4[0]^b5[0]^b6[0]^b7[0]^b8[0]
                ^b9[0]^b10[0]^b11[0]^b12[0]^b13[0]^b14[0]^b15[0];
    a64[1] = b1[1]^b1[1]^b2[1]^b3[1]^b4[1]^b5[1]^b6[1]^b7[1]^b8[1]
                ^b9[1]^b11[1]^b11[1]^b12[1]^b13[1]^b14[1]^b15[1];
}

inline static void F(uint8_t k[MGM_128_BLOCK_SIZE], //  ---> (f(a1) + a0, a1)
                     uint8_t a1[MGM_128_BLOCK_SIZE],
                     uint8_t a0[MGM_128_BLOCK_SIZE])
{
    uint8_t tmp[MGM_128_BLOCK_SIZE];
    memcpy(tmp, a1, MGM_128_BLOCK_SIZE);
    func_X(a1, a1, k);
    func_LS(a1);
    func_X(a1, a1, a0);
    memcpy(a0, tmp, MGM_128_BLOCK_SIZE);
}

static void mgm_128_encrypt_block(const uint8_t deployed_key[MGM_128_DEPLOYED_KEY_SIZE],
                                    const uint8_t in[MGM_128_BLOCK_SIZE],
                                    uint8_t out[MGM_128_BLOCK_SIZE])
{
    const uint8_t *round_key = deployed_key;

    memcpy(out, in, MGM_128_BLOCK_SIZE);

    // X[K10]LSX[K9]...LSX[K1](a)
    for(int i = 0; i < ROUNDS-1; i++, round_key += MGM_128_BLOCK_SIZE)
    {
        func_X(out, out, round_key);
        func_LS(out);
    }
    func_X(out, out, round_key);
}



inline static void incr_right(uint8_t *val) {
    uint64_t incVal = ((uint64_t*)val)[1];
    incVal = __builtin_bswap64(incVal) + 1;
    ((uint64_t*)val)[1] = __builtin_bswap64(incVal);
}

inline static void incr_left(uint8_t *val) {
    uint64_t incVal = ((uint64_t*)val)[0];
    incVal = __builtin_bswap64(incVal) + 1;
    ((uint64_t*)val)[0] = __builtin_bswap64(incVal);
}

inline static uint64x2_t PMULL_00(const uint64x2_t a, const uint64x2_t b) {
    uint64x2_t r;
    __asm __volatile("pmull    %0.1q, %1.1d, %2.1d \n\t"
                     :"=w" (r) : "w" (a), "w" (b) );
    return r;
}

inline static uint64x2_t PMULL_11(const uint64x2_t a, const uint64x2_t b) {
    uint64x2_t r;
    __asm __volatile("pmull2   %0.1q, %1.2d, %2.2d \n\t"
                     :"=w" (r) : "w" (a), "w" (b) );
    return r;
}

inline static uint64x2_t PMULL_01(const uint64x2_t a, const uint64x2_t b)
{
    uint64x2_t r;
    __asm __volatile("pmull    %0.1q, %1.1d, %2.1d \n\t"
                     :"=w" (r) : "w" (a), "w" (vget_high_u64(b)) );
    return r;
}

inline static uint64x2_t PMULL_10(const uint64x2_t a, const uint64x2_t b)
{
    uint64x2_t r;
    __asm __volatile("pmull    %0.1q, %1.1d, %2.1d \n\t"
                     :"=w" (r) : "w" (vget_high_u64(a)), "w" (b) );
    return r;
}

static uint8x16_t multiplication_gf_128(const uint8x16_t a,
                                        const uint8x16_t b)
{
    uint64x2_t tmp0, tmp1, tmp2, a64, b64;
    const uint64x2_t r = {0xe100000000000000, 0xc200000000000000};
    const uint64x2_t z = vdupq_n_u64(0);
    const uint8x16_t BSWAP_MASK = {15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0};
    a64 = vreinterpretq_u64_u8(vrbitq_u8(a));
    b64 = vreinterpretq_u64_u8(vrbitq_u8(b));

    tmp0 = PMULL_00(a64, b64);
    tmp1 = veorq_u64(PMULL_10(a64, b64), PMULL_01(a64, b64));
    tmp2 = PMULL_11(a64, b64);

    tmp1 = veorq_u64(tmp1, vextq_u64(z, tmp0, 1));
    tmp1 = veorq_u64(tmp1, PMULL_01(tmp0, r));
    tmp0 = vextq_u64(tmp0, z, 1);
    tmp0 = veorq_u64(tmp0, tmp1);
    tmp0 = vshlq_n_u64(tmp0, 1);
    tmp0 = PMULL_00(tmp0, r);
    tmp2 = veorq_u64(tmp2, tmp0);
    tmp2 = veorq_u64(tmp2, vextq_u64(tmp1, z, 1));
    tmp1 = vcombine_u64(vget_low_u64(tmp1), vget_low_u64(tmp2));
    tmp1 = vshrq_n_u64(tmp1, 63);
    tmp2 = vshlq_n_u64(tmp2, 1);
    tmp0 = veorq_u64(tmp2, tmp1);
    return vqtbl1q_u8(vrbitq_u8(vreinterpretq_u8_u64(tmp0)), BSWAP_MASK);
}

static void MGM_128_generate_next_mgm_mac_block(MGM128Ctx *ctx, const uint8_t* in)
{
    //ctx->macHash accumulates hash sum for imitation
    //ctx->macCounter contains current block-counter
    //x contains multiplication_gf_128(block, ctx->gamma) result
    uint8x16_t x;
    uint8x16_t block = vld1q_u8(in);
    mgm_128_encrypt_block(ctx->deployedKey, ctx->macCounter, ctx->gamma);
    x = multiplication_gf_128(block, vld1q_u8(ctx->gamma));
    *((uint8x16_t *)ctx->macHash) = veorq_u8(vld1q_u8(ctx->macHash), x);
    incr_left(ctx->macCounter);
}

static void MGM_128_mgm_finalize_last_block(MGM128Ctx *ctx)
{
    uint8x16_t block; //last block for calculation mac
    uint8x16_t x; //multiplication_gf_128(block, ctx->gamma) result
    //calculate last block
    ((uint64_t*)(&block))[1] = ctx->associatedSize * 8;
    ((uint64_t*)(&block))[0] = ctx->dataSize * 8;
    const uint8x16_t BSWAP_MASK = {15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0};
    block = vqtbl1q_u8(block, BSWAP_MASK);

    mgm_128_encrypt_block(ctx->deployedKey, ctx->macCounter, ctx->gamma);
    x = multiplication_gf_128(block, vld1q_u8(ctx->gamma));

    block = vld1q_u8(ctx->macHash);
    block = veorq_u8(block, x);
    block = vqtbl1q_u8(block, BSWAP_MASK);

    //calculate imitation
    mgm_128_encrypt_block(ctx->deployedKey, (uint8_t*)&block, (uint8_t*)ctx->macHash);
}



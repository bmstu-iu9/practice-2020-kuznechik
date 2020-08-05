#pragma once
#include "mgm128.h"
#include <string.h>
#include <emmintrin.h>
#include <smmintrin.h>
#include <immintrin.h>

//kuznechick_start

inline static void func_X(uint8_t out[MGM_128_BLOCK_SIZE],
            const uint8_t var1[MGM_128_BLOCK_SIZE],
            const uint8_t var2[MGM_128_BLOCK_SIZE])
{

    __m128i out_128;
    __m128i var1_128 = _mm_loadu_si128((const __m128i*)var1);
    __m128i var2_128 = _mm_loadu_si128((const __m128i*)var2);
    out_128 = _mm_xor_si128(var1_128, var2_128);
    _mm_storeu_si128((__m128i*)out, out_128);
}

inline static __m128i func_LS(__m128i val)
{
    __m128i temp0;
    __m128i temp1;
    __m128i addr0;
    __m128i addr1;

    addr0 = _mm_and_si128(*((const __m128i *)bitmask), val);
    addr1 = _mm_andnot_si128(*((const __m128i *)bitmask), val);

    addr0 = _mm_srli_epi16(addr0, 4);
    addr1 = _mm_slli_epi16(addr1, 4);

    temp0 = _mm_load_si128((const __m128i *) (tableLS + _mm_extract_epi16(addr0, 0) + 0x1000));
    temp1 = _mm_load_si128((const __m128i *) (tableLS + _mm_extract_epi16(addr1, 0) + 0x0000));

    temp0 = _mm_xor_si128(temp0, *((const __m128i *) (tableLS+ _mm_extract_epi16(addr0, 1)+ 0x3000)));
    temp1 = _mm_xor_si128(temp1, *((const __m128i *) (tableLS + _mm_extract_epi16(addr1, 1) + 0x2000)));

    temp0 = _mm_xor_si128(temp0, *((const __m128i *) (tableLS + _mm_extract_epi16(addr0, 2) + 0x5000)));
    temp1 = _mm_xor_si128(temp1, *((const __m128i *) (tableLS + _mm_extract_epi16(addr1, 2) + 0x4000)));

    temp0 = _mm_xor_si128(temp0, *((const __m128i *) (tableLS + _mm_extract_epi16(addr0, 3) + 0x7000)));
    temp1 = _mm_xor_si128(temp1, *((const __m128i *) (tableLS + _mm_extract_epi16(addr1, 3) + 0x6000)));

    temp0 = _mm_xor_si128(temp0, *((const __m128i *) (tableLS + _mm_extract_epi16(addr0, 4) + 0x9000)));
    temp1 = _mm_xor_si128(temp1, *((const __m128i *) (tableLS + _mm_extract_epi16(addr1, 4) + 0x8000)));

    temp0 = _mm_xor_si128(temp0, *((const __m128i *) (tableLS + _mm_extract_epi16(addr0, 5) + 0xB000)));
    temp1 = _mm_xor_si128(temp1, *((const __m128i *) (tableLS + _mm_extract_epi16(addr1, 5) + 0xA000)));

    temp0 = _mm_xor_si128(temp0, *((const __m128i *) (tableLS + _mm_extract_epi16(addr0, 6) + 0xD000)));
    temp1 = _mm_xor_si128(temp1, *((const __m128i *) (tableLS + _mm_extract_epi16(addr1, 6) + 0xC000)));

    temp0 = _mm_xor_si128(temp0, *((const __m128i *) (tableLS + _mm_extract_epi16(addr0, 7) + 0xF000)));
    temp1 = _mm_xor_si128(temp1, *((const __m128i *) (tableLS + _mm_extract_epi16(addr1, 7) + 0xE000)));

    return _mm_xor_si128(temp0, temp1);
}

inline static void func_F(const uint8_t *k, __m128i *a1, __m128i *a0) //  ---> (f(a1) + a0, a1)
{
    __m128i temp0;
    __m128i temp1 = _mm_loadu_si128((const __m128i *)k);
    temp0 = *a1;
    *a1 = _mm_xor_si128(temp1, *a1); //func X
    *a1 = func_LS(*a1);
    *a1 = _mm_xor_si128(*a0, *a1);
    *a0 = temp0;
}

static void mgm_128_encrypt_block(const uint8_t deployed_key[MGM_128_DEPLOYED_KEY_SIZE],
                           const uint8_t in[MGM_128_BLOCK_SIZE],
                                  uint8_t out[MGM_128_BLOCK_SIZE])
{
    __m128i out128 = _mm_loadu_si128((const __m128i*)in);
    __m128i *round_key = (__m128i *)deployed_key;
    
    // X[K10]LSX[K9]...LSX[K1](a)
    for(int i = 0; i < ROUNDS-1; i++)
    {
    	out128 = _mm_xor_si128(round_key[i], out128); //func X
    	out128 = func_LS(out128);
    }
    out128 = _mm_xor_si128(round_key[ROUNDS-1], out128);
    memcpy(out, &out128, MGM_128_BLOCK_SIZE);
}

//kuznechick_end

// multiplication mod f(x) = x^128 + x^7 + x^2 + x + 1
inline static __m128i multiplication_gf_128(__m128i a, __m128i b)
{
    __m128i tmp0, tmp1, tmp2, tmp3, tmp4,
            tmp5, tmp6, tmp7, tmp8, tmp9;
    __m128i XMM_MASK = _mm_setr_epi32(0xFFFFFFFF, 0x0, 0x0, 0x0);
    __m128i BSWAP_MASK = _mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
    a = _mm_shuffle_epi8(a, BSWAP_MASK);
    b = _mm_shuffle_epi8(b, BSWAP_MASK);
    tmp0 = _mm_clmulepi64_si128(a, b, 0x00);
    tmp3 = _mm_clmulepi64_si128(a, b, 0x11);
    tmp1 = _mm_shuffle_epi32(a,78);
    tmp2 = _mm_shuffle_epi32(b,78);
    tmp1 = _mm_xor_si128(tmp1, a);
    tmp2 = _mm_xor_si128(tmp2, b);
    tmp1 = _mm_clmulepi64_si128(tmp1, tmp2, 0x00);
    tmp1 = _mm_xor_si128(tmp1, tmp0);
    tmp1 = _mm_xor_si128(tmp1, tmp3);
    tmp2 = _mm_slli_si128(tmp1, 8);
    tmp1 = _mm_srli_si128(tmp1, 8);
    tmp0 = _mm_xor_si128(tmp0, tmp2);
    tmp3 = _mm_xor_si128(tmp3, tmp1);
    tmp4 = _mm_srli_epi32(tmp3, 31);
    tmp5 = _mm_srli_epi32(tmp3, 30);
    tmp6 = _mm_srli_epi32(tmp3, 25);
    tmp4 = _mm_xor_si128(tmp4, tmp5);
    tmp4 = _mm_xor_si128(tmp4, tmp6);
    tmp5 = _mm_shuffle_epi32(tmp4, 147);
    tmp4 = _mm_and_si128(XMM_MASK, tmp5);
    tmp5 = _mm_andnot_si128(XMM_MASK, tmp5);
    tmp0 = _mm_xor_si128(tmp0, tmp5);
    tmp3 = _mm_xor_si128(tmp3, tmp4);
    tmp7 = _mm_slli_epi32(tmp3, 1);
    tmp0 = _mm_xor_si128(tmp0, tmp7);
    tmp8 = _mm_slli_epi32(tmp3, 2);
    tmp0 = _mm_xor_si128(tmp0, tmp8);
    tmp9 = _mm_slli_epi32(tmp3, 7);
    tmp0 = _mm_xor_si128(tmp0, tmp9);

    return _mm_xor_si128(tmp0, tmp3);
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

static void mgm_128_finalize_last_block(MGM128Ctx *ctx)
{
    __m128i block; //last block for calculation mac
    __m128i x; //multiplication_gf_128(block, ctx->gamma) result
    //calculate last block
    block = _mm_insert_epi64(block, ctx->associatedSize * 8, 1);
    block = _mm_insert_epi64(block, ctx->dataSize * 8, 0);
    __m128i BSWAP_MASK = _mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
    block = _mm_shuffle_epi8(block, BSWAP_MASK);

    mgm_128_encrypt_block(ctx->deployedKey, ctx->macCounter, ctx->gamma);
    x = multiplication_gf_128(block, *((__m128i *)ctx->gamma));

    block = _mm_loadu_si128((const __m128i*)ctx->macHash);
    block = _mm_xor_si128(block, x);
    block = _mm_shuffle_epi8(block, BSWAP_MASK);

    //calculate imitation
    mgm_128_encrypt_block(ctx->deployedKey, (uint8_t*)&block, (uint8_t*)ctx->macHash);

}

static void mgm_128_generate_next_mac_block(MGM128Ctx *ctx, const uint8_t* in)
{
    __m128i block = _mm_loadu_si128((const __m128i*)in);
    __m128i x;
    mgm_128_encrypt_block(ctx->deployedKey, ctx->macCounter, ctx->gamma);
    x = multiplication_gf_128(block, *((__m128i *)ctx->gamma));
    *((__m128i *)ctx->macHash) = _mm_xor_si128(*((__m128i *)ctx->macHash), x);
    incr_left(ctx->macCounter);
}

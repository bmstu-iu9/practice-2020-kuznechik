#include <stdio.h>
#include <stdlib.h>
#include "mgm128.h"

void test() {
    MGM128Ctx *ctx;

    const uint8_t key[MGM_128_KEY_SIZE] = {
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,  0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };

    uint8_t plaintext1[] = {
        0x11
    };

    uint8_t plaintext2[] = {
        0x22, 0x33, 0x44
    };

    uint8_t plaintext3[] = {
        0x55, 0x66, 0x77, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xEE, 0xFF, 0x0A, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xEE, 0xFF, 0x0A, 0x00, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xEE, 0xFF, 0x0A, 0x00, 0x11, 0xAA, 0xBB, 0xCC
    };

    const uint8_t associated1[] = {
        0x02, 0x02, 0x02, 0x02, 0x02
    };

    const uint8_t associated2[] = {
        0x02, 0x02, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x04, 0x04, 0x04, 0x04, 0x04,
        0x04, 0x04
    };

    const uint8_t associated3[] = {
        0x04, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0xEA, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
        0x05, 0x05
    };

    const uint8_t nonce[MGM_128_BLOCK_SIZE] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88
    };

    const uint8_t cipher[] = {
        0xA9, 0x75, 0x7B, 0x81, 0x47, 0x95, 0x6E, 0x90, 0x55, 0xB8, 0xA3, 0x3D, 0xE8, 0x9F, 0x42, 0xFC,
        0x80, 0x75, 0xD2, 0x21, 0x2B, 0xF9, 0xFD, 0x5B, 0xD3, 0xF7, 0x06, 0x9A, 0xAD, 0xC1, 0x6B, 0x39,
        0x49, 0x7A, 0xB1, 0x59, 0x15, 0xA6, 0xBA, 0x85, 0x93, 0x6B, 0x5D, 0x0E, 0xA9, 0xF6, 0x85, 0x1C,
        0xC6, 0x0C, 0x14, 0xD4, 0xD3, 0xF8, 0x83, 0xD0, 0xAB, 0x94, 0x42, 0x06, 0x95, 0xC7, 0x6D, 0xEB,
        0x2C, 0x75, 0x52
    };

    const uint8_t imitation[MGM_128_BLOCK_SIZE] = {
        0xCF, 0x5D, 0x65, 0x6F, 0x40, 0xC3, 0x4F, 0x5C, 0x46, 0xE8, 0xBB, 0x0E, 0x29, 0xFC, 0xDB, 0x4C
    };
    uint8_t encrypted[sizeof(cipher)];
    uint8_t encrypted_imitation[MGM_128_BLOCK_SIZE];
    int err;
    int i;
    int OK = 0;

    ctx = mgm_128_ctx_create_init(key, nonce);
    if (ctx == NULL) {
        goto cleanup;
    }

    err = mgm_128_update_associated(ctx, associated1, sizeof(associated1));
    if (err != OK) {
        goto cleanup;
    }

    err = mgm_128_update_associated(ctx, associated2, sizeof(associated2));
    if (err != OK) {
        goto cleanup;
    }

    err = mgm_128_update_associated(ctx, associated3, sizeof(associated3));
    if (err != OK) {
        goto cleanup;
    }

    err = mgm_128_encrypt(ctx, plaintext1, encrypted, sizeof(plaintext1));
    if (err != OK) {
        goto cleanup;
    }

    err = mgm_128_encrypt(ctx, plaintext2, encrypted + sizeof(plaintext1), sizeof(plaintext2));
    if (err != OK) {
        goto cleanup;
    }

    err = mgm_128_encrypt(ctx, plaintext3, encrypted + sizeof(plaintext1) + sizeof(plaintext2), sizeof(plaintext3));
    if (err != OK) {
        goto cleanup;
    }

    err = mgm_128_finalize(ctx, encrypted_imitation);
    if (err != OK) {
        goto cleanup;
    }

    for(i = 0; i < MGM_128_BLOCK_SIZE; i++) {
        if (imitation[i] != encrypted_imitation[i]) {
            err = -1;
            printf("imitation err: 0x%.2X != 0x%.2X\n", imitation[i], encrypted_imitation[i]);
        }
    }
    for(i = 0; i < sizeof(cipher); i++) {
        if (encrypted[i] != cipher[i]) {
            err = -1;
            printf("encrypted err: 0x%.2X != 0x%.2X\n", imitation[i], encrypted_imitation[i]);
        }
    }
    if (err == OK) {
    	printf("SUCCESS\n");
    }

cleanup:
    mgm_128_ctx_clean(ctx);
}


int main() {
    test();
    return 0;
}

// hmac_sha512.c  — HMAC-SHA512 (streaming + one-shot) with RFC4231 self-tests
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "hmac_sha512.h"
#include "sha512.h"

#ifndef SHA512_DIGEST_SIZE
#define SHA512_DIGEST_SIZE 64
#endif
#ifndef SHA512_BLOCK_SIZE
#define SHA512_BLOCK_SIZE 128
#endif

/* ===================== Streaming HMAC ===================== */
void hmac_sha512_init(HMAC_SHA512_CTX* ctx,
    const uint8_t* key, size_t key_len)
{
    uint8_t key_block[SHA512_BLOCK_SIZE];
    if (!ctx) return;
    ctx->initialized = 0;

    memset(key_block, 0, sizeof(key_block));
    if (key_len > SHA512_BLOCK_SIZE) {
        SHA512_CTX kctx;
        sha512_init(&kctx);
        sha512_update(&kctx, key, key_len);
        sha512_final(&kctx, key_block);
    }
    else if (key_len) {
        memcpy(key_block, key, key_len);
    }

    for (size_t i = 0; i < SHA512_BLOCK_SIZE; ++i) {
        ctx->i_key_pad[i] = (uint8_t)(key_block[i] ^ 0x36);
        ctx->o_key_pad[i] = (uint8_t)(key_block[i] ^ 0x5c);
    }

    sha512_init(&ctx->ictx);
    sha512_update(&ctx->ictx, ctx->i_key_pad, SHA512_BLOCK_SIZE);

    sha512_init(&ctx->octx);
    sha512_update(&ctx->octx, ctx->o_key_pad, SHA512_BLOCK_SIZE);

    ctx->initialized = 1;
}

void hmac_sha512_update(HMAC_SHA512_CTX* ctx,
    const uint8_t* data, size_t data_len)
{
    if (!ctx || !ctx->initialized) return;
    if (data_len) sha512_update(&ctx->ictx, data, data_len);
}

void hmac_sha512_final(HMAC_SHA512_CTX* ctx, uint8_t* mac_out)
{
    uint8_t inner_hash[SHA512_DIGEST_SIZE];
    SHA512_CTX octx2;
    if (!ctx || !ctx->initialized || !mac_out) return;

    sha512_final(&ctx->ictx, inner_hash);

    octx2 = ctx->octx; /* copy */
    sha512_update(&octx2, inner_hash, SHA512_DIGEST_SIZE);
    sha512_final(&octx2, mac_out);

    ctx->initialized = 0; /* re-init needed for reuse */
}

/* ===================== One-shot HMAC ===================== */
void hmac_sha512(const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len,
    uint8_t* mac_out)
{
    HMAC_SHA512_CTX ctx;
    hmac_sha512_init(&ctx, key, key_len);
    hmac_sha512_update(&ctx, data, data_len);
    hmac_sha512_final(&ctx, mac_out);
}


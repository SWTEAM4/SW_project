#include "hmac.h"
#include "sha512.h"
#include <string.h>

void hmac_sha512(
    const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len,
    uint8_t* mac_out)
{
    uint8_t key_block[HMAC_BLOCK_SIZE];
    uint8_t o_key_pad[HMAC_BLOCK_SIZE];
    uint8_t i_key_pad[HMAC_BLOCK_SIZE];
    uint8_t inner_hash[SHA512_DIGEST_SIZE];
    size_t i;

    // Step 1: Prepare key block
    memset(key_block, 0, HMAC_BLOCK_SIZE);

    if (key_len > HMAC_BLOCK_SIZE) {
        sha512_context key_ctx;
        sha512_init(&key_ctx);
        sha512_update(&key_ctx, key, key_len);
        sha512_final(&key_ctx, key_block);
        
    }
    else {
        memcpy(key_block, key, key_len);
        
    }

    // Step 2: XOR with ipad and opad
    for (i = 0; i < HMAC_BLOCK_SIZE; i++) {
        i_key_pad[i] = key_block[i] ^ 0x36;
        o_key_pad[i] = key_block[i] ^ 0x5c;
    }

    // Step 3: inner hash = H((key ^ ipad) || data)
    sha512_context inner_ctx;
    sha512_init(&inner_ctx);
    sha512_update(&inner_ctx, i_key_pad, HMAC_BLOCK_SIZE);
    sha512_update(&inner_ctx, data, data_len);
    sha512_final(&inner_ctx, inner_hash);

    // Step 4: outer hash = H((key ^ opad) || inner_hash)
    sha512_context outer_ctx;
    sha512_init(&outer_ctx);
    sha512_update(&outer_ctx, o_key_pad, HMAC_BLOCK_SIZE);
    sha512_update(&outer_ctx, inner_hash, SHA512_DIGEST_SIZE);
    sha512_final(&outer_ctx, mac_out);
}

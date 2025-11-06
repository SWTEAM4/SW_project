#ifndef SHA512_H
#define SHA512_H

#include <stdint.h>
#include <stddef.h>

#define SHA512_BLOCK_SIZE 128
#define SHA512_DIGEST_SIZE 64

typedef struct {
    uint64_t state[8];
    uint8_t buffer[SHA512_BLOCK_SIZE];
    uint64_t bitlen_high;
    uint64_t bitlen_low;
    size_t datalen;
} sha512_context;

void sha512_init(sha512_context* ctx);
void sha512_update(sha512_context* ctx, const uint8_t* data, size_t len);
void sha512_final(sha512_context* ctx, uint8_t* hash);

#endif // SHA512_H


/*
#ifndef SHA512_H
#define SHA512_H

#include <stddef.h>
#include <stdint.h>

#define SHA512_BLOCK_SIZE 128
#define SHA512_DIGEST_SIZE 64

typedef struct {
    uint64_t state[8];
    uint64_t bitlen;
    uint8_t buffer[SHA512_BLOCK_SIZE];
} sha512_context;

void sha512_init(sha512_context *ctx);
void sha512_update(sha512_context *ctx, const uint8_t *data, size_t len);
void sha512_final(sha512_context *ctx, uint8_t *hash);

#endif // SHA512_H
*/
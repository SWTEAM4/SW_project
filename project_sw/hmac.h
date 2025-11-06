#ifndef HMAC_H
#define HMAC_H

#include <stddef.h>
#include <stdint.h>

#define HMAC_BLOCK_SIZE 128
#define HMAC_DIGEST_SIZE 64

void hmac_sha512(
    const uint8_t* key, size_t key_len,
    const uint8_t* data, size_t data_len,
    uint8_t* mac_out);

#endif // HMAC_H

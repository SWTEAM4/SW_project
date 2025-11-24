#ifndef HMAC_SHA512_H
#define HMAC_SHA512_H

#include <stddef.h>
#include <stdint.h>
#include "sha512.h"   /* SHA512_CTX 선언 사용 */

#ifdef __cplusplus
extern "C" {
#endif

    /* ---- 파라미터 ---- */
#define HMAC_SHA512_BLOCK_SIZE   128u
#define HMAC_SHA512_DIGEST_SIZE  64u

/* ---- 원샷 HMAC-SHA512 ---- */
    void hmac_sha512(const uint8_t* key, size_t key_len,
        const uint8_t* data, size_t data_len,
        uint8_t* mac_out);

    /* ---- 스트리밍 HMAC-SHA512 ---- */
    typedef struct {
        uint8_t     o_key_pad[HMAC_SHA512_BLOCK_SIZE];
        uint8_t     i_key_pad[HMAC_SHA512_BLOCK_SIZE];
        SHA512_CTX  ictx;   /* inner hash context  */
        SHA512_CTX  octx;   /* outer hash context  */
        int         initialized;
    } HMAC_SHA512_CTX;

    void hmac_sha512_init(HMAC_SHA512_CTX* ctx,
        const uint8_t* key, size_t key_len);

    void hmac_sha512_update(HMAC_SHA512_CTX* ctx,
        const uint8_t* data, size_t data_len);

    void hmac_sha512_final(HMAC_SHA512_CTX* ctx, uint8_t* mac_out);
    
#ifdef __cplusplus
}
#endif
#endif /* HMAC_SHA512_H */



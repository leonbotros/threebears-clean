#ifndef api_h
#define api_h

#include <stdint.h>

#define CRYPTO_SECRETKEYBYTES 40
#define CRYPTO_PUBLICKEYBYTES 804
#define CRYPTO_BYTES 32
#define CRYPTO_CIPHERTEXTBYTES 917
#define CRYPTO_ALGNAME "BabyBear"

int crypto_kem_keypair(
    uint8_t *pk,
    uint8_t *sk
);

int crypto_kem_enc(
    uint8_t *ct,
    uint8_t *ss,
    const uint8_t *pk
);

int crypto_kem_dec(
    uint8_t *ss,
    const uint8_t *ct,
    const uint8_t *sk
);

#endif /* api_h */


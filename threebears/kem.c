#include <string.h> /* for memcpy */

#include "api.h"
#include "threebears_common.h"
#include "randombytes.h"
#include "threebears.h"
#include "params.h"

int crypto_kem_keypair(
    uint8_t *pk,
    uint8_t *sk
) {
    randombytes(sk,PRIVATE_KEY_BYTES);
    get_pubkey(pk,sk);
    return 0;
}

int crypto_kem_enc(
    uint8_t *ct,
    uint8_t *ss,
    const uint8_t *pk
) {
    uint8_t seed[ENC_SEED_BYTES+IV_BYTES];
    randombytes(seed,sizeof(seed));
    encapsulate(ss,ct,pk,seed);
    secure_bzero(seed,sizeof(seed));
    return 0;
}

int crypto_kem_dec(
    uint8_t *ss,
    const uint8_t *ct,
    const uint8_t *sk
) {
    return decapsulate(ss,ct,sk);
}


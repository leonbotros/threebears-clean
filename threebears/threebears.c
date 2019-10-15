/** ThreeBears reference implementation */
#include "api.h"
#if FEC_BITS
#include "melas_fec.h"
#endif
#include "params.h"
#include "ring.h"
#include "sp800-185.h"
#include "threebears.h"

#define FEC_BYTES ((FEC_BITS+7)/8)
#define ENC_BITS  (ENC_SEED_BYTES*8 + FEC_BITS)

enum { HASH_PURPOSE_UNIFORM = 0, HASH_PURPOSE_KEYGEN = 1, HASH_PURPOSE_ENCAPS = 2, HASH_PURPOSE_PRF = 3 };

/** Initialize the hash function with a given purpose */
static void threebears_hash_init(
    shake256incctx *ctx,
    uint8_t purpose
) {
    const char S[] = "ThreeBears";
    cshake256_inc_init(ctx, NULL, 0, (const uint8_t *)S, strlen(S));
    const uint8_t pblock[15] = {
        VERSION, PRIVATE_KEY_BYTES, MATRIX_SEED_BYTES, ENC_SEED_BYTES,
        IV_BYTES, SHARED_SECRET_BYTES, LGX, DIGITS & 0xFF, DIGITS >> 8, DIM,
                VAR_TIMES_128 - 1, LPR_BITS, FEC_BITS, CCA, 0 /* padding */
    };
    cshake256_inc_absorb(ctx, (const uint8_t *)pblock, sizeof(pblock));
    cshake256_inc_absorb(ctx, &purpose, 1);
}

/** Sample n gf_t's uniformly from a seed */
static void uniform(gf_t matrix, const uint8_t *seed, uint8_t iv) {
    uint8_t c[GF_BYTES];
    shake256incctx ctx;
    threebears_hash_init(&ctx, HASH_PURPOSE_UNIFORM);
    cshake256_inc_absorb(&ctx, seed, MATRIX_SEED_BYTES);
    cshake256_inc_absorb(&ctx, &iv, 1);
    cshake256_inc_finalize(&ctx);
    cshake256_inc_squeeze(c, sizeof(c), &ctx);
    PQCLEAN_NAMESPACE_expand(matrix, c);
}

/** The ThreeBears error distribution */
static slimb_t psi(uint8_t ci) {
    int sample = 0, var = VAR_TIMES_128;
    for (; var > 64; var -= 64, ci <<= 2) {
        sample += ((ci + 64) >> 8) + ((ci - 64) >> 8);
    }
    return sample + ((ci + var) >> 8) + ((ci - var) >> 8);
}

/** Sample a vector of n noise elements */
static void noise(gf_t x, const shake256incctx *ctx, uint8_t iv) {
    uint8_t c[DIGITS];
    shake256incctx ctx2;
    memcpy(&ctx2, ctx, sizeof(ctx2));
    cshake256_inc_absorb(&ctx2, &iv, 1);
    cshake256_inc_finalize(&ctx2);
    cshake256_inc_squeeze(c, DIGITS, &ctx2);
    for (size_t i = 0; i < DIGITS; i++) {
        x[i] = psi(c[i]) + modulus(i);
    }
}

/* Expand public key from private key */
void PQCLEAN_NAMESPACE_get_pubkey(uint8_t *pk, const uint8_t *sk) {
    shake256incctx ctx;
    threebears_hash_init(&ctx, HASH_PURPOSE_KEYGEN);
    cshake256_inc_absorb(&ctx, sk, PRIVATE_KEY_BYTES);

    shake256incctx ctx2;
    memcpy(&ctx2, &ctx, sizeof(ctx2));
    cshake256_inc_finalize(&ctx2);
    cshake256_inc_squeeze(pk, MATRIX_SEED_BYTES, &ctx2);

    gf_t sk_expanded[DIM], b, c;
    for (size_t i = 0; i < DIM; i++) {
        noise(sk_expanded[i], &ctx, i);
    }
    for (size_t i = 0; i < DIM; i++) {
        noise(c, &ctx, i + DIM);
        for (size_t j = 0; j < DIM; j++) {
            uniform(b, pk, i + DIM * j);
            PQCLEAN_NAMESPACE_mac(c, b, sk_expanded[j]);
        }
        PQCLEAN_NAMESPACE_contract(&pk[MATRIX_SEED_BYTES + i * GF_BYTES], c);
    }
}

/* Encapsulate a shared secret and return it */
void PQCLEAN_NAMESPACE_encapsulate(
    uint8_t *shared_secret,
    uint8_t *capsule,
    const uint8_t *pk,
    const uint8_t *seed
) {
    uint8_t *lpr_data = &capsule[GF_BYTES * DIM];
    #if IV_BYTES
    uint8_t *iv = &lpr_data[(ENC_BITS * LPR_BITS + 7) / 8];
    memcpy(iv, &seed[ENC_SEED_BYTES], IV_BYTES);
    #endif

    shake256incctx ctx;
    threebears_hash_init(&ctx, HASH_PURPOSE_ENCAPS);
    cshake256_inc_absorb(&ctx, pk, MATRIX_SEED_BYTES);
    cshake256_inc_absorb(&ctx, seed, ENC_SEED_BYTES + IV_BYTES);

    gf_t sk_expanded[DIM], b, c;
    for (size_t i = 0; i < DIM; i++) {
        noise(sk_expanded[i], &ctx, i);
    }
    for (size_t i = 0; i < DIM; i++) {
        noise(c, &ctx, i + DIM);
        for (size_t j = 0; j < DIM; j++) {
            uniform(b, pk, j + DIM * i);
            PQCLEAN_NAMESPACE_mac(c, b, sk_expanded[j]);
        }
        PQCLEAN_NAMESPACE_contract(&capsule[i * GF_BYTES], c);
    }
    noise(c, &ctx, 2 * DIM);

    /* Calculate approximate shared secret */
    for (size_t i = 0; i < DIM; i++) {
        PQCLEAN_NAMESPACE_expand(b, &pk[MATRIX_SEED_BYTES + i * GF_BYTES]);
        PQCLEAN_NAMESPACE_mac(c, b, sk_expanded[i]);
    }
    PQCLEAN_NAMESPACE_canon(c);


    uint8_t tbi[ENC_SEED_BYTES + FEC_BYTES];
    #if CCA
    memcpy(tbi, seed, ENC_SEED_BYTES);
    #else
    cshake256_inc_finalize(&ctx);
    cshake256_inc_squeeze(tbi, ENC_SEED_BYTES, &ctx);
    threebears_hash_init(&ctx, HASH_PURPOSE_ENCAPS);
    cshake256_inc_absorb(&ctx, pk, MATRIX_SEED_BYTES);
    cshake256_inc_absorb(&ctx, tbi, ENC_SEED_BYTES);
    #if IV_BYTES
    cshake256_inc_absorb(&ctx, iv, IV_BYTES);
    #endif
    #endif /*!CCA*/

    #if FEC_BITS
    PQCLEAN_NAMESPACE_melas_fec_set(&tbi[ENC_SEED_BYTES], tbi, ENC_SEED_BYTES);
    #endif

    /* Export with rounding */
    for (size_t i = 0; i < ENC_BITS; i += 2) {
        limb_t h = tbi[i / 8] >> (i % 8);
        unsigned rlimb0 = (c[i / 2]          >> (LGX - LPR_BITS)) + (h << 3);
        unsigned rlimb1 = (c[DIGITS - i / 2 - 1] >> (LGX - LPR_BITS)) + ((h >> 1) << 3);
        lpr_data[i / 2] = (rlimb0 & 0xF) | rlimb1 << 4;
    }

    cshake256_inc_finalize(&ctx);
    cshake256_inc_squeeze(shared_secret, SHARED_SECRET_BYTES, &ctx);
}

/* Decapsulate a shared secret and return it */
void PQCLEAN_NAMESPACE_decapsulate(
    uint8_t shared_secret[SHARED_SECRET_BYTES],
    const uint8_t capsule[CAPSULE_BYTES],
    const uint8_t sk[PRIVATE_KEY_BYTES]
) {
    const uint8_t *lpr_data = &capsule[GF_BYTES*DIM];
    
    /* Calculate approximate shared secret */
    shake256incctx ctx;
    threebears_hash_init(&ctx,HASH_PURPOSE_KEYGEN);
    cshake256_inc_absorb(&ctx,sk,PRIVATE_KEY_BYTES);
    
    gf_t ska,b,c={0};
    for (unsigned i=0; i<DIM; i++) {
        PQCLEAN_NAMESPACE_expand(b,&capsule[i*GF_BYTES]);
        noise(ska,&ctx,i);
        PQCLEAN_NAMESPACE_mac(c,ska,b);
    }
    
    /* Recover seed from LPR data */
    uint8_t seed[ENC_SEED_BYTES+FEC_BYTES+IV_BYTES];
    PQCLEAN_NAMESPACE_canon(c);
    unsigned rounding = 1<<(LPR_BITS-1), out=0;
    for (signed i=ENC_BITS-1; i>=0; i--) {
        unsigned j = (i&1) ? DIGITS-i/2-1 : i/2;
        unsigned our_rlimb = c[j] >> (LGX-LPR_BITS-1);
        unsigned their_rlimb = lpr_data[i*LPR_BITS/8] >> ((i*LPR_BITS) % 8);
        unsigned delta =  their_rlimb*2 - our_rlimb + rounding;
        out |= ((delta>>LPR_BITS) & 1)<<(i%8);
        if (i%8==0) {
            seed[i/8] = out;
            out = 0;
        }
    }
#if FEC_BITS
    PQCLEAN_NAMESPACE_melas_fec_correct(seed,ENC_SEED_BYTES,&seed[ENC_SEED_BYTES]);
#endif
    
#if CCA
    /* Re-encapsulate and check; encapsulate will compute the shared secret */
    uint8_t pk[PUBLIC_KEY_BYTES], capsule2[CAPSULE_BYTES];
    PQCLEAN_NAMESPACE_get_pubkey(pk,sk);
#if IV_BYTES
    memcpy(&seed[ENC_SEED_BYTES],&lpr_data[(ENC_BITS*LPR_BITS+7)/8],IV_BYTES);
#endif
    PQCLEAN_NAMESPACE_encapsulate(shared_secret,capsule2,pk,seed);
    
    /* Check capsule == capsule2 in constant time */
    unsigned char ret = 0;
    for (unsigned i=0; i<CAPSULE_BYTES; i++) {
        ret |= capsule[i] ^ capsule2[i];
    }
    unsigned ok = ((int)ret - 1) >> 8;

    /* Calculate PRF key */
    uint8_t sep = 0xFF;
    uint8_t prfk[PRF_KEY_BYTES];
    cshake256_inc_absorb(&ctx,&sep,1);
    cshake256_inc_finalize(&ctx);
    cshake256_inc_squeeze(prfk, PRF_KEY_BYTES, &ctx);

    /* Calculate PRF */
    threebears_hash_init(&ctx,HASH_PURPOSE_PRF);
    cshake256_inc_absorb(&ctx,prfk,PRF_KEY_BYTES);
    cshake256_inc_absorb(&ctx,capsule,CAPSULE_BYTES);
    uint8_t prfout[SHARED_SECRET_BYTES];
    cshake256_inc_finalize(&ctx);
    cshake256_inc_squeeze(prfout, SHARED_SECRET_BYTES, &ctx);

    for (unsigned i=0; i<SHARED_SECRET_BYTES; i++) {
        shared_secret[i] = (shared_secret[i] & ok) | (prfout[i] & ~ok);
    }
#else /* !CCA */
    /* Recalculate matrix seed */
    uint8_t matrix_seed[MATRIX_SEED_BYTES];
    cshake256_inc_finalize(&ctx);
    cshake256_inc_squeeze(matrix_seed, MATRIX_SEED_BYTES, &ctx);
    
    /* Re-run the key derivation from encaps */
    threebears_hash_init(&ctx,HASH_PURPOSE_ENCAPS);
    cshake256_inc_absorb(&ctx,matrix_seed,MATRIX_SEED_BYTES);
    cshake256_inc_absorb(&ctx,seed,ENC_SEED_BYTES);
#if IV_BYTES
    cshake256_inc_absorb(&ctx,&lpr_data[(ENC_BITS*LPR_BITS+7)/8],IV_BYTES);
#endif
    cshake256_inc_finalize(&ctx);
    cshake256_inc_squeeze(shared_secret, SHARED_SECRET_BYTES, &ctx);
#endif
}

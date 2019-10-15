#ifndef __THREEBEARS_RING_H__
#define __THREEBEARS_RING_H__

#include "api.h"
#include "params.h"

typedef uint16_t limb_t;
typedef int16_t slimb_t;
typedef uint32_t dlimb_t;
typedef int32_t dslimb_t;
#define LMASK (((limb_t)1<<LGX)-1)
typedef limb_t gf_t[DIGITS];

/* Serialize a gf_t */
void PQCLEAN_NAMESPACE_contract(uint8_t ch[GF_BYTES], gf_t a);

/* Deserialize a gf_t */
void PQCLEAN_NAMESPACE_expand(gf_t ll, const uint8_t ch[GF_BYTES]);

/* Multiply and accumulate c = c + a*b */
void PQCLEAN_NAMESPACE_mac(gf_t c, const gf_t a, const gf_t b);

/* Reduce ring element to canonical form */
void PQCLEAN_NAMESPACE_canon(gf_t c);

/** Return the i'th limb of the modulus */
static inline limb_t modulus(size_t i) {
    return (i==DIGITS/2) ? LMASK-1 : LMASK;
}

#endif

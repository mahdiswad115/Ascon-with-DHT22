#ifndef ASCON_AEAD_H
#define ASCON_AEAD_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Encrypt: output = ciphertext || 16-byte tag
// clen will be set to mlen + 16 (for standard ASCON AEADs)
int ascon_aead128_encrypt(uint8_t *c, size_t *clen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *ad, size_t adlen,
                          const uint8_t *npub, const uint8_t *k);

int ascon_aead128_decrypt(uint8_t *m, size_t *mlen,
                          const uint8_t *c, size_t clen,
                          const uint8_t *ad, size_t adlen,
                          const uint8_t *npub, const uint8_t *k);

// Ascon-128a variants
int ascon_aead128a_encrypt(uint8_t *c, size_t *clen,
                           const uint8_t *m, size_t mlen,
                           const uint8_t *ad, size_t adlen,
                           const uint8_t *npub, const uint8_t *k);

int ascon_aead128a_decrypt(uint8_t *m, size_t *mlen,
                           const uint8_t *c, size_t clen,
                           const uint8_t *ad, size_t adlen,
                           const uint8_t *npub, const uint8_t *k);

#ifdef __cplusplus
}
#endif

#endif // ASCON_AEAD_H

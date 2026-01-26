#include "ascon_aead.h"
#include "crypto_aead.h"

int ascon_aead128_encrypt(uint8_t *c, size_t *clen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *ad, size_t adlen,
                          const uint8_t *npub, const uint8_t *k)
{
    unsigned long long outlen = 0;
    int rc = crypto_aead_encrypt(
        (unsigned char*)c, &outlen,
        (const unsigned char*)m, (unsigned long long)mlen,
        (const unsigned char*)ad, (unsigned long long)adlen,
        NULL,
        (const unsigned char*)npub,
        (const unsigned char*)k
    );
    *clen = (size_t)outlen;
    return rc;
}

int ascon_aead128_decrypt(uint8_t *m, size_t *mlen,
                          const uint8_t *c, size_t clen,
                          const uint8_t *ad, size_t adlen,
                          const uint8_t *npub, const uint8_t *k)
{
    unsigned long long outlen = 0;
    int rc = crypto_aead_decrypt(
        (unsigned char*)m, &outlen,
        NULL,
        (const unsigned char*)c, (unsigned long long)clen,
        (const unsigned char*)ad, (unsigned long long)adlen,
        (const unsigned char*)npub,
        (const unsigned char*)k
    );
    *mlen = (size_t)outlen;
    return rc;
}

// Your aead.c is Ascon-128a style (uses ASCON_128A_IV and ASCON_128A_RATE).
// Mapping 128a API to the same implementation is correct here.
int ascon_aead128a_encrypt(uint8_t *c, size_t *clen,
                           const uint8_t *m, size_t mlen,
                           const uint8_t *ad, size_t adlen,
                           const uint8_t *npub, const uint8_t *k)
{
    return ascon_aead128_encrypt(c, clen, m, mlen, ad, adlen, npub, k);
}

int ascon_aead128a_decrypt(uint8_t *m, size_t *mlen,
                           const uint8_t *c, size_t clen,
                           const uint8_t *ad, size_t adlen,
                           const uint8_t *npub, const uint8_t *k)
{
    return ascon_aead128_decrypt(m, mlen, c, clen, ad, adlen, npub, k);
}

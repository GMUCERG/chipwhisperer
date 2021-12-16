#include <stdint.h>
#include "supercop.h"


void kernelrandombytes( crypto_byte_t *,crypto_size_t);
void randombytes(       crypto_byte_t *,crypto_size_t);
crypto_size_t randombytes_calls;
crypto_size_t randombytes_bytes;



// PRNG
crypto_byte_t sc_rnd[CRYPTO_RNGBYTES];


// AEAD/HASH hash
crypto_byte_t sc_m[CRYPTO_NMBYTES]; // in
crypto_byte_t sc_c[CRYPTO_NCBYTES]; // out

// AEAD
crypto_byte_t sc_ad[CRYPTO_ABYTES];
crypto_byte_t sc_nsec[CRYPTO_NSECBYTES];
crypto_byte_t sc_npub[CRYPTO_NPUBBYTES];
crypto_byte_t sc_k[CRYPTO_KEYBYTES];

unsigned long long sc_m_len;
unsigned long long sc_c_len;
unsigned long long sc_ad_len;





int do_crypto_hash(){
    // from crypto_hash.h
    return crypto_hash(
    /*unsigned char *out*/          sc_c,
    /*const unsigned char *in */    sc_m,
    /*unsigned long long inlen*/    sc_m_len);
}

int do_crypto_aead_encrypt();
int do_crypto_aead_decrypt();
int do_crypto_rand_update();

int set_crypto_m(   const uint8_t * m, uint8_t len );
int set_crypto_c(   const uint8_t * m, uint8_t len );
int set_crypto_k(   const uint8_t * m, uint8_t len );
int set_crypto_ad(  const uint8_t * m, uint8_t len );
int set_crypto_nsec(const uint8_t * m, uint8_t len );
int set_crypto_npub(const uint8_t * m, uint8_t len );
int set_crypto_rand(const uint8_t * m, uint8_t len );


int get_crypto_result(uint8_t * b, uint8_t max);

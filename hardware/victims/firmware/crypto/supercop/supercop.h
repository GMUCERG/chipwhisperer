
#ifndef _SUPERCOP_H_
#define _SUPERCOP_H_

#include "api.h"
#include <stdint.h>



int do_crypto_hash();
int do_crypto_aead_encrypt();
int do_crypto_aead_decrypt();

// These functions are called by simpleserial to set up the vars

int set_crypto_m(   const uint8_t * m, uint8_t len ); // 'm'  message + hash in
int set_crypto_c(   const uint8_t * m, uint8_t len ); // 'c'  cipertext + hash out
int set_crypto_k(   const uint8_t * m, uint8_t len ); // 'k'
int set_crypto_ad(  const uint8_t * m, uint8_t len ); // 'a'
int set_crypto_nsec(const uint8_t * m, uint8_t len ); // 's'
int set_crypto_npub(const uint8_t * m, uint8_t len ); // 'p'
int set_crypto_seed(const uint8_t * m, uint8_t len ); // 'r'


int get_crypto_m(uint8_t * b, uint8_t max);
int get_crypto_c(uint8_t * b, uint8_t max);

int get_crypto_seed( void* b, uint8_t max); // extract the seed.

#ifndef CRYPTO_RNGBYTES
#define CRYPTO_RNGBYTES 16
#endif

#ifndef CRYPTO_NMBYTES
#define CRYPTO_NMBYTES 32
#endif

#ifndef CRYPTO_NCBYTES
#define CRYPTO_NCBYTES (CRYPTO_NMBYTES * 2)
#endif

// For HASH compatability
#ifdef SUPERCOP_HASH

#include "crypto_hash.h"

    #ifndef CRYPTO_BYTES
        #error "CRYPTO_BYTES (hash length) should be defined in api.h"
    #endif

#else

    // dummy value
    #ifndef CRYPTO_BYTES
        #define CRYPTO_BYTES 0
    #endif

#endif


// For AEAD compatability
#ifdef SUPERCOP_AEAD

#include "crypto_aead.h"

    #ifndef CRYPTO_KEYBYTES
        #error "crypto_aead: CRYPTO_KEYBYTES (key length) should be defined in api.h"
    #endif

    #ifndef CRYPTO_NSECBYTES
        #error "crypto_aead: CRYPTO_NSECBYTES should be defined in api.h, even if 0"
    #endif

    #ifndef CRYPTO_NPUBBYTES
        #error "crypto_aead: CRYPTO_NPUBBYTES should be defined in api.h"
    #endif

    #ifndef CRYPTO_ABYTES
        #error "crypto_aead: CRYPTO_ABYTES should be defined in api.h"
    #endif

    #ifndef CRYPTO_NOOVERLAP
        #error "crypto_aead: CRYPTO_NOOVERLAP should be defined as 1 in api.h"
    #endif

#else

    #ifndef CRYPTO_KEYBYTES
        #define CRYPTO_KEYBYTES     0
    #endif

    #ifndef CRYPTO_NSECBYTES
        #define CRYPTO_NSECBYTES    0
    #endif

    #ifndef CRYPTO_NPUBBYTES
        #define CRYPTO_NPUBBYTES    0
    #endif

    #ifndef CRYPTO_ABYTES
        #define CRYPTO_ABYTES       0
    #endif

    #ifndef CRYPTO_NOOVERLAP
        #define CRYPTO_NOOVERLAP    1
    #endif

#endif // expect AEAD



#endif

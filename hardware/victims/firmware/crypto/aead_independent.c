// cryptocop-style controller for AEAD encryption and decryption

#include "aead_independent.h"


// DEST | ENC | LEN | UNUSED
// AEAD inputs outputs
uint8_t c[MAX_LEN+CRYPTO_ABYTES];
uint8_t ad[MAX_LEN];
uint8_t m[MAX_LEN],m_len;
uint8_t npub[CRYPTO_NPUBBYTES];

uint8_t k[CRYPTO_KEYBYTES];
uint32_t initial_key[CRYPTO_KEYBYTES];
uint32_t clen,adlen,mlen;

uint8_t fixed_key = 0;

#ifdef __AEAD_IMPL_UCL_SPOOK

#include "api.h"
#include "prng.h"
#include "s1p.h"
#include "utils_masking.h"
#include "primitives.h"
#ifndef D
    #define D=1
#endif

#define MAX_LEN 16

// from parameters.h
#ifndef KEYBYTES
#define KEYBYTES 16
#endif

// from api.h
#define CRYPTO_KEYBYTES KEYBYTES
#define CRYPTO_NPUBBYTES 16
#define CRYPTO_NSECBYTES 0
#define CRYPTO_ABYTES 16
#define CRYPTO_NOOVERLAP 1





void aead_indep_enc_pretrigger(uint8_t* pt){
    init_rng(prng_state[0]);
    fill_table();
}


void aead_indep_enc_posttrigger(uint8_t*pt){
        if(fixed_key==0){
            for(int i=0;i<(4*D);i++){
                k[i] = get_random();
            }
        }else{
            simple_refresh(k,initial_key);
        }
}

void aead_indep_enc(uint8_t* pt){
        crypto_aead_encrypt(
                c,&clen,
                m,mlen,
                ad,adlen,
                NULL,npub,k);
}

// for(int n =0; n<N;n++){
//     init_rng(prng_state[0]);
//     fill_table();
//
//     HAL_GPIO_WritePin(GPIOC, LD4_Pin, GPIO_PIN_RESET); // trig on
//     HAL_GPIO_WritePin(GPIOB, GPIO_PIN_13, GPIO_PIN_SET); // trig on
//     crypto_aead_encrypt(
//             c,&clen,
//             m,mlen,
//             ad,adlen,
//             NULL,npub,k);
//     HAL_GPIO_WritePin(GPIOB, GPIO_PIN_13, GPIO_PIN_RESET); // trig of
//     HAL_GPIO_WritePin(GPIOC, LD4_Pin, GPIO_PIN_RESET); // trig on
//     /// END ENCRYPT
//
//     shadow(prng_state);             // exectute one shadow
//     memcpy(npub,&prng_state[1][0],16); // change the nonce
//     init_rng(prng_state[2]);       // reset prng
//     fill_table();
//
//     if(fixed_key==0){
//         for(int i=0;i<(4*D);i++){
//             k[i] = get_random();
//         }
//     }else{
//         simple_refresh(k,initial_key);
//     }
// }
// memcpy(initial_key,k,D*16);

#else

#error "AEAD algorithm Not Defined!"

#endif

//
//
// static uint8_t u8cpy(void* dest, void* src,  uint8_t len){
//     for(int i = 0; i < len; ++i){
//         dst[i] = src[i];
//     }
// }


// shared implementation(s)

void aead_indep_key(uint8_t * src){
    memcpy(k, src, CRYPTO_KEYBYTES);
}

void aead_indep_ad(uint8_t * src){
    memcpy(ad, src, CRYPTO_KEYBYTES);
}
void aead_indep_m(uint8_t * src, uint8_t len){
    memcpy(m, src, len);
}
void aead_indep_mask(uint8_t * src, uint8_t len){
    memcpy(npub, src, CRYPTO_NPUBBYTES);
}

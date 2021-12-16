#ifndef AEAD_INDPENDENT_H
#define AEAD_INDPENDENT_H

#ifndef KEY_LENGTH
#define KEY_LENGTH 16
#define DEFAULT_KEY 0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
#endif

#ifndef DEFAULT_KEY
#error "must define a default key"
#endif


#define AEAD_KEY_FIXED    (0x01)
#define AEAD_KEY_RANDOM   (0x00)


void aead_indep_init(uint8_t mode);
void aead_indep_key(uint8_t * key);
void aead_indep_ad(uint8_t * ad);
void aead_indep_m(uint8_t * m, uint8_t len);
void aead_indep_mask(uint8_t * m, uint8_t len);

// do the actual encryption
void aead_indep_enc(uint8_t * pt);
// before and after each round (note - DIFFERENT than AES!)
void aead_indep_enc_pretrigger(uint8_t * pt);
void aead_indep_enc_posttrigger(uint8_t * pt);



// ToDo: Decryption


#endif

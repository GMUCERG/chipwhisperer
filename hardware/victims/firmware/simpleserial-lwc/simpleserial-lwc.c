/*
    This file is part of the ChipWhisperer Example Targets
    Copyright (C) 2012-2017 NewAE Technology Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* Contributed by jdilles@gmu.edu */
/* Generic SimpleSerial for LWC (AEAD) */

#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>
#include <stdlib.h>

// ToDo: Refactor out into //#include "aead-independant.h"
#include "aead-independant.h"


// PRNG
shadow_state prng_state;
uint32_t seed[4];
uint32_t N;
uint32_t fixed_key;


uint8_t c[MAX_LEN+CRYPTO_ABYTES];
uint8_t ad[MAX_LEN];
uint8_t m[MAX_LEN],m_len;
uint8_t npub[CRYPTO_NPUBBYTES];
uint32_t k[(CRYPTO_KEYBYTES/4)*D];
uint32_t initial_key[4*D];
uint32_t clen,adlen,mlen;



static uint8_t u8cpy(void* dest, void* src,  uint8_t len){
    for(int i = 0; i < len; ++i){
        dst[i] = src[i];
    }
}

// Note that the bare minimum implementation for capture_trace is:
//    if key:
//        target.set_key(key, ack=ack)
//    if plaintext:
//        target.simpleserial_write('p', plaintext)
//    while not target.is_done():
//    response = target.simpleserial_read('r', target.output_len, ack=ack)



uint8_t get_key(uint8_t* nk, uint8_t len)
{
	aead_indep_key(nk, len);
	return 0x00;
}

uint8_t get_mask(uint8_t* m, uint8_t len)
{
  aead_indep_mask(m, len);
  return 0x00;
}

uint8_t get_pt(uint8_t* pt, uint8_t len)
{
    aead_indep_message(pt, len);

    aead_indep_enc_pretrigger(pt);

	trigger_high();

  #ifdef ADD_JITTER
  for (volatile uint8_t k = 0; k < (*pt & 0x0F); k++);
  #endif

	aead_indep_enc(pt); /* encrypting the data block */
	trigger_low();

    aead_indep_enc_posttrigger(pt);

	simpleserial_put('r', 16, pt);
	return 0x00;
}

uint8_t reset(uint8_t* x, uint8_t len)
{
    // Reset key here if needed
	return 0x00;
}

static uint16_t num_encryption_rounds = 10;

uint8_t enc_multi_getpt(uint8_t* pt, uint8_t len)
{
    aead_indep_message(pt, len);

    for(unsigned int i = 0; i < num_encryption_rounds; i++){
        // note! unlike AES, this has to happen inside loop to update nonce
        aead_indep_enc_pretrigger(pt);


        trigger_high();
        aead_indep_enc(pt);
        trigger_low();

        // note! unlike AES, this has to happen inside loop to update nonce
        aead_indep_enc_posttrigger(pt);
    }

	simpleserial_put('r', 16, pt);
    return 0;
}

uint8_t enc_multi_setnum(uint8_t* t, uint8_t len)
{
    //Assumes user entered a number like [0, 200] to mean "200"
    //which is most sane looking for humans I think
    num_encryption_rounds = t[1];
    num_encryption_rounds |= t[0] << 8;
    return 0;
}


// case 0:
//               dest = c;
//               clen = len;
//               break;
//           case 1:
//               dest = ad;
//               adlen = len;
//               break;
//           case 2:
//               dest = m;
//               mlen = len;
//               break;
//           case 3:
//               dest = npub;
//               break;
//           case 4:
//               dest = (uint8_t*) k;
//               break;
//           case 5:
//               dest = (uint8_t *) seed;
//               break;
//           case 6:
//               dest = (uint8_t *) &N;
//               break;
//           case 7:
//               dest = (uint8_t *) &fixed_key;
//               break;
//           default:
//               break;






#if SS_VER == SS_VER_2_1

uint8_t ss21_get_fixed(void* pdst, uint8_t n, uint8_t* plen, uint8_t** pbuf){
    uint8_t* dst = (uint8_t*)pdst;
    uint8_t* buf = *pbuf;
    uint8_t len = *plen;
    if(n > len)
        return SS_ERR_LEN;

    for(uint8_t i = 0; i < n; ++i)
        dst[i] = buf[i];

    // slice remaining buffer
    *pbuf += n; *plen -= n;
    return 0;
}

// read one length byte as n, then read n bytes into dst, up to max
uint8_t ss21_get_var(void* dst, uint8_t max, uint8_t* plen, uint8_t** pbuf){
    uint8_t n = 0, err;
    err = ss21_get_fixed(&n, 1, plen, pbuf);
    if(err) return err;
    if(n > max) return SS_ERR_LEN;
    err = ss21_get_fixed(dst, n, plen, pbuf);
    return err;
}


uint8_t info(uint8_t* x, uint8_t len)
{
        print("ChipWhisperer simpleserial-trace-ecc, compiled ");
        print(__DATE__);
        print(", ");
        print(__TIME__);
        print("\n");
	return 0x00;
}

// scmd     dest       bytes         lenvar
// 0x01 -> c           (var 1-256)   clen
// 0x02 -> ad          (var 1-256)   adlen
// 0x04 -> m           (var 1-255)   mlen
// 0x08 -> npub        16
// 0x10 -> k           16 * D
// 0x20 -> seed
// 0x40 -> N
// 0x80 -> fixed_key
//
uint8_t aead(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
{
    uint8_t err = 0;
    if(!scmd) return SS_ERR_CMD;

    if(scmd & 0x80) err = ss21_get_fixed( &fixed_key, 4, &len, &buf);
    if(err) return err;
    if(scmd & 0x40) err = ss21_get_fixed( &N, 4, &len, &buf);
    if(err) return err;
    if(scmd & 0x20) err = ss21_get_fixed( seed, 16, &len, &buf);
    if(err) return err;
    if(scmd & 0x10) err = ss21_get_fixed( k, 16*D, &len, &buf);
    if(err) return err;
    if(scmd & 0x08) err = ss21_get_fixed( npub, CRYPTO_NPUBBYTES, &len, &buf);
    if(err) return err;
    if(scmd & 0x04) err = ss21_get_var( m, MAX_LEN, &len, &buf);
    if(err) return err;
    if(scmd & 0x02) err = ss21_get_var( ad, MAX_LEN,&len, &buf);
    if(err) return err;
    if(scmd & 0x01) err = ss21_get_var( c, MAX_LEN, &len, &buf);
    if(err) return err;

    if(len) return SS_ERR_LEN;


    uint8_t req_len = 0;
    uint8_t mask_len = 0;
    if (scmd & 0x04) {
        // Mask has variable length. First byte encodes the length
        mask_len = buf[req_len];
        req_len += 1 + mask_len;
        if (req_len > len) {
            return SS_ERR_LEN;
        }
        err = get_mask(buf + req_len - mask_len, mask_len);
        if (err)
            return err;
    }

    if (scmd & 0x02) {
        req_len += 16;
        if (req_len > len) {
            return SS_ERR_LEN;
        }
        err = get_key(buf + req_len - 16, 16);
        if (err)
            return err;
    }
    if (scmd & 0x01) {
        req_len += 16;
        if (req_len > len) {
            return SS_ERR_LEN;
        }
        err = get_pt(buf + req_len - 16, 16);
        if (err)
            return err;
    }

    if (len != req_len) {
        return SS_ERR_LEN;
    }

    return 0x00;

}
#endif

int main(void)
{
	uint8_t tmp[KEY_LENGTH] = {DEFAULT_KEY};

    platform_init();
    init_uart();
    trigger_setup();

	aead_indep_init();
	aead_indep_key(tmp);

    /* Uncomment this to get a HELLO message for debug */

    // putch('h');
    // putch('e');
    // putch('l');
    // putch('l');
    // putch('o');
    // putch('\n');

	simpleserial_init();
    #if SS_VER == SS_VER_2_1
    simpleserial_addcmd(0x01, 16, aead);
    #else
    simpleserial_addcmd('k', 16, get_key);
    simpleserial_addcmd('p', 16,  get_pt);
    simpleserial_addcmd('x',  0,   reset);
    // simpleserial_addcmd_flags('m', 18, get_mask, CMD_FLAG_LEN);
    simpleserial_addcmd('s', 2, enc_multi_setnum);
    simpleserial_addcmd('f', 16, enc_multi_getpt);
    #endif
    while(1)
        simpleserial_get();
}

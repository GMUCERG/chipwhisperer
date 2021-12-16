/*
 * Copyright 2020 UCLouvain
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdint.h>
#include "prng.h"
#include "randombytes.h"
#include "kernelrandombytes.h"
#include "supercop.h"


unsigned long long randombytes_calls = 0;
unsigned long long randombytes_bytes = 0;

#ifdef TRACK_RANDOMBYTES
#define PRNG_STATS(n) do { randombytes_bytes += (n); } while(++randombytes_calls == 0)
#else
#define PRNG_STATS(n) do{ ; }while(0)
#endif

#if CRYPTO_RNGBYTES==0

// PRNG Disabled


void fill_table(){
    return;
}
void init_rng(uint32_t *seed){
    return;
}

uint32_t get_random(){
    PRNG_STATS(4);

    return 0;
}

void randombytes(unsigned char * m,unsigned long long n){
    PRNG_STATS(n);

    while(n-->0) *m++ = 0;
}

#else // enabled

#include "tinymt32.h"

#define MAX (1+CRYPTO_RNGBYTES/4)

static tinymt32_t random;
static uint32_t prng_tab[MAX];
static uint32_t prng_index;

void fill_table(){
    for(int i=0;i<MAX;++i){
        tinymt32_next_state(random);
        prng_tab[i] = tinymt32_temper(random);
    }
    prng_index = 0;
}

void init_rng(uint32_t *seed){
    memset(prng_state_core,0,64);
    memcpy(prng_state_core[0],seed,16);
    prng_index = MAX;
}

uint32_t get_random(){
    PRNG_STATS(4);

    if(prng_index >= MAX)
        fill_table();

    return prng_tab[++prng_index];

}


void randombytes(unsigned char * m,unsigned long long n){
    PRNG_STATS(n);

    while(n-->0) *m++ = 0;
}



#endif // check CRYPTO_RNGBYTES


void kernelrandombytes(unsigned char * m,unsigned long long n){
    randombytes(m, n);
}

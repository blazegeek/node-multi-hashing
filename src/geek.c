#include "geek.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_echo.h"
#include "sha3/sph_shabal.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_hamsi.h"
#include "sha3/sph_simd.h"

void geek_hash(const char* input, char* output, uint32_t len)
{
	sph_blake512_context	ctx_blake;
	sph_bmw512_context		ctx_bmw;
	sph_echo512_context		ctx_echo;
	sph_shabal512_context	ctx_shabal;
	sph_groestl512_context	ctx_groestl;    
	sph_cubehash512_context		ctx_cubehash;      
	sph_keccak512_context	ctx_keccak;    
	sph_hamsi512_context	ctx_hamsi;
	sph_simd512_context		ctx_simd;

	// These uint512 in the c++ source of the client are backed by an array of uint32
	uint32_t hashA[16], hashB[16];	

	sph_blake512_init(&ctx_blake);
	sph_blake512 (&ctx_blake, input, len);
	sph_blake512_close(&ctx_blake, hashA);

	sph_bmw512_init(&ctx_bmw);
	sph_bmw512 (&ctx_bmw, hashA, 64);
	sph_bmw512_close(&ctx_bmw, hashB);

	sph_echo512_init(&ctx_echo); 
	sph_echo512 (&ctx_echo, hashB, 64);   
	sph_echo512_close(&ctx_echo, hashA); 

	sph_shabal512_init(&ctx_shabal);
	sph_shabal512 (&ctx_shabal, hashA, 64);
	sph_shabal512_close(&ctx_shabal, hashB);

	sph_groestl512_init(&ctx_groestl);
	sph_groestl512 (&ctx_groestl, hashB, 64);
	sph_groestl512_close(&ctx_groestl, hashA);

	sph_cubehash512_init(&ctx_cubehash); 
	sph_cubehash512 (&ctx_cubehash, hashA, 64);   
	sph_cubehash512_close(&ctx_cubehash, hashB);    
	
	sph_keccak512_init(&ctx_keccak);
	sph_keccak512 (&ctx_keccak, hashB, 64);
	sph_keccak512_close(&ctx_keccak, hashA);

	sph_hamsi512_init(&ctx_hamsi);
	sph_hamsi512 (&ctx_hamsi, hashA, 64);
	sph_hamsi512_close(&ctx_hamsi, hashB);    

	sph_simd512_init(&ctx_simd); 
	sph_simd512 (&ctx_simd, hashB, 64);   
	sph_simd512_close(&ctx_simd, hashA); 

	memcpy(output, hashA, 32);
}

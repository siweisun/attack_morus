#include <string.h>
#include <immintrin.h>
#include <stdio.h>
#include <stdint.h>
#include "crypto_aead.h"

/*define data alignment for different C compilers*/
#if defined(__GNUC__)
#define DATA_ALIGN32(x) x __attribute__ ((aligned(32)))
#else
#define DATA_ALIGN32(x) __declspec(align(32)) x
#endif

#ifdef _MSC_VER
#define  inline __inline
#endif

#define n1 13
#define n2 46
#define n3 38
#define n4 7
#define n5 4

#define XOR256(x,y)       _mm256_xor_si256((x),(y))        /*XOR256(x,y) = x ^ y, where x and y are two 256-bit word*/
#define AND256(x,y)       _mm256_and_si256((x),(y))        /*AND(x,y) = x & y, where x and y are two 256-bit word*/
#define ANDNOT256(x,y)    _mm256_andnot_si256((x),(y))     /*ANDNOT(x,y) = (!x) & y, where x and y are two 256-bit word*/
#define OR256(x,y)        _mm256_or_si256((x),(y))         /*OR(x,y)  = x | y, where x and y are two 256-bit word*/
#define SETZERO256()      _mm256_setzero_si256()           /*set the value of 256-bit register to zero*/
#define SETONE256()       _mm256_set_epi32(0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff)  /*set each bit in the 256-bit register to 1*/

#define XOR(x,y)          _mm_xor_si128((x),(y))       /*XOR(x,y) = x ^ y, where x and y are two 128-bit word*/
#define AND(x,y)          _mm_and_si128((x),(y))       /*AND(x,y) = x & y, where x and y are two 128-bit word*/
#define ANDNOT(x,y)       _mm_andnot_si128((x),(y))    /*ANDNOT(x,y) = (!x) & y, where x and y are two 128-bit word*/
#define OR(x,y)           _mm_or_si128((x),(y))        /*OR(x,y)  = x | y, where x and y are two 128-bit word*/
#define SETZERO()         _mm_setzero_si128()          /*set the value of 128-bit register to zero*/
#define SETONE()          _mm_set_epi8(0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, 0xff) /*set each bit in the 128-bit register to 1*/

#define ROTL256(x,n)      OR256( _mm256_slli_epi64((x), (n)), _mm256_srli_epi64((x),(64-n)) )   /*Rotate 4 64-bit unsigned integers in x to the left by n-bit positions*/

#define ROTL256_64(x)     _mm256_permute4x64_epi64((x), _MM_SHUFFLE(2,1,0,3))  /*Rotate x by 64-bit  positions to the left*/
#define ROTL256_128(x)    _mm256_permute4x64_epi64((x), _MM_SHUFFLE(1,0,3,2))  /*Rotate x by 128-bit positions to the left*/
#define ROTL256_192(x)    _mm256_permute4x64_epi64((x), _MM_SHUFFLE(0,3,2,1))  /*Rotate x by 192-bit positions to the left*/

#define SHIFTL256_64(x)   _mm256_slli_si256((x), 4)                    /*Shift each 128-bit words in x by 32-bit  positions to the left*/

#define STORE(x,p)        _mm_store_si128((__m128i *)(p), (x))         /*store the 128-bit word x into memeory address p, where p is the multile of 16 bytes*/
#define LOAD(p)           _mm_load_si128((__m128i *)(p))               /*load 16 bytes from the memory address p, return a 128-bit word, where p is the multile of 16 bytes*/

#define STORE256(x,p)     _mm256_store_si256((__m256i *)(p), (x))         /*store the 256-bit word x into memeory address p, where p is the multile of 32 bytes*/
#define LOAD256(p)        _mm256_load_si256((__m256i *)(p))               /*load 32 bytes from the memory address p, return a 256-bit word, where p is the multile of 32 bytes*/

/*
void printfxmm(__m256i *state)    //print the state, used for debugging
{
		 int i,j;
		 DATA_ALIGN32(unsigned char t[32]);

		 for (i = 0; i < 5; i++) {
				_mm256_store_si256((__m256i*)t, state[i]);
				printf("\n");
				for (j = 0; j < 32; j++) printf("%2x",t[j]);
				printf("\n");
		 }
}
*/

void morus_stateupdate(__m256i msgblk, __m256i *state)
{
	state[0] = XOR256(state[0], state[3]);
	state[0] = XOR256(state[0], AND256(state[1], state[2]));
	state[0] = ROTL256(state[0], n1);
	state[3] = ROTL256_64(state[3]);

	state[1] = XOR256(state[1], msgblk);
	state[1] = XOR256(state[1], state[4]);
	state[1] = XOR256(state[1], AND256(state[2], state[3]));
	state[1] = ROTL256(state[1], n2);
	state[4] = ROTL256_128(state[4]);

	state[2] = XOR256(state[2], msgblk);
	state[2] = XOR256(state[2], state[0]);
	state[2] = XOR256(state[2], AND256(state[3], state[4]));
	state[2] = ROTL256(state[2], n3);
	state[0] = ROTL256_192(state[0]);

	state[3] = XOR256(state[3], msgblk);
	state[3] = XOR256(state[3], state[1]);
	state[3] = XOR256(state[3], AND256(state[4], state[0]));
	state[3] = ROTL256(state[3], n4);
	state[1] = ROTL256_128(state[1]);

	state[4] = XOR256(state[4], msgblk);
	state[4] = XOR256(state[4], state[2]);
	state[4] = XOR256(state[4], AND256(state[0], state[1]));
	state[4] = ROTL256(state[4], n5);
	state[2] = ROTL256_64(state[2]);
}

/* The input to the initialization is the 128-bit key; 128-bit IV; */
void morus_initialization(__m256i *state)
{
    int i;
    for (i = 0; i < 5; i++){
        uint8_t e0 = rand() % 256; //printf("%02X", e0);
        uint8_t e1 = rand() % 256; //printf("%02X", e1);
        uint8_t e2 = rand() % 256; //printf("%02X", e2);
        uint8_t e3 = rand() % 256; //printf("%02X", e3);
        uint8_t e4 = rand() % 256; //printf("%02X", e4);
        uint8_t e5 = rand() % 256; //printf("%02X", e5);
        uint8_t e6 = rand() % 256; //printf("%02X", e6);
        uint8_t e7 = rand() % 256; //printf("%02X", e7);
        uint8_t e8 = rand() % 256; //printf("%02X", e8);
        uint8_t e9 = rand() % 256; //printf("%02X", e9);
        uint8_t e10 = rand() % 256; //printf("%02X", e10);
        uint8_t e11 = rand() % 256; //printf("%02X", e11);
        uint8_t e12 = rand() % 256; //printf("%02X", e12);
        uint8_t e13 = rand() % 256; //printf("%02X", e13);
        uint8_t e14 = rand() % 256; //printf("%02X", e14);
        uint8_t e15 = rand() % 256; //printf("%02X", e15);
        uint8_t e16 = rand() % 256; //printf("%02X", e0);
        uint8_t e17 = rand() % 256; //printf("%02X", e1);
        uint8_t e18 = rand() % 256; //printf("%02X", e2);
        uint8_t e19 = rand() % 256; //printf("%02X", e3);
        uint8_t e20 = rand() % 256; //printf("%02X", e4);
        uint8_t e21 = rand() % 256; //printf("%02X", e5);
        uint8_t e22 = rand() % 256; //printf("%02X", e6);
        uint8_t e23 = rand() % 256; //printf("%02X", e7);
        uint8_t e24 = rand() % 256; //printf("%02X", e8);
        uint8_t e25 = rand() % 256; //printf("%02X", e9);
        uint8_t e26 = rand() % 256; //printf("%02X", e10);
        uint8_t e27 = rand() % 256; //printf("%02X", e11);
        uint8_t e28 = rand() % 256; //printf("%02X", e12);
        uint8_t e29 = rand() % 256; //printf("%02X", e13);
        uint8_t e30 = rand() % 256; //printf("%02X", e14);
        uint8_t e31 = rand() % 256; //printf("%02X", e15);
/*
        state[i] = _mm256_set_epi8(0xdd, 0x28, 0xb5, 0x73, 0x42, 0x31, 0x11, 0x20, \
                                   0xf1, 0x2f, 0xc2, 0x6d, 0x55, 0x18, 0x3d, 0xdb, \
                                   0x62, 0x79, 0xe9, 0x90, 0x59, 0x37, 0x22, 0x15, \
                                   0x0d, 0x08, 0x05, 0x03, 0x02, 0x01, 0x01, 0x00);
*/
        state[i] = _mm256_set_epi8(e0,  e1,  e2,   e3,  e4,  e5,  e6,  e7, \
                                   e8,  e9,  e10,  e11, e12, e13, e14, e15, \
                                   e16, e17, e18,  e19, e20, e21, e22, e23, \
                                   e24, e25, e26,  e27, e28, e29, e30, e31);

    }

//    printf("After init:\n");
//    print_five_m256i(state);

}

// one step of encryption: it encrypts a 32-byte block
inline void morus_enc_aut_step(const unsigned char *plaintext,
	unsigned char *ciphertext, __m256i *state,\
	unsigned char *updatedState0, \
	unsigned char *updatedState1, \
	unsigned char *updatedState2, \
	unsigned char *updatedState3, \
	unsigned char *updatedState4  )
{
	__m256i keystream;
	__m256i msgblk = _mm256_loadu_si256((__m256i*)plaintext);

	//encryption
	keystream = XOR256(state[0], ROTL256_192(state[1]));
	keystream = XOR256(keystream, AND256(state[2], state[3]));
	_mm256_storeu_si256((__m256i*)ciphertext, XOR256(keystream, msgblk));

	state[0] = XOR256(state[0], state[3]);
	state[0] = XOR256(state[0], AND256(state[1], state[2]));
	state[0] = ROTL256(state[0], n1);
	state[3] = ROTL256_64(state[3]);

	state[1] = XOR256(state[1], msgblk);
	state[1] = XOR256(state[1], state[4]);
	state[1] = XOR256(state[1], AND256(state[2], state[3]));
	state[1] = ROTL256(state[1], n2);
	state[4] = ROTL256_128(state[4]);

	state[2] = XOR256(state[2], msgblk);
	state[2] = XOR256(state[2], state[0]);
	state[2] = XOR256(state[2], AND256(state[3], state[4]));
	state[2] = ROTL256(state[2], n3);
	state[0] = ROTL256_192(state[0]);

	state[3] = XOR256(state[3], msgblk);
	state[3] = XOR256(state[3], state[1]);
	state[3] = XOR256(state[3], AND256(state[4], state[0]));
	state[3] = ROTL256(state[3], n4);
	state[1] = ROTL256_128(state[1]);

	state[4] = XOR256(state[4], msgblk);
	state[4] = XOR256(state[4], state[2]);
	state[4] = XOR256(state[4], AND256(state[0], state[1]));
	state[4] = ROTL256(state[4], n5);
	state[2] = ROTL256_64(state[2]);
/*
	printf("updated state:\n");
	print_five_m256i(state);
*/
	_mm256_storeu_si256((__m256i*)updatedState0, state[0]);
	_mm256_storeu_si256((__m256i*)updatedState1, state[1]);
	_mm256_storeu_si256((__m256i*)updatedState2, state[2]);
	_mm256_storeu_si256((__m256i*)updatedState3, state[3]);
	_mm256_storeu_si256((__m256i*)updatedState4, state[4]);
}

//encrypt a message
int crypto_aead_encrypt_1block(
	const unsigned char *m, unsigned char *c,\
    unsigned char *state_1_0,\
    unsigned char *state_1_1,\
    unsigned char *state_1_2,\
    unsigned char *state_1_3,\
    unsigned char *state_1_4\
	)
{

	__m256i morus_state[5];

	//initialization stage
	morus_initialization(morus_state);

	//encrypt the plaintext
    morus_enc_aut_step(m, c, morus_state, state_1_0, state_1_1, state_1_2, state_1_3, state_1_4);

	return 0;
}

int crypto_aead_encrypt_2blocks(
	const unsigned char *m,
	unsigned char *c_0,\
	unsigned char *c_1,\
    unsigned char *state_1_0,\
    unsigned char *state_1_1,\
    unsigned char *state_1_2,\
    unsigned char *state_1_3,\
    unsigned char *state_1_4,\
    unsigned char *state_2_0,\
    unsigned char *state_2_1,\
    unsigned char *state_2_2,\
    unsigned char *state_2_3,\
    unsigned char *state_2_4
	)
{

	__m256i morus_state[5];

	//initialization stage
	morus_initialization(morus_state);

	//encrypt the plaintext
    morus_enc_aut_step(m, c_0, morus_state, state_1_0, state_1_1, state_1_2, state_1_3, state_1_4);
    morus_enc_aut_step(m, c_1, morus_state, state_2_0, state_2_1, state_2_2, state_2_3, state_2_4);

	return 0;
}


int crypto_aead_encrypt_3blocks(
	const unsigned char *m,
	unsigned char *c_0,\
	unsigned char *c_1,\
	unsigned char *c_2,\
    unsigned char *state_1_0,\
    unsigned char *state_1_1,\
    unsigned char *state_1_2,\
    unsigned char *state_1_3,\
    unsigned char *state_1_4,\
    unsigned char *state_2_0,\
    unsigned char *state_2_1,\
    unsigned char *state_2_2,\
    unsigned char *state_2_3,\
    unsigned char *state_2_4,\
    unsigned char *state_3_0,\
    unsigned char *state_3_1,\
    unsigned char *state_3_2,\
    unsigned char *state_3_3,\
    unsigned char *state_3_4
	)
{

	__m256i morus_state[5];

	//initialization stage
	morus_initialization(morus_state);

	//encrypt the plaintext
    morus_enc_aut_step(m, c_0, morus_state, state_1_0, state_1_1, state_1_2, state_1_3, state_1_4);
    morus_enc_aut_step(m, c_1, morus_state, state_2_0, state_2_1, state_2_2, state_2_3, state_2_4);
    morus_enc_aut_step(m, c_2, morus_state, state_3_0, state_3_1, state_3_2, state_3_3, state_3_4);

	return 0;
}

int crypto_aead_encrypt_4blocks(
	const unsigned char *m,
	unsigned char *c_0,\
	unsigned char *c_1,\
	unsigned char *c_2,\
	unsigned char *c_3,\
    unsigned char *state_1_0,\
    unsigned char *state_1_1,\
    unsigned char *state_1_2,\
    unsigned char *state_1_3,\
    unsigned char *state_1_4,\
    unsigned char *state_2_0,\
    unsigned char *state_2_1,\
    unsigned char *state_2_2,\
    unsigned char *state_2_3,\
    unsigned char *state_2_4,\
    unsigned char *state_3_0,\
    unsigned char *state_3_1,\
    unsigned char *state_3_2,\
    unsigned char *state_3_3,\
    unsigned char *state_3_4,\
    unsigned char *state_4_0,\
    unsigned char *state_4_1,\
    unsigned char *state_4_2,\
    unsigned char *state_4_3,\
    unsigned char *state_4_4
	)
{

	__m256i morus_state[5];

	//initialization stage
	morus_initialization(morus_state);

	//encrypt the plaintext
    morus_enc_aut_step(m, c_0, morus_state, state_1_0, state_1_1, state_1_2, state_1_3, state_1_4);
    morus_enc_aut_step(m, c_1, morus_state, state_2_0, state_2_1, state_2_2, state_2_3, state_2_4);
    morus_enc_aut_step(m, c_2, morus_state, state_3_0, state_3_1, state_3_2, state_3_3, state_3_4);
    morus_enc_aut_step(m, c_3, morus_state, state_4_0, state_4_1, state_4_2, state_4_3, state_4_4);


	return 0;
}


/* -------------------
    Helper functions
-----------------------*/
void print_five_m256i(__m256i *state)
{
    uint8_t *val = (uint8_t*) state;
    printf("state:\n");

    int i;
    int j;

    for (i = 0; i < 5; i++){
        printf("S%d: ", i);

        for (j = 0; j < 32; j++){
            printf("%02X", val[i*32 + (31-j)]);
        }
        printf("\n");
    }

}

void print_m256i(__m256i state)
{
    uint8_t *val = (uint8_t*) &state;
    int i;
    printf("state: ");
    for (i = 0; i < 32; i++){
        printf("%02X", val[31-i]);
    }

    printf("\n");

}

void print1block(unsigned char *d)
{
    int i = 0;
    for (i = 0; i < 32; i++) printf("%02X", d[31-i]);
    printf("\n");
}


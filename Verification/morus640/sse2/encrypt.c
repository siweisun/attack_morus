#include <string.h>
#include <immintrin.h>
#include <stdint.h>
#include "crypto_aead.h"

#ifdef _MSC_VER
#define inline __inline
#define _mm_store_si128 _mm_storeu_si128
#define _mm_load_si128 _mm_loadu_si128
#endif

#define n1 5
#define n2 31
#define n3 7
#define n4 22
#define n5 13

#define XOR(x,y)       _mm_xor_si128((x),(y))     /*XOR(x,y) = x ^ y, where x and y are two 128-bit word*/
#define AND(x,y)       _mm_and_si128((x),(y))     /*AND(x,y) = x & y, where x and y are two 128-bit word*/
#define ANDNOT(x,y)    _mm_andnot_si128((x),(y))  /*ANDNOT(x,y) = (!x) & y, where x and y are two 128-bit word*/
#define OR(x,y)        _mm_or_si128((x),(y))      /*OR(x,y)  = x | y, where x and y are two 128-bit word*/
#define SETZERO()      _mm_setzero_si128()        /*set the value of 128-bit register to zero*/
#define SETONE()       _mm_set_epi32(0xffffffff,0xffffffff,0xffffffff,0xffffffff)  /*set each bit in the 128-bit register to 1*/

#define ROTL(x,n)      XOR(_mm_slli_epi32((x), (n)),  _mm_srli_epi32((x),(32-n)))  /*Rotate 4 32-bit unsigned integers in x to the left by n-bit positions*/
#define ROTL8(x)       _mm_shuffle_epi8((x), _mm_set_epi8(14,13,12,11,10,9,8,7,6,5,4,3,2,1,0,15) )  /*Rotate 4 32-bit unsigned integers in x to the left by 8-bit positions*/

#define ROTL32(x)      _mm_shuffle_epi32((x),_MM_SHUFFLE(2,1,0,3))   /*Rotate x by 32-bit positions to the left*/
#define ROTL64(x)      _mm_shuffle_epi32((x),_MM_SHUFFLE(1,0,3,2))   /*Rotate x by 64-bit positions to the left*/
#define ROTL96(x)      _mm_shuffle_epi32((x),_MM_SHUFFLE(0,3,2,1))   /*Rotate x by 96-bit positions to the left*/

#define STORE(x,p)     _mm_store_si128((__m128i *)(p), (x))         /*store the 128-bit word x into memeory address p, where p is the multile of 16 bytes*/
#define LOAD(p)        _mm_load_si128((__m128i *)(p))               /*load 16 bytes from the memory address p, return a 128-bit word, where p is the multile of 16 bytes*/

void morus_stateupdate(__m128i msgblk, __m128i *state)
{

	state[0] = XOR(state[0], state[3]);
	state[0] = XOR(state[0], AND(state[1], state[2]));
	state[0] = ROTL(state[0], n1);
	state[3] = ROTL32(state[3]);


	state[1] = XOR(state[1], msgblk);
	state[1] = XOR(state[1], state[4]);
	state[1] = XOR(state[1], AND(state[2], state[3]));
	state[1] = ROTL(state[1], n2);
	state[4] = ROTL64(state[4]);


	state[2] = XOR(state[2], msgblk);
	state[2] = XOR(state[2], state[0]);
	state[2] = XOR(state[2], AND(state[3], state[4]));
	state[2] = ROTL(state[2], n3);
	state[0] = ROTL96(state[0]);


	state[3] = XOR(state[3], msgblk);
	state[3] = XOR(state[3], state[1]);
	state[3] = XOR(state[3], AND(state[4], state[0]));
	state[3] = ROTL(state[3], n4);
	state[1] = ROTL64(state[1]);


	state[4] = XOR(state[4], msgblk);
	state[4] = XOR(state[4], state[2]);
	state[4] = XOR(state[4], AND(state[0], state[1]));
	state[4] = ROTL(state[4], n5);
	state[2] = ROTL32(state[2]);


}


/*The input to the initialization is the 128-bit key; 128-bit IV;*/
void morus_initialization(__m128i *state)
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
        //printf("\n");
        //_mm_store_si128((__m128i*)t, state[0]);
        //state[i] = _mm_set_epi16(e0, e1, e2, e3, e4, e5, e6, e7);
        state[i] = _mm_set_epi8(e0, e1,e2,e3,e4,e5,e6,e7,e8,e9,e10,e11,e12,e13,e14,e15);
    }

   // print_five_m128i(state);

}

// one step of encryption: it encrypts a 16-byte block
static inline void morus_enc_aut_step(const unsigned char *plaintextblock,\
	unsigned char *ciphertextblock, __m128i *state, \
	unsigned char *updatedState0, \
	unsigned char *updatedState1, \
	unsigned char *updatedState2, \
	unsigned char *updatedState3, \
	unsigned char *updatedState4 \
	)
{
	__m128i keystream;
	__m128i msgblk = _mm_load_si128((__m128i*)plaintextblock);

	//encryption
	keystream = XOR(state[0], ROTL96(state[1]));
	keystream = XOR(keystream, AND(state[2], state[3]));
	_mm_store_si128((__m128i*)ciphertextblock, XOR(keystream, msgblk));

	//state update
	morus_stateupdate(msgblk, state);

	//store the updated state
	_mm_store_si128((__m128i*)updatedState0, state[0]);
	_mm_store_si128((__m128i*)updatedState1, state[1]);
	_mm_store_si128((__m128i*)updatedState2, state[2]);
	_mm_store_si128((__m128i*)updatedState3, state[3]);
	_mm_store_si128((__m128i*)updatedState4, state[4]);

	//printf("In update:\n");
	//print_five_m128i(state);

}


//encrypt a message
int crypto_aead_encrypt_1block(const unsigned char *m, unsigned char *c,\
                                unsigned char *state_1_0,\
                                unsigned char *state_1_1,\
                                unsigned char *state_1_2,\
                                unsigned char *state_1_3,\
                                unsigned char *state_1_4\
                                )
{

	__m128i morus_state[5];

	//initialization
	morus_initialization(morus_state);

	//encrypt the plaintext
	morus_enc_aut_step(m, c, morus_state, state_1_0, state_1_1,state_1_2,state_1_3,state_1_4);

	//printf("Updated state:\n");
	//print_five_m128i(morus_state);

	//printf("-------------------\n");
	//print1block((__m128i*)state_1_0); printf("\n");
	//print1block((__m128i*)state_1_1); printf("\n");
	//print1block((__m128i*)state_1_2); printf("\n");
	//print1block((__m128i*)state_1_3); printf("\n");
	//print1block((__m128i*)state_1_4); printf("\n");

	return 0;
}


int crypto_aead_encrypt_2blocks(const unsigned char *m,
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

	__m128i morus_state[5];

	//initialization
	morus_initialization(morus_state);

    //print_five_m128i(morus_state);

	//encrypt the plaintext
	morus_enc_aut_step(m, c_0, morus_state, state_1_0, state_1_1,state_1_2,state_1_3,state_1_4);
	//print_five_m128i(morus_state);

	morus_enc_aut_step(m, c_1, morus_state, state_2_0, state_2_1,state_2_2,state_2_3,state_2_4);
	//print_five_m128i(morus_state);

	return 0;
}

int crypto_aead_encrypt_3blocks(const unsigned char *m,
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

	__m128i morus_state[5];

	//initialization
	morus_initialization(morus_state);

	//encrypt the plaintext
	morus_enc_aut_step(m, c_0, morus_state, state_1_0, state_1_1,state_1_2,state_1_3,state_1_4);
	morus_enc_aut_step(m, c_1, morus_state, state_2_0, state_2_1,state_2_2,state_2_3,state_2_4);
	morus_enc_aut_step(m, c_2, morus_state, state_3_0, state_3_1,state_3_2,state_3_3,state_3_4);

	//printf("Updated state:\n");
	//print_five_m128i(morus_state);

	//printf("-------------------\n");
	//print1block((__m128i*)state_1_0); printf("\n");
	//print1block((__m128i*)state_1_1); printf("\n");
	//print1block((__m128i*)state_1_2); printf("\n");
	//print1block((__m128i*)state_1_3); printf("\n");
	//print1block((__m128i*)state_1_4); printf("\n");

	return 0;
}


int crypto_aead_encrypt_4blocks(const unsigned char *m,
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

	__m128i morus_state[5];

	//initialization
	morus_initialization(morus_state);

	//encrypt the plaintext
	morus_enc_aut_step(m, c_0, morus_state, state_1_0, state_1_1,state_1_2,state_1_3,state_1_4);
	morus_enc_aut_step(m, c_1, morus_state, state_2_0, state_2_1,state_2_2,state_2_3,state_2_4);
	morus_enc_aut_step(m, c_2, morus_state, state_3_0, state_3_1,state_3_2,state_3_3,state_3_4);
	morus_enc_aut_step(m, c_3, morus_state, state_4_0, state_4_1,state_4_2,state_4_3,state_4_4);


	//printf("Updated state:\n");
	//print_five_m128i(morus_state);

	//printf("-------------------\n");
	//print1block((__m128i*)state_1_0); printf("\n");
	//print1block((__m128i*)state_1_1); printf("\n");
	//print1block((__m128i*)state_1_2); printf("\n");
	//print1block((__m128i*)state_1_3); printf("\n");
	//print1block((__m128i*)state_1_4); printf("\n");

	return 0;
}



void print_five_m128i(__m128i *state)
{
    uint8_t *val = (uint8_t*) state;
    printf("state:\n");

    int i = 0;
    for (i = 0; i < 5; i++){
        printf("S%d: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n", i,\
           val[i*16+15],   val[i*16+14], val[i*16+13], val[i*16+12], \
           val[i*16+11], val[i*16+10], val[i*16+9], val[i*16+8], \
           val[i*16+7], val[i*16+6], val[i*16+5], val[i*16+4], \
           val[i*16+3], val[i*16+2], val[i*16+1], val[i*16+0]);
    }

}

void print_m128i(__m128i state)
{
    uint8_t *val = (uint8_t*) &state;
    printf("\nstate:\n");
    printf("S0: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n",\
           val[15], val[14], val[13], val[12], val[11], val[10], val[9], val[8], val[7], val[6], val[5], val[4], val[3], val[2], val[1], val[0]);
}

void print1block(unsigned char *d)
{
    int i = 0;
    for (i = 0; i < 16; i++) printf("%02X", d[15-i]);
    printf("\n");
}

/*
void morus_tag_generation(unsigned long long msglen, unsigned long long adlen, unsigned char *c, __m128i *state)
{
	int i;
	unsigned char t[16];
	__m128i  tmp;

	((uint64_t*)t)[0] = (adlen << 3);
	((uint64_t*)t)[1] = (msglen << 3);

	state[4] = XOR(state[4], state[0]);

	tmp = _mm_load_si128((__m128i*)t);

	for (i = 0; i < 10; i++) morus_stateupdate(tmp, state);

	state[0] = XOR(state[0], ROTL96(state[1]));
	state[0] = XOR(state[0], AND(state[2], state[3]));

	_mm_store_si128((__m128i*)t, state[0]);
	//in this program, the mac length is assumed to be multiple of bytes
	memcpy(c + msglen, t, 16);
}
*/


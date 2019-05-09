#include "crypto_aead.h"
#include <string.h>
#include <stdlib.h>

#ifdef _MSC_VER
#define inline __inline
#endif

#define n1 5
#define n2 31
#define n3 7
#define n4 22
#define n5 13

#define rotl(x,n)   (((x) << (n)) | ((x) >> (32-n)))


/*-------------------
unsigned int == 4 bytes
---------------------*/
/*
| msgblk is one 32-bit message block
| state[] = state[0] || state[1] || state[2] || state[3] || state[4], 5 32-bit words
*/
inline void morus_stateupdate(unsigned int msgblk, unsigned int state[5])
{
    //printf("Internal Rounds:\n");
	// Round 1
	state[0] = state[0] ^ state[3];
	state[0] = state[0] ^ (state[1] & state[2]);
	state[0] = rotl(state[0], n1);

	//printState(state);

	// Round 2
	state[1] = state[1] ^ msgblk;
	state[1] = state[1] ^ state[4];
	state[1] = state[1] ^ (state[2] & state[3]);
	state[1] = rotl(state[1], n2);

	//printState(state);

	// Round 3
	state[2] = state[2] ^ msgblk;
	state[2] = state[2] ^ state[0];
	state[2] = state[2] ^ (state[3] & state[4]);
	state[2] = rotl(state[2], n3);

	//printState(state);

	// Round 4
	state[3] = state[3] ^ msgblk;
	state[3] = state[3] ^ state[1];
	state[3] = state[3] ^ (state[4] & state[0]);
	state[3] = rotl(state[3], n4);

	//printState(state);

    // Round 5
	state[4] = state[4] ^ msgblk;
	state[4] = state[4] ^ state[2];
	state[4] = state[4] ^ (state[0] & state[1]);
	state[4] = rotl(state[4], n5);

	//printState(state);


}

/*The input to the initialization is the 128-bit key; 128-bit IV;
  Here we just generate randomized state[0]||state[1]||state[2]||state[3]||state[4]
*/
void morus_initialization(unsigned int state[5])
{

	state[0] = rand() ^ (rand() << 16);
	state[1] = rand() ^ (rand() << 16);
	state[2] = rand() ^ (rand() << 16);
	state[3] = rand() ^ (rand() << 16);
	state[4] = rand() ^ (rand() << 16);
	/*
	state[0] = 0x0ff2697f;
	state[1] = 0x3ddc02d7;
	state[2] = 0x22013e61;
	state[3] = 0x13fd19c5;
	state[4] = 0x4a9b6476;
	printState(state);*/
}

// one step of encryption: it encrypts a 4-byte block
inline void morus_enc_aut_step(const unsigned int plaintextblock, unsigned int *ciphertextblock, unsigned int state[5])
{
	//encryption
	//printf("\nIn enc blk:\n");
	//printf("Key stream blk:   ");
	//printMsgblk(state[0] ^ state[1] ^ (state[2] & state[3]));

	*ciphertextblock = plaintextblock ^ state[0] ^ state[1] ^ (state[2] & state[3]);

	morus_stateupdate(plaintextblock, state);
}


//encrypt a message of 4 32-bit words
int crypto_aead_encrypt(unsigned int plaintext[4], unsigned int ciphertext[4])
{
	unsigned int morus_state[5];

	//initialization
	morus_initialization(morus_state);

	//printf("After initialization:\n");
	//printState(morus_state);

	//encrypt the plaintext
	morus_enc_aut_step(plaintext[0], ciphertext, morus_state);
	//printf("Plaintext blk 0:  ");
	//printMsgblk(plaintext[0]);

	//printf("Ciphertext blk 0: ");
	//printMsgblk(ciphertext[0]);

	//printf("State:            ");
	//printState(morus_state);


	morus_enc_aut_step(plaintext[1], ciphertext + 1, morus_state);
	//printf("Plaintext blk 1:  ");
	//printMsgblk(plaintext[1]);

	//printf("Ciphertext blk 1: ");
	//printMsgblk(ciphertext[1]);

	//printf("State:            ");
	//printState(morus_state);

	morus_enc_aut_step(plaintext[2], ciphertext + 2, morus_state);
	//printf("Plaintext blk 2:  ");
	//printMsgblk(plaintext[2]);

	//printf("Ciphertext blk 2: ");
	//printMsgblk(ciphertext[2]);

	//printf("State:            ");
	//printState(morus_state);

	morus_enc_aut_step(plaintext[3], ciphertext + 3, morus_state);
	//printf("Plaintext blk 3:  ");
	//printMsgblk(plaintext[3]);

	//printf("Ciphertext blk 3: ");
	//printMsgblk(ciphertext[3]);

	//printf("State:            ");
	//printState(morus_state);

	return 0;
}

void printState(unsigned int state[5])
{
    printf("%08X  %08X  %08X  %08X  %08X\n", state[0], state[1], state[2], state[3], state[4]);
}

void printMsgblk(unsigned int p)
{
    printf("%08X\n", p);
}



#include <string.h>
#include <stdint.h>
#include "crypto_aead.h"

#ifdef _MSC_VER
#define inline __inline
#endif

#define n1 13
#define n2 46
#define n3 38
#define n4 7
#define n5 4

#define rotl(x,n)      (((x) << (n)) | ((x) >> (64-n)))

inline void morus_stateupdate(const uint64_t msgblk, uint64_t state[5])
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
void morus_initialization(uint64_t state[5])
{

	state[0] = rand();
	state[0] = (state[0] << 16) ^ rand();
	state[0] = (state[0] << 16) ^ rand();
	state[0] = (state[0] << 16) ^ rand();
	state[0] = (state[0] << 16) ^ rand();
	state[0] = (state[0] << 16) ^ rand();

	state[1] = rand();
	state[1] = (state[1] << 16) ^ rand();
	state[1] = (state[1] << 16) ^ rand();
	state[1] = (state[1] << 16) ^ rand();
	state[1] = (state[1] << 16) ^ rand();
	state[1] = (state[1] << 16) ^ rand();

	state[2] = rand();
	state[2] = (state[2] << 16) ^ rand();
	state[2] = (state[2] << 16) ^ rand();
	state[2] = (state[2] << 16) ^ rand();
	state[2] = (state[2] << 16) ^ rand();
	state[2] = (state[2] << 16) ^ rand();

	state[3] = rand();
	state[3] = (state[3] << 16) ^ rand();
	state[3] = (state[3] << 16) ^ rand();
	state[3] = (state[3] << 16) ^ rand();
	state[3] = (state[3] << 16) ^ rand();
	state[3] = (state[3] << 16) ^ rand();
	state[3] = (state[3] << 16) ^ rand();

	state[4] = rand();
	state[4] = (state[4] << 16) ^ rand();
	state[4] = (state[4] << 16) ^ rand();
	state[4] = (state[4] << 16) ^ rand();
	state[4] = (state[4] << 16) ^ rand();
	state[4] = (state[4] << 16) ^ rand();
	/*
	state[0] = 0x0ff2697f;
	state[1] = 0x3ddc02d7;
	state[2] = 0x22013e61;
	state[3] = 0x13fd19c5;
	state[4] = 0x4a9b6476;*/

	//printState(state);
}

// one step of encryption: it encrypts a 4-byte block
inline void morus_enc_aut_step(const uint64_t plaintextblock, uint64_t *ciphertextblock, uint64_t state[5])
{
	//encryption
	//printf("\nIn enc blk:\n");
	//printf("Key stream blk:   ");
	//printMsgblk(state[0] ^ state[1] ^ (state[2] & state[3]));

	*ciphertextblock = plaintextblock ^ state[0] ^ state[1] ^ (state[2] & state[3]);

	morus_stateupdate(plaintextblock, state);
}


//encrypt a message of 4 32-bit words
int crypto_aead_encrypt(uint64_t plaintext[4], uint64_t ciphertext[4])
{
	uint64_t morus_state[5];

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

void printState(uint64_t state[5])
{
    printf("%016llX  %016llX  %016llX  %016llX  %016llX\n", state[0], state[1], state[2], state[3], state[4]);
}

void printMsgblk(uint64_t p)
{
    printf("%llX\n", p);
}


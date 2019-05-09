#include <immintrin.h>

int crypto_aead_encrypt_1block(
    const unsigned char *m, unsigned char *c,\
    unsigned char *state_1_0,\
    unsigned char *state_1_1,\
    unsigned char *state_1_2,\
    unsigned char *state_1_3,\
    unsigned char *state_1_4\
);

void print_five_m128i(__m128i *state);
void print_m128i(__m128i state);
void print1block(unsigned char *d);

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
);

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
);

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
);

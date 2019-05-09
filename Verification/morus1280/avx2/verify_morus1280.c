#include <stdio.h>
#include "crypto_aead.h"
#define bit(x, n)       (( (x) >> (n) ) & ( 0x1 ))

int main()
{
    srand(time(NULL));
    uint64_t i = 0;
    uint64_t count0 = 0;
    uint64_t count1 = 0;

    const unsigned char plaintext[32] = {0x0};
    printf("Plaintext:\n");
    print1block(plaintext);
    printf("\n\n");

    unsigned char ciphertext[32];
    unsigned char c_1[32];
    unsigned char c_2[32];
    unsigned char c_3[32];

    unsigned char state_1_0[32];
    unsigned char state_1_1[32];
    unsigned char state_1_2[32];
    unsigned char state_1_3[32];
    unsigned char state_1_4[32];

    unsigned char state_2_0[32];
    unsigned char state_2_1[32];
    unsigned char state_2_2[32];
    unsigned char state_2_3[32];
    unsigned char state_2_4[32];

    unsigned char state_3_0[32];
    unsigned char state_3_1[32];
    unsigned char state_3_2[32];
    unsigned char state_3_3[32];
    unsigned char state_3_4[32];

    unsigned char state_4_0[32];
    unsigned char state_4_1[32];
    unsigned char state_4_2[32];
    unsigned char state_4_3[32];
    unsigned char state_4_4[32];


    crypto_aead_encrypt_4blocks(\
            plaintext, ciphertext,\
            c_1,c_2,c_3,\
            state_1_0, state_1_1, state_1_2, state_1_3, state_1_4,\
            state_2_0, state_2_1, state_2_2, state_2_3, state_2_4,\
            state_3_0, state_3_1, state_3_2, state_3_3, state_3_4,\
            state_4_0, state_4_1, state_4_2, state_4_3, state_4_4
        );

    printf("\nc0:\n");
    print1block(ciphertext);

    printf("\nc1:\n");
    print1block(c_1);

    printf("\nc2:\n");
    print1block(c_2);

    printf("\nc3:\n");
    print1block(c_3);

    printf("\nstate_1\n");
    print1block(state_1_0);
    print1block(state_1_1);
    print1block(state_1_2);
    print1block(state_1_3);
    print1block(state_1_4);

    printf("\nstate_2\n");
    print1block(state_2_0);
    print1block(state_2_1);
    print1block(state_2_2);
    print1block(state_2_3);
    print1block(state_2_4);


    printf("\nstate_3\n");
    print1block(state_3_0);
    print1block(state_3_1);
    print1block(state_3_2);
    print1block(state_3_3);
    print1block(state_3_4);


    printf("\nstate_4\n");
    print1block(state_4_0);
    print1block(state_4_1);
    print1block(state_4_2);
    print1block(state_4_3);
    print1block(state_4_4);

    int z;

    printf("\n========== Verifying fragment chi-1 =============\n");
    count0 = 0;
    count1 = 0;

    for (i = 0; i < (uint64_t)(0xFFFFF) + 1; i++){
        crypto_aead_encrypt_4blocks(\
            plaintext, ciphertext,\
            c_1,c_2,c_3,\
            state_1_0, state_1_1, state_1_2, state_1_3, state_1_4,\
            state_2_0, state_2_1, state_2_2, state_2_3, state_2_4,\
            state_3_0, state_3_1, state_3_2, state_3_3, state_3_4,\
            state_4_0, state_4_1, state_4_2, state_4_3, state_4_4
        );


        z = bit(c_1[31-4],5)^bit(c_1[31-12],5)^bit(c_1[31-20],5)^bit(c_1[31-28],5)^\
            bit(state_1_4[31-4],5)^bit(state_1_4[31-12],5)^bit(state_1_4[31-20],5)^bit(state_1_4[31-28],5)^\
            bit(state_2_1[31-6],3)^bit(state_2_1[31-14],3)^bit(state_2_1[31-22],3)^bit(state_2_1[31-30],3)^\
            bit(ciphertext[31-5],0)^bit(ciphertext[31-13],0)^bit(ciphertext[31-21],0)^bit(ciphertext[31-29],0);


        if (z == 0){
            count0 = count0 + 1;
        }
        else{
            count1 = count1 + 1;
        }
    }

    printf("(%lld - %lld) / N = %lld / %lld\n", count0, count1, count0 - count1, count0 + count1);


    printf("\n========== Verifying fragment chi-2 =============\n");
    count0 = 0;
    count1 = 0;

    for (i = 0; i < (uint64_t)(0xFFFFF)*4 + 1; i++){
        crypto_aead_encrypt_4blocks(\
            plaintext, ciphertext,\
            c_1,c_2,c_3,\
            state_1_0, state_1_1, state_1_2, state_1_3, state_1_4,\
            state_2_0, state_2_1, state_2_2, state_2_3, state_2_4,\
            state_3_0, state_3_1, state_3_2, state_3_3, state_3_4,\
            state_4_0, state_4_1, state_4_2, state_4_3, state_4_4
        );


        z = bit(c_1[31-0],6)^bit(c_1[31-8],6)^bit(c_1[31-16],6)^bit(c_1[31-24],6)^\
            bit(state_2_1[31-6],3)^bit(state_2_1[31-14],3)^bit(state_2_1[31-22],3)^bit(state_2_1[31-30],3)^\
            bit(c_2[31-6],3)^bit(c_2[31-14],3)^bit(c_2[31-22],3)^bit(c_2[31-30],3);


        if (z == 0){
            count0 = count0 + 1;
        }
        else{
            count1 = count1 + 1;
        }
    }

    printf("(%lld - %lld) / N = %lld / %lld\n", count0, count1, count0 - count1, count0 + count1);


    printf("\n========== Verifying fragment chi-3 =============\n");
    count0 = 0;
    count1 = 0;

    for (i = 0; i < (uint64_t)(0xFFFFF) + 1; i++){
        crypto_aead_encrypt_4blocks(\
            plaintext, ciphertext,\
            c_1,c_2,c_3,\
            state_1_0, state_1_1, state_1_2, state_1_3, state_1_4,\
            state_2_0, state_2_1, state_2_2, state_2_3, state_2_4,\
            state_3_0, state_3_1, state_3_2, state_3_3, state_3_4,\
            state_4_0, state_4_1, state_4_2, state_4_3, state_4_4
        );


        z = bit(state_3_1[31-6],7)^bit(state_3_1[31-14],7)^bit(state_3_1[31-22],7)^bit(state_3_1[31-30],7)\
            ^bit(c_3[31-6],7)^bit(c_3[31-14],7)^bit(c_3[31-22],7)^bit(c_3[31-30],7)^\
            bit(c_2[31-7],2)^bit(c_2[31-15],2)^bit(c_2[31-23],2)^bit(c_2[31-31],2);


        if (z == 0){
            count0 = count0 + 1;
        }
        else{
            count1 = count1 + 1;
        }
    }

    printf("(%lld - %lld) / N = %lld / %lld\n", count0, count1, count0 - count1, count0 + count1);


    printf("\n========== Verifying fragment chi-4 =============\n");
    count0 = 0;
    count1 = 0;

    for (i = 0; i < (uint64_t)(0xFFFFF) + 1; i++){
        crypto_aead_encrypt_4blocks(\
            plaintext, ciphertext,\
            c_1,c_2,c_3,\
            state_1_0, state_1_1, state_1_2, state_1_3, state_1_4,\
            state_2_0, state_2_1, state_2_2, state_2_3, state_2_4,\
            state_3_0, state_3_1, state_3_2, state_3_3, state_3_4,\
            state_4_0, state_4_1, state_4_2, state_4_3, state_4_4
        );


        z = bit(c_1[31-5],4)^bit(c_1[31-13],4)^bit(c_1[31-21],4)^bit(c_1[31-29],4)^\
            bit(state_3_1[31-6],7)^bit(state_3_1[31-14],7)^bit(state_3_1[31-22],7)^bit(state_3_1[31-30],7)^\
            bit(c_2[31-3],1)^bit(c_2[31-11],1)^bit(c_2[31-19],1)^bit(c_2[31-27],1)^\
            bit(state_2_4[31-3],1)^bit(state_2_4[31-11],1)^bit(state_2_4[31-19],1)^bit(state_2_4[31-27],1);


        if (z == 0){
            count0 = count0 + 1;
        }
        else{
            count1 = count1 + 1;
        }
    }

    printf("(%lld - %lld) / N = %lld / %lld\n", count0, count1, count0 - count1, count0 + count1);

    printf("\n========== Verifying fragment chi-5 =============\n");
    count0 = 0;
    count1 = 0;

    for (i = 0; i < (uint64_t)(0xFFFFF) + 1; i++){
        crypto_aead_encrypt_4blocks(\
            plaintext, ciphertext,\
            c_1,c_2,c_3,\
            state_1_0, state_1_1, state_1_2, state_1_3, state_1_4,\
            state_2_0, state_2_1, state_2_2, state_2_3, state_2_4,\
            state_3_0, state_3_1, state_3_2, state_3_3, state_3_4,\
            state_4_0, state_4_1, state_4_2, state_4_3, state_4_4
        );


        z = bit(state_2_4[31-3],1)^bit(state_2_4[31-11],1)^bit(state_2_4[31-19],1)^bit(state_2_4[31-27],1)^\
            bit(c_2[31-4],5)^bit(c_2[31-12],5)^bit(c_2[31-20],5)^bit(c_2[31-28],5)^bit(state_1_4[31-4],5)^\
            bit(state_1_4[31-12],5)^bit(state_1_4[31-20],5)^bit(state_1_4[31-28],5);


        if (z == 0){
            count0 = count0 + 1;
        }
        else{
            count1 = count1 + 1;
        }
    }

    printf("(%lld - %lld) / N = %lld / %lld\n", count0, count1, count0 - count1, count0 + count1);


    return 0;

    return 0;
}

#include <stdio.h>
#include "crypto_aead.h"
#include <stdint.h>

#define bit(x, n)       (( (x) >> (n) ) & ( 0x1 ))

int main()
{
    srand(time(NULL));
    uint64_t i = 0;
    uint64_t count0 = 0;
    uint64_t count1 = 0;

    const unsigned char plaintext[16] = {0x00};
    printf("Plaintext:\n");
    print1block(plaintext);
    printf("\n\n");

    unsigned char ciphertext[16];
    unsigned char c_1[16];
    unsigned char c_2[16];
    unsigned char c_3[16];

    unsigned char state_1_0[16];
    unsigned char state_1_1[16];
    unsigned char state_1_2[16];
    unsigned char state_1_3[16];
    unsigned char state_1_4[16];

    unsigned char state_2_0[16];
    unsigned char state_2_1[16];
    unsigned char state_2_2[16];
    unsigned char state_2_3[16];
    unsigned char state_2_4[16];

    unsigned char state_3_0[16];
    unsigned char state_3_1[16];
    unsigned char state_3_2[16];
    unsigned char state_3_3[16];
    unsigned char state_3_4[16];

    unsigned char state_4_0[16];
    unsigned char state_4_1[16];
    unsigned char state_4_2[16];
    unsigned char state_4_3[16];
    unsigned char state_4_4[16];


    crypto_aead_encrypt_1block(plaintext, ciphertext, state_1_0, state_1_1, state_1_2, state_1_3, state_1_4);
    printf("\n\nCiphertext:\n");
    print1block(ciphertext);

    printf("\n\n\n");


    // involved ciphertext bytes: 0, 4, 8, 12
    unsigned char lambda0[16] = {0x10, 0x00, 0x00, 0x00,\
                                 0x10, 0x00, 0x00, 0x00,\
                                 0x10, 0x00, 0x00, 0x00,\
                                 0x10, 0x00, 0x00, 0x00};

    // involved state bytes: 3, 7, 11, 15
    unsigned char beta0_0[16] = {0x00, 0x00, 0x00, 0x02,\
                                 0x00, 0x00, 0x00, 0x02,\
                                 0x00, 0x00, 0x00, 0x02,\
                                 0x00, 0x00, 0x00, 0x02};

    unsigned char lambda1[16] = {0x08, 0x00, 0x02, 0x02,\
                                 0x08, 0x00, 0x02, 0x02,\
                                 0x08, 0x00, 0x02, 0x02,\
                                 0x08, 0x00, 0x02, 0x02};

    unsigned char beta1[16*5] =  {0x00, 0x00, 0x40, 0x03,    0x00, 0x00, 0x40, 0x03,   0x00, 0x00, 0x40, 0x03,    0x00, 0x00, 0x40, 0x03,\
                                  0x00, 0x00, 0x00, 0x03,    0x00, 0x00, 0x00, 0x03,   0x00, 0x00, 0x00, 0x03,    0x00, 0x00, 0x00, 0x03,\
                                  0x00, 0x00, 0x00, 0x02,    0x00, 0x00, 0x00, 0x02,   0x00, 0x00, 0x00, 0x02,    0x00, 0x00, 0x00, 0x02,\
                                  0x00, 0x00, 0x00, 0x00,    0x00, 0x00, 0x00, 0x00,   0x00, 0x00, 0x00, 0x00,    0x00, 0x00, 0x00, 0x00,\
                                  0x00, 0x00, 0x40, 0x00,    0x00, 0x00, 0x40, 0x00,   0x00, 0x00, 0x40, 0x00,    0x00, 0x00, 0x40, 0x00};

    int z;


    printf("\n========== Verifying fragment chi-1 =============\n");
    count0 = 0;
    count1 = 0;

    for (i = 0; i < (uint64_t)(0xFFFFF) + 1; i++){
        crypto_aead_encrypt_2blocks(\
            plaintext, ciphertext,\
            c_1,\
            state_1_0, state_1_1, state_1_2, state_1_3, state_1_4,\
            state_2_0, state_2_1, state_2_2, state_2_3, state_2_4\
        );


        z = bit(ciphertext[15-0],4)^bit(ciphertext[15-4],4)^bit(ciphertext[15-8],4)^bit(ciphertext[15-12],4)^\
            bit(c_1[15-3],1)^bit(c_1[15-7],1)^bit(c_1[15-11],1)^bit(c_1[15-15],1)^\
            bit(state_2_1[15-3],0)^bit(state_2_1[15-7],0)^bit(state_2_1[15-11],0)^bit(state_2_1[15-15],0)^\
            bit(state_1_4[15-3],1)^bit(state_1_4[15-7],1)^bit(state_1_4[15-11],1)^bit(state_1_4[15-15],1);

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

    for (i = 0; i < (uint64_t)(0xFFFFF) + 1; i++){
        crypto_aead_encrypt_3blocks(\
            plaintext, ciphertext,\
            c_1,c_2,\
            state_1_0, state_1_1, state_1_2, state_1_3, state_1_4,\
            state_2_0, state_2_1, state_2_2, state_2_3, state_2_4,\
            state_3_0, state_3_1, state_3_2, state_3_3, state_3_4
        );


        z = bit(c_1[15-0],3)^bit(c_1[15-4],3)^bit(c_1[15-8],3)^bit(c_1[15-12],3)^\
            bit(c_2[15-3],0)^bit(c_2[15-7],0)^bit(c_2[15-11],0)^bit(c_2[15-15],0)^\
            bit(state_2_1[15-3],0)^bit(state_2_1[15-7],0)^bit(state_2_1[15-11],0)^bit(state_2_1[15-15],0);


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


        z = bit(c_2[15-2],0)^bit(c_2[15-6],0)^bit(c_2[15-10],0)^bit(c_2[15-14],0)^\
            bit(c_3[15-2],5)^bit(c_3[15-6],5)^bit(c_3[15-10],5)^bit(c_3[15-14],5)^\
            bit(state_3_1[15-2],5)^bit(state_3_1[15-6],5)^bit(state_3_1[15-10],5)^bit(state_3_1[15-14],5);


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


        z = bit(c_1[15-2],1)^bit(c_1[15-6],1)^bit(c_1[15-10],1)^bit(c_1[15-14],1)^\
            bit(c_2[15-2],6)^bit(c_2[15-6],6)^bit(c_2[15-10],6)^bit(c_2[15-14],6)^\
            bit(state_3_1[15-2],5)^bit(state_3_1[15-6],5)^bit(state_3_1[15-10],5)^bit(state_3_1[15-14],5)^\
            bit(state_2_4[15-2],6)^bit(state_2_4[15-6],6)^bit(state_2_4[15-10],6)^bit(state_2_4[15-14],6);



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


        z = bit(c_2[15-3],1)^bit(c_2[15-7],1)^bit(c_2[15-11],1)^bit(c_2[15-15],1)^\
            bit(state_1_4[15-3],1)^bit(state_1_4[15-7],1)^bit(state_1_4[15-11],1)^bit(state_1_4[15-15],1)^\
            bit(state_2_4[15-2],6)^bit(state_2_4[15-6],6)^bit(state_2_4[15-10],6)^bit(state_2_4[15-14],6);


        if (z == 0){
            count0 = count0 + 1;
        }
        else{
            count1 = count1 + 1;
        }
    }

    printf("(%lld - %lld) / N = %lld / %lld\n", count0, count1, count0 - count1, count0 + count1);

    return 0;
}

#include <stdio.h>
#include "crypto_aead.h"
#include <stdlib.h>
#define bit(x,n)    (( (x) >> (n) ) & (0x1))

#include <stdint.h>

int main()
{
    srand(time(NULL)); // seed the random number generator

    unsigned int i = 0;
    unsigned int count0 = 0;
    unsigned int count1 = 0;

    uint64_t plaintext[4] = {0x0, 0x0, 0x0, 0x0};
    uint64_t ciphertext[4];
    int z;

    for (i = 0; i < (0xFFFF+1)*40 + 1; i++){
            crypto_aead_encrypt(plaintext, ciphertext);

            z = bit(ciphertext[0], 63-47) ^\
                bit(ciphertext[1], 63-1) ^ bit(ciphertext[1], 63-34) ^ bit(ciphertext[1], 63-43) ^\
                bit(ciphertext[2], 63-30) ^ bit(ciphertext[2], 63-34) ^ bit(ciphertext[2], 63-52) ^ bit(ciphertext[2], 63-61) ^\
                bit(ciphertext[3], 63-48);

            if (z == 0){
                count0 = count0 + 1;
            }
            else{
                count1 = count1 + 1;
            }

    }

    printf("%d / %d\n", count0 - count1, count0 + count1);

    return 0;
}

#include <stdio.h>
#include "crypto_aead.h"
#include <stdlib.h>
#define bit(x,n)    (( (x) >> (n) ) & (0x1))

int main()
{
    srand(time(NULL));

    unsigned int i = 0;
    unsigned int count0 = 0;
    unsigned int count1 = 0;

    const unsigned int plaintext[4] = {0x0, 0x0, 0x0, 0x0};
    unsigned int ciphertext[4];
    int z;

    for (i = 0; i < (0xFFFF+1)*40 + 1; i++){
            crypto_aead_encrypt(plaintext, ciphertext);
            z = bit(ciphertext[0], 28) ^\
                bit(ciphertext[1], 27) ^ bit(ciphertext[1], 9) ^ bit(ciphertext[1], 1) ^\
                bit(ciphertext[2], 14) ^ bit(ciphertext[2], 8) ^ bit(ciphertext[2], 1) ^ bit(ciphertext[2], 0) ^\
                bit(ciphertext[3], 13);

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

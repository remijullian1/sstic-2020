#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <openssl/ripemd.h>

#ifndef DEBUG
 #define printf(fmt, ...) (0)
#endif

// #define DEBUG

#define KEY_X 0x64   // Triangle 
#define KEY_W 0x73   // Carre
#define KEY_SP 0x78  // Rond
#define KEY_ALT 0x7A // Croix

static const uint8_t KEYS[4] = {
    KEY_X,
    KEY_W,
    KEY_SP,
    KEY_ALT
};

/* Hardcoded key */
static const uint8_t xor_key_data[0x2B] = {
    0x97,0x8b,0x8b,0x8f,0x8c,0xc5,0xd0,0xd0,
    0x88,0x88,0x88,0xd1,0x86,0x90,0x8a,0x8b,
    0x8a,0x9d,0x9a,0xd1,0x9c,0x90,0x92,0xd0,
    0x88,0x9e,0x8b,0x9c,0x97,0xc0,0x89,0xc2,
    0xbc,0x94,0x89,0xaa,0xbe,0x93,0xc8,0xa6,
    0xcb,0x92,0x88
};

// uint8_t good_key[8] = { KEY_ALT, KEY_SP, KEY_X, KEY_W, KEY_ALT, KEY_SP, KEY_X, KEY_W};

int derivate_one_key(uint8_t *input_key)
{
    RIPEMD160_CTX ctxA, ctxB;
    uint8_t buff_A[0x40];
    uint8_t buff_B[0x40];
    uint8_t buff_key[0x40];
    uint8_t buff_final[0x40];
    uint8_t key[8];
    int ret;

    memset(key, 0, sizeof(key));

    for (int i = 0; i < 8; i++) {
        RIPEMD160_Init(&ctxA);
        RIPEMD160_Init(&ctxB);

        memset(buff_A, '6', 0x40);
        memset(buff_B, '\\', 0x40);
        memset(buff_key, 0, 0x40);

        /* Modify 43 bytes / 64 bytes */
        for (int j = 0; j < 0x2b; j++) {
            buff_A[j] ^= xor_key_data[j];
            buff_B[j] ^= xor_key_data[j];
        }

        /* Update context based on previous XOR operation */
        RIPEMD160_Update(&ctxA, buff_A, 0x40);
        RIPEMD160_Update(&ctxB, buff_B, 0x40);

        key[i] = input_key[i];
        memcpy(buff_key, key, 8);

        /* Overlapping buffer */
        buff_key[8] = 0x80;
        buff_key[56] = 0x40;
        buff_key[57] = 0x02;

        /* Update first context based on input key */
        RIPEMD160_Update(&ctxA, buff_key, 0x40);
    
        memset(buff_final, 0, 0x40);
        memcpy(buff_final, &ctxA.A, 0x14);
         /* Overlapping buffer */
        buff_final[0x14+0] = 0x80;
        buff_final[0x14+0x24] = 0xA0;
        buff_final[0x14+0x25] = 0x02;
        /* Update second context based on first context */
        RIPEMD160_Update(&ctxB, buff_final, 0x40);

    }

    /* Write on stdout the 20 bytes digest */
    ret = write(1, &ctxB.A, 0x14);
    assert(ret == 0x14);

    return 0;
}

int derivate_all_keys()
{
    uint8_t key[8];
    for (int i = 0; i <= 65535; i++) {
        for (int j = 0; j < 8; j++) {
            key[j] = KEYS[(i >> (2*j)) & 3];
        }
        derivate_one_key(key);
    }
    return 0;
}

int main(int argc, char *argv)
{
    derivate_all_keys();
    return 0;
}
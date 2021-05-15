#ifndef SECURERF_H
#define SECURERF_H

/* Xoodyak authenticated encryption algorithm intended to be used with RFM69
 * Adds time-based nonce expiration
 * References:  https://keccak.team/xoodyak.html
 *              https://github.com/LowPowerLab/RFM69
 */

/*********** Includes ***********/
#include <Arduino.h>

/*********** Definitions ***********/
#define XOODYAK_KEY_SIZE 16       /* Size of the key for Xoodyak                */
#define XOODYAK_TAG_SIZE 16       /* Size of the authentication tag for Xoodyak */
#define XOODYAK_NONCE_SIZE 16     /* Size of the nonce for Xoodyak              */
#define RFM69_MAX_PAYLOAD_SIZE 61 /* Max size for RFM69 payload in bytes        */
#define MAX_AD_SIZE 4             /* Max associated data size in bytes          */
#define NONCE_LIFETIME 500        /* Max nonce life time (in ms)                */
#define NONCE_MIN_GEN_TIME 1      /* Min nonce generation time (in seconds)     */

#define XOODYAK_ABSORB_RATE 44  /* Absorbing data rate into the sponge state                            */
#define XOODYAK_SQUEEZE_RATE 24 /* Rate for squeezing data out of the sponge                            */
#define XOODYAK_PHASE_UP 0      /* Indicates block permutation has just been performed                  */
#define XOODYAK_PHASE_DOWN 1    /* Indicates data has been absorbed but block permutation has not been  */

/* Generic left rotate */
#define leftRotate(a, bits)                           \
    (__extension__({                                  \
        uint32_t _temp = (a);                         \
        (_temp << (bits)) | (_temp >> (32 - (bits))); \
    }))

#define leftRotate1(a) (leftRotate((a), 1))
#define leftRotate5(a) (leftRotate((a), 5))
#define leftRotate8(a) (leftRotate((a), 8))
#define leftRotate11(a) (leftRotate((a), 11))
#define leftRotate14(a) (leftRotate((a), 14))

/* XOR a source byte buffer against a destination */
#define lw_xor_block(dest, src, len) \
    do { \
        unsigned char *_dest = (dest); \
        const unsigned char *_src = (src); \
        unsigned _len = (len); \
        while (_len > 0) { \
            *_dest++ ^= *_src++; \
            --_len; \
        } \
    } while (0)

/* XOR a source byte buffer against a destination and write to another
 * destination at the same time. */
#define lw_xor_block_swap(dest2, dest, src, len) \
    do { \
        unsigned char *_dest2 = (dest2); \
        unsigned char *_dest = (dest); \
        const unsigned char *_src = (src); \
        unsigned _len = (len); \
        while (_len > 0) { \
            unsigned char _temp = *_src++; \
            *_dest2++ = *_dest ^ _temp; \
            *_dest++ = _temp; \
            --_len; \
        } \
    } while (0)

/* XOR a source byte buffer against a destination and write to another
 * destination at the same time */
#define lw_xor_block_2_dest(dest2, dest, src, len) \
    do { \
        unsigned char *_dest2 = (dest2); \
        unsigned char *_dest = (dest); \
        const unsigned char *_src = (src); \
        unsigned _len = (len); \
        while (_len > 0) { \
            *_dest2++ = (*_dest++ ^= *_src++); \
            --_len; \
        } \
    } while (0)

/*********** Typedef structs ***********/

/* State information for the Xoodoo permutation */
typedef union
{
    /** Words of the state organized into rows and columns */
    uint32_t S[3][4];
    /** Words of the state as a single linear array */
    uint32_t W[12];
    /** Bytes of the state */
    uint8_t B[12 * sizeof(uint32_t)];

} xoodoo_state_t;

class SecureRF
{

public:

    SecureRF();

    static unsigned char PLAINTEXT[RFM69_MAX_PAYLOAD_SIZE - MAX_AD_SIZE - XOODYAK_TAG_SIZE + 1];
    static unsigned char ASSOCIATED[MAX_AD_SIZE + 1];
    static unsigned char SECURE_PAYLOAD[RFM69_MAX_PAYLOAD_SIZE + 1];

    static uint8_t PLAINTEXT_LEN, ASSOCIATED_LEN, SECURE_PAYLOAD_LEN;

    void setMasterKey(unsigned char *k);

    bool setNonce(unsigned char *nonce);

    bool setSecureMessage(
        unsigned char *message, // INPUT: 0-44
        unsigned char messageLength,
        unsigned char *ad, // INPUT: 0-3 (+1)
        unsigned char adLength
        //unsigned char *out // OUTPUT: (1-4)+(0-44)+16
    );

    bool getSecureMessage(
        unsigned char *in      // INPUT: 17-61
        //unsigned char *message, // OUTPUT: 0-44
        //unsigned char *ad       // OUTPUT: 0-3
    );

private:

    /* Parameters */
    unsigned char key[XOODYAK_KEY_SIZE];
    bool keySet;
    //static unsigned char plaintext[RFM69_MAX_PAYLOAD_SIZE - MAX_AD_SIZE - XOODYAK_TAG_SIZE];
    //static unsigned char ciphertext[RFM69_MAX_PAYLOAD_SIZE];
    //static unsigned char associated[MAX_AD_SIZE];
    unsigned char nonce[XOODYAK_NONCE_SIZE]; // public nonce

    /* Times */
    uint32_t nonceGenTime;

    /* Encrypts and authenticates a packet with Xoodyak */
    // int8_t xoodyak_aead_encrypt(
    //     unsigned char *c,          /* Buffer to receive the output                                     */
    //     size_t *clen,              /* Length of the output which includes Ciphertext + AuthTag (16B)   */
    //     const unsigned char *m,    /* Buffer containing the plaintext to encrypt                       */
    //     size_t mlen,               /* Length of the plaintext in bytes                                 */
    //     const unsigned char *ad,   /* Buffer containing A.Data (gets authenticated but not encrypted)  */
    //     size_t adlen,              /* Length of the associated data in bytes                           */
    //     const unsigned char *npub, /* Points to the packet nonce which must by 16 bytes in length    */
    //     const unsigned char *k     /* Points to the private master key to encrypt the packet (16B)     */
    // );                             /* Returns 0 on success, or a negative value if there was an error in the parameters */

    // /* Decrypts and authenticates a packet with Xoodyak */
    // int8_t xoodyak_aead_decrypt(
    //     unsigned char *m,          /* Buffer containing the decrypted plaintext                        */
    //     size_t *mlen,              /* Length of the plaintext in bytes                                 */
    //     const unsigned char *c,    /* Buffer containing the ciphertext and Auth.Tag to decrypt         */
    //     size_t clen,               /* Length of the input which includes Ciphertext + AuthTag (16B)    */
    //     const unsigned char *ad,   /* Buffer containing A.Data (gets authenticated)                    */
    //     size_t adlen,              /* Length of the associated data in bytes                           */
    //     const unsigned char *npub, /* Points to the packet nonce which must by 16 bytes in length    */
    //     const unsigned char *k     /* Points to the private master key to decrypt the packet (16B)     */
    // );                             /* Returns 0 on success, -1 if the Auth.Tag is invalid, other negative number if there was an error in the parameters */

};

#endif

/*
 * Copyright (C) 2021 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
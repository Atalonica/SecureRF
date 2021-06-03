
/*
 * Copyright (C) 2021 Atalonica.
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

#ifndef SECURERF_H
#define SECURERF_H

/* Xoodyak authenticated encryption algorithm intended to be used with RFM69
 * Adds time-based nonce expiration
 * References:  https://keccak.team/xoodyak.html
 *              https://github.com/rweather/lwc-finalists
 */

/*********** Includes ***********/
#include <Arduino.h>

/*********** Definitions ***********/
#define XOODYAK_KEY_SIZE 16       /* Size of the key for Xoodyak                */
#define XOODYAK_TAG_SIZE 16       /* Size of the authentication tag for Xoodyak */
#define XOODYAK_NONCE_SIZE 16     /* Size of the nonce for Xoodyak              */
#define XOODYAK_HASH_SIZE 4       /* ize of the hash output for Xoodyak         */
#define RFM69_MAX_PAYLOAD_SIZE 61 /* Max size for RFM69 payload in bytes        */
#define MAX_AD_SIZE 4             /* Max associated data size in bytes          */
#define NONCE_LIFETIME 500        /* Max nonce life time (in ms) (keep small)   */
#define NONCE_MIN_GEN_TIME 1000   /* Min allowed nonce generation time (in ms)  */

#define XOODYAK_ABSORB_RATE 44  /* Absorbing data rate into the sponge state                            */
#define XOODYAK_HASH_RATE 16    /* Hash absorbing data rate (hashing mode)                              */
#define XOODYAK_SQUEEZE_RATE 24 /* Rate for squeezing data out of the sponge                            */
#define XOODYAK_PHASE_UP 0      /* Indicates block permutation has just been performed                  */
#define XOODYAK_PHASE_DOWN 1    /* Indicates data has been absorbed but block permutation has not been  */
#define XOODYAK_HASH_MODE_INIT_ABSORB 0
#define XOODYAK_HASH_MODE_ABSORB 1
#define XOODYAK_HASH_MODE_SQUEEZE 2

/* Generic left rotate */
#define leftRotate(a, bits)                               \
    (__extension__(                                       \
        {                                                 \
            uint32_t _temp = (a);                         \
            (_temp << (bits)) | (_temp >> (32 - (bits))); \
        }))

#define leftRotate1(a) (leftRotate((a), 1))
#define leftRotate5(a) (leftRotate((a), 5))
#define leftRotate8(a) (leftRotate((a), 8))
#define leftRotate11(a) (leftRotate((a), 11))
#define leftRotate14(a) (leftRotate((a), 14))

/* XOR a source byte buffer against a destination */
#define lw_xor_block(dest, src, len)       \
    do                                     \
    {                                      \
        unsigned char *_dest = (dest);     \
        const unsigned char *_src = (src); \
        unsigned _len = (len);             \
        while (_len > 0)                   \
        {                                  \
            *_dest++ ^= *_src++;           \
            --_len;                        \
        }                                  \
    } while (0)

/* XOR a source byte buffer against a destination and write to another
 * destination at the same time. */
#define lw_xor_block_swap(dest2, dest, src, len) \
    do                                           \
    {                                            \
        unsigned char *_dest2 = (dest2);         \
        unsigned char *_dest = (dest);           \
        const unsigned char *_src = (src);       \
        unsigned _len = (len);                   \
        while (_len > 0)                         \
        {                                        \
            unsigned char _temp = *_src++;       \
            *_dest2++ = *_dest ^ _temp;          \
            *_dest++ = _temp;                    \
            --_len;                              \
        }                                        \
    } while (0)

/* XOR a source byte buffer against a destination and write to another
 * destination at the same time */
#define lw_xor_block_2_dest(dest2, dest, src, len) \
    do                                             \
    {                                              \
        unsigned char *_dest2 = (dest2);           \
        unsigned char *_dest = (dest);             \
        const unsigned char *_src = (src);         \
        unsigned _len = (len);                     \
        while (_len > 0)                           \
        {                                          \
            *_dest2++ = (*_dest++ ^= *_src++);     \
            --_len;                                \
        }                                          \
    } while (0)

#define xoodoo_hash_permute(state) \
    xoodoo_permute((xoodoo_state_t *)((state)->s.state))

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

/**
 * \brief State information for Xoodyak incremental hashing modes.
 */
typedef union
{
    struct
    {
        uint8_t state[48];    /**< Current hash state */
        uint8_t count;        /**< Number of bytes in the current block */
        uint8_t mode;         /**< Hash mode: absorb or squeeze */
    } s;                      /**< State */
    unsigned long long align; /**< For alignment of this structure */

} xoodyak_hash_state_t;

class SecureRF
{

public:
    SecureRF();

    static unsigned char PLAINTEXT[RFM69_MAX_PAYLOAD_SIZE - MAX_AD_SIZE - XOODYAK_TAG_SIZE + 1];
    static unsigned char ASSOCIATED[MAX_AD_SIZE + 1];
    static unsigned char SECURE_PAYLOAD[RFM69_MAX_PAYLOAD_SIZE + 1];

    static uint8_t PLAINTEXT_LEN, ASSOCIATED_LEN, SECURE_PAYLOAD_LEN;

    /* [setKeys]
     * kx (16): input buffer with PSK key used for Xoodyak AEAD
     * kh (16): input buffer with PSK key used for Xoodyak hashing
     */
    void setKeys(const unsigned char *kx, const unsigned char *kh);

    /* [createNonceRequest]
     * nNameId (4): input buffer identifying nonce request message
     * nRandId (4): four random bytes
     * nReq   (12): output buffer where the nonce request payload will be saved
     */
    bool createNonceRequest(const unsigned char *nReqNameId, const unsigned char *nReqRandId, unsigned char *nReq );

    /* [onNonceRequest]
     * nReq   (12): input buffer with received nonce request
     * n      (16): input buffer with generated nonce
     * nRes   (20): output buffer where the nonce response will be saved
     */
    bool onNonceRequest(unsigned char *nReq, const unsigned char *n, unsigned char *nRes);

    /* [onNonceResponse]
     * nReq   (20): input buffer with received nonce response
     */
    bool onNonceResponse(unsigned char *nRes);

    bool createSecureMessage(
        unsigned char *message, // INPUT: 0-44
        unsigned char messageLength,
        unsigned char *ad, // INPUT: 0-3 (+1)
        unsigned char adLength);

    bool onSecureMessage(
        unsigned char *in // INPUT: 17-61
    );

    bool waitingSecureMessage();

private:
    /* Parameters */
    unsigned char keyX[XOODYAK_KEY_SIZE];
    unsigned char keyH[XOODYAK_KEY_SIZE];
    bool keysSet;
    unsigned char _nReqNameId[4];
    unsigned char _nReqRandId[4];
    unsigned char nonce[XOODYAK_NONCE_SIZE]; // nonce
    uint32_t nonceGenTime;
    bool incomingAEAD = false;

    bool setNonce(const unsigned char *n, uint8_t offset = 0);
};

#endif

/*
 * Copyright (C) 2023 Atalonica.
 * Copyright (C) 2023 Southern Storm Software, Pty Ltd.
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

/* ASCON128 authenticated encryption algorithm intended to be used with RFM69
 * Adds time-based nonce expiration
 * References:  https://ascon.iaik.tugraz.at/
 *              https://github.com/rweather/ascon-suite/
 */

/*********** Includes ***********/
#include <Arduino.h>

/*********** Definitions ***********/
#define ASCON128_KEY_SIZE 16      /* Size of the key for ASCON128                */
#define ASCON128_TAG_SIZE 16      /* Size of the authentication tag for ASCON128 */
#define ASCON128_NONCE_SIZE 16    /* Size of the nonce for ASCON128              */
#define ASCON_HASH_SIZE 4        /* Size of the hash output for ASCON           */
#define ASCON_XOF_RATE 8
#define RFM69_MAX_PAYLOAD_SIZE 61 /* Max size for RFM69 payload in bytes         */
#define MAX_AD_SIZE 4             /* Max associated data size in bytes           */
#define NONCE_LIFETIME 1000       /* Max nonce life time (in ms) (keep small)    */
#define NONCE_MIN_GEN_TIME 500    /* Min allowed nonce generation time (in ms)   */

/*********** Typedef structs ***********/

/* Structure of the internal state of the ASCON permutation. */
typedef union
{
    uint64_t S[5];                  /**< 64-bit words of the state */
    uint32_t W[10];                 /**< 32-bit words of the state */
    uint8_t B[40];                  /**< Bytes of the state */
    void *P[40 / sizeof(void *)];   /**< Private backend state */

} ascon_state_t;

typedef struct
{
    ascon_state_t state;    
    unsigned char count;    
    unsigned char mode;     
} ascon_xof_state_t;

typedef struct
{
    ascon_xof_state_t xof;  
} ascon_hash_state_t;

class SecureRF
{

public:
    SecureRF();

    static unsigned char PLAINTEXT[RFM69_MAX_PAYLOAD_SIZE - 1 - ASCON128_TAG_SIZE + 1];
    static unsigned char ASSOCIATED[MAX_AD_SIZE + 1];
    static unsigned char SECURE_PAYLOAD[RFM69_MAX_PAYLOAD_SIZE + 1];

    static uint8_t PLAINTEXT_LEN, ASSOCIATED_LEN, SECURE_PAYLOAD_LEN;

    /* [setKeys]
     * kx (16): input buffer with PSK key used for ASCON128 AEAD
     * kh (16): input buffer with PSK key used for ASCON128 hashing
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
    unsigned char keyX[ASCON128_KEY_SIZE];
    unsigned char keyH[ASCON128_KEY_SIZE];
    bool keysSet;
    unsigned char _nReqNameId[4];
    unsigned char _nReqRandId[4];
    unsigned char nonce[ASCON128_NONCE_SIZE]; // nonce
    uint32_t nonceGenTime, nonceMinGenTime = NONCE_MIN_GEN_TIME;
    uint16_t nErrorCounter = 0;
    bool incomingAEAD = false;

    bool setNonce(const unsigned char *n, uint8_t offset = 0);
};

#endif

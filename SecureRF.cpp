
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

#include "SecureRF.h"

/*********** Includes ***********/
#include <string.h>

/*********** Variables ***********/
unsigned char SecureRF::PLAINTEXT[RFM69_MAX_PAYLOAD_SIZE - 1 - XOODYAK_TAG_SIZE + 1];
unsigned char SecureRF::ASSOCIATED[MAX_AD_SIZE + 1];
unsigned char SecureRF::SECURE_PAYLOAD[RFM69_MAX_PAYLOAD_SIZE + 1];
uint8_t SecureRF::PLAINTEXT_LEN;
uint8_t SecureRF::ASSOCIATED_LEN;
uint8_t SecureRF::SECURE_PAYLOAD_LEN;

/*********** Private function prototypes ***********/
static void xoodyak_absorb(
    xoodoo_state_t *state,     /* Xoodoo permutation state                 */
    uint8_t *phase,            /* Points to the current phase, up or down  */
    const unsigned char *data, /* Points to the data to be absorbed        */
    size_t len                 /* Length of the data to be absorbed        */
);

void xoodoo_permute(xoodoo_state_t *state);

int8_t xoodyak_aead_encrypt(
    unsigned char *c, uint8_t *clen,
    const unsigned char *m, uint8_t mlen,
    const unsigned char *ad, uint8_t adlen,
    const unsigned char *npub,
    const unsigned char *k);

int8_t xoodyak_aead_decrypt(
    unsigned char *m, uint8_t *mlen,
    const unsigned char *c, uint8_t clen,
    const unsigned char *ad, uint8_t adlen,
    const unsigned char *npub,
    const unsigned char *k);

void emptyMem(unsigned char *ptr, uint8_t bytes);

int xoodyak_hash(unsigned char *out, const unsigned char *in, uint8_t inlen);
void xoodyak_hash_init(xoodyak_hash_state_t *state);
void xoodyak_hash_absorb(xoodyak_hash_state_t *state, const unsigned char *in, size_t inlen);
void xoodyak_hash_squeeze(xoodyak_hash_state_t *state, unsigned char *out, size_t outlen);
void xoodyak_hash_finalize(xoodyak_hash_state_t *state, unsigned char *out);
void xoodyak_hash_pad(xoodyak_hash_state_t *state);

/*********** Public functions ***********/

SecureRF::SecureRF()
{
    keysSet = false;
    PLAINTEXT_LEN = 0;
    ASSOCIATED_LEN = 0;
    SECURE_PAYLOAD_LEN = 0;
    emptyMem(PLAINTEXT, RFM69_MAX_PAYLOAD_SIZE - 1 - XOODYAK_TAG_SIZE + 1);
    emptyMem(ASSOCIATED, MAX_AD_SIZE + 1);
    emptyMem(SECURE_PAYLOAD, RFM69_MAX_PAYLOAD_SIZE + 1);
}

void SecureRF::setKeys(const unsigned char *kx, const unsigned char *kh)
{
    if (keysSet == false)
    {
        memcpy(keyX, kx, XOODYAK_KEY_SIZE);
        memcpy(keyH, kh, XOODYAK_KEY_SIZE);
        keysSet = true;
    }
}

bool SecureRF::createNonceRequest(const unsigned char *nReqNameId, const unsigned char *nReqRandId, unsigned char *nReq)
{
    /* Buffer to be hashed */
    unsigned char in[24];
    memcpy(in, nReqNameId, 4);
    memcpy(in + 4, nReqRandId, 4);
    memcpy(in + 8, keyH, 16);

    /* Buffer to store hash */
    unsigned char nReqHash[4];

    if (keysSet && xoodyak_hash(nReqHash, in, 24) == 0)
    {
        /* Save input data for later */
        memcpy(_nReqNameId, nReqNameId, 4);
        memcpy(_nReqRandId, nReqRandId, 4);

        /* Generate nonce request payload */
        memcpy(nReq, in, 8);
        memcpy(nReq + 8, nReqHash, 4);
        nReq[12] = 0;
        return true;
    }
    return false;
}

bool SecureRF::onNonceRequest(unsigned char *nReq, const unsigned char *n, unsigned char *nRes)
{

    /* If the nonce has been already send and another nonce request is received,
     * maybe an attacker is replaying nonce requests,
     * increase nonceMinGenTime exponentially. 
     */
    if(incomingAEAD)
    {
        nErrorCounter = (nErrorCounter >= 200000 ? nErrorCounter : nErrorCounter + 1);
        nonceMinGenTime *= nErrorCounter;
        return false;
    }

    /* Buffer to be hashed */
    unsigned char in[36];
    memcpy(in, nReq, 8);
    memcpy(in + 8, keyH, 16);

    /* Check integrity of nonce request */
    unsigned char nReqHash[4];
    if (xoodyak_hash(nReqHash, (const unsigned char*)in, 24) == 0)
    {
        if (memcmp(nReq + 8, nReqHash, 4) == 0)
        {
            /* Generate nonce response payload (and save nonce) */
            nReqHash[0] = nReq[4] ^= nReq[2];
            nReqHash[1] = nReq[5] ^= nReq[3];
            nReqHash[2] = nReq[6] ^= 0x58;
            nReqHash[3] = nReq[7] ^= nReq[0];
            memcpy(in, nReqHash, 4);
            memcpy(in + 4, keyH, 16);
            memcpy(in + 20, n, 16);
            if (xoodyak_hash(nRes, in, 36) == 0)
            {
                memcpy(nRes + 4, n, 16);
                nRes[20] = 0;
                incomingAEAD = true;
                return setNonce(n);
            }
        }
    }

    /* If nonce request fails checks, increase error */
    nErrorCounter = nErrorCounter >= 200000 ? nErrorCounter : nErrorCounter + 1;
    nonceMinGenTime *= nErrorCounter;
    return false;
}

bool SecureRF::onNonceResponse(unsigned char *nRes)
{
    unsigned char nResTag[4];

    /* Buffer to be hashed */
    unsigned char in[36];
    in[0] = _nReqRandId[0] ^ _nReqNameId[2];
    in[1] = _nReqRandId[1] ^ _nReqNameId[3];
    in[2] = _nReqRandId[2] ^ 0x58;
    in[3] = _nReqRandId[3] ^ _nReqNameId[0];
    memcpy(in + 4, keyH, 16);
    memcpy(in + 20, nRes + 4, 16);

    /* Generate and save expected return tag */
    if (xoodyak_hash(nResTag, (const unsigned char*)in, 36) == 0)
    {
        /* Check nonce response tag is valid */
        if (memcmp(nRes, nResTag, 4) == 0)
        {
            /* Save received nonce value */
            return setNonce(nRes, 4);
        }
    }

    return false;
}

bool SecureRF::createSecureMessage(
    unsigned char *message,
    unsigned char messageLength,
    unsigned char *ad,
    unsigned char adLength)
{
    uint8_t outLen;
    SECURE_PAYLOAD_LEN = 0;

    /* Ensure that nonce has not expired */
    if (keysSet && millis() - nonceGenTime < NONCE_LIFETIME)
    {
        /* Check & save input data */
        adLength++;
        if (adLength <= MAX_AD_SIZE && messageLength <= RFM69_MAX_PAYLOAD_SIZE - adLength - XOODYAK_TAG_SIZE)
        {
            /* Append protocol-specific AD information byte to ad */
            memmove(ad + 1, ad, 4);
            memset(ad, ((adLength - 1) > 1 ? (adLength - 1) << 6 : (adLength - 1) << 7) | (messageLength & 0x3F), 1);

            /* Xoodyak AEAD Encrypt */
            if (xoodyak_aead_encrypt((unsigned char *)SECURE_PAYLOAD, &outLen, message, messageLength, ad, adLength, nonce, keyX) == 0)
            {
                /* Check cipher+tag length is OK */
                if (outLen == messageLength + XOODYAK_TAG_SIZE)
                {
                    /* Append AD and add NULL at end of output so we can send it with RFM69 */
                    memmove(SECURE_PAYLOAD + adLength, SECURE_PAYLOAD, outLen);
                    memcpy(SECURE_PAYLOAD, ad, adLength);
                    SECURE_PAYLOAD_LEN = outLen + adLength;
                    SECURE_PAYLOAD[SECURE_PAYLOAD_LEN] = 0;
                    return true;
                }
            }
        }
    }
    PLAINTEXT_LEN = 0;
    ASSOCIATED_LEN = 0;
    SECURE_PAYLOAD_LEN = 0;
    emptyMem(PLAINTEXT, RFM69_MAX_PAYLOAD_SIZE - 1 - XOODYAK_TAG_SIZE + 1);
    emptyMem(ASSOCIATED, MAX_AD_SIZE + 1);
    emptyMem(SECURE_PAYLOAD, RFM69_MAX_PAYLOAD_SIZE + 1);
    return false;
}

bool SecureRF::waitingSecureMessage()
{
    if (keysSet && millis() - nonceGenTime < NONCE_LIFETIME && incomingAEAD)
    {
        incomingAEAD = false;
        return true;
    }
    return false;
}

bool SecureRF::onSecureMessage(
    unsigned char *in)
{
    uint8_t msgLen, adLen;
    unsigned char tmp_ciphtag[64];
    unsigned char tmp_ad[5];
    PLAINTEXT_LEN = 0;
    ASSOCIATED_LEN = 0;

    /* Ensure that nonce has not expired */
    if (millis() - nonceGenTime < NONCE_LIFETIME)
    {
        /* Extract AD and message lengths */
        adLen = (in[0] >> 6) + 1;
        msgLen = in[0] & 0x3F;

        /* Split AD and Ciphertext+Tag: IN -> AD + (CIPH+TAG)*/
        memcpy(tmp_ad, in, adLen);
        memcpy(tmp_ciphtag, in + adLen, msgLen + XOODYAK_TAG_SIZE);

        /* Xoodyak AEAD Decrypt and validation */
        if (xoodyak_aead_decrypt((unsigned char *)PLAINTEXT, &msgLen, tmp_ciphtag, msgLen + XOODYAK_TAG_SIZE, tmp_ad, adLen, nonce, keyX) == 0)
        {
            /* Check ad+cipher+tag length is OK */
            if (adLen + msgLen + XOODYAK_TAG_SIZE <= RFM69_MAX_PAYLOAD_SIZE)
            {
                /* Update output buffers lengths and 
                 * update ad buffer (and remove protocol-specific byte) */
                ASSOCIATED_LEN = adLen - 1;
                memcpy(ASSOCIATED, tmp_ad + 1, ASSOCIATED_LEN);
                PLAINTEXT_LEN = msgLen;
                PLAINTEXT[msgLen] = 0;

                /* Reset nonceMinGenTime (in case it was increased) */
                nonceMinGenTime = NONCE_MIN_GEN_TIME;
                nErrorCounter = 0;

                return true;
            }
        }
    }
    PLAINTEXT_LEN = 0;
    ASSOCIATED_LEN = 0;
    SECURE_PAYLOAD_LEN = 0;
    emptyMem(PLAINTEXT, RFM69_MAX_PAYLOAD_SIZE - 1 - XOODYAK_TAG_SIZE + 1);
    emptyMem(ASSOCIATED, MAX_AD_SIZE + 1);
    emptyMem(SECURE_PAYLOAD, RFM69_MAX_PAYLOAD_SIZE + 1);
    return false;
}

bool SecureRF::setNonce(const unsigned char *n, uint8_t offset)
{
    /* Update generation/request time and limit generation frequency */
    if (millis() - nonceGenTime > nonceMinGenTime)
    {
        nonceGenTime = millis();
        /* If nonce is same as previous -> error */
        if (memcmp(n + offset, nonce, XOODYAK_NONCE_SIZE) == 0)
        {
            return false;
        }
        memcpy(nonce, n + offset, XOODYAK_NONCE_SIZE);
        return true;
    }

    nonceGenTime = millis();
    return false;
}

/*********** Private functions **********/

void emptyMem(unsigned char *ptr, uint8_t nBytes)
{
    memset(ptr, 0, nBytes);
}

int8_t xoodyak_aead_encrypt(
    unsigned char *c, uint8_t *clen,
    const unsigned char *m, uint8_t mlen,
    const unsigned char *ad, uint8_t adlen,
    const unsigned char *npub,
    const unsigned char *k)
{
    xoodoo_state_t state;
    uint8_t phase, domain;
    unsigned temp;

    /* Set the length of the returned ciphertext */
    *clen = mlen + XOODYAK_TAG_SIZE;

    /* Check if ciphertext + associated data length can be send by RFM69 */
    if (*clen + adlen > RFM69_MAX_PAYLOAD_SIZE || adlen > MAX_AD_SIZE)
    {
        return -1;
    }

    /* Initialize the state with the key */
    memcpy(state.B, k, XOODYAK_KEY_SIZE);
    memset(state.B + XOODYAK_KEY_SIZE, 0, sizeof(state.B) - XOODYAK_KEY_SIZE);
    state.B[XOODYAK_KEY_SIZE + 1] = 0x01; /* Padding */
    state.B[sizeof(state.B) - 1] = 0x02;  /* Domain separation */
    phase = XOODYAK_PHASE_DOWN;

    /* Absorb the nonce and associated data */
    xoodyak_absorb(&state, &phase, npub, XOODYAK_NONCE_SIZE);
    xoodyak_absorb(&state, &phase, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    domain = 0x80;
    while (mlen > XOODYAK_SQUEEZE_RATE)
    {
        state.B[sizeof(state.B) - 1] ^= domain;
        xoodoo_permute(&state);
        lw_xor_block_2_dest(c, state.B, m, XOODYAK_SQUEEZE_RATE);
        state.B[XOODYAK_SQUEEZE_RATE] ^= 0x01; /* Padding */
        c += XOODYAK_SQUEEZE_RATE;
        m += XOODYAK_SQUEEZE_RATE;
        mlen -= XOODYAK_SQUEEZE_RATE;
        domain = 0;
    }
    state.B[sizeof(state.B) - 1] ^= domain;
    xoodoo_permute(&state);
    temp = (unsigned)mlen;
    lw_xor_block_2_dest(c, state.B, m, temp);
    state.B[temp] ^= 0x01; /* Padding */
    c += temp;

    /* Generate the authentication tag */
    state.B[sizeof(state.B) - 1] ^= 0x40; /* Domain separation */
    xoodoo_permute(&state);
    memcpy(c, state.B, XOODYAK_TAG_SIZE);

    return 0;
}

int8_t aead_check_tag(
    unsigned char *plaintext, size_t plaintext_len,
    const unsigned char *tag1, const unsigned char *tag2, size_t size)
{
    /* Set "accum" to -1 if the tags match, or 0 if they don't match */
    int accum = 0;
    while (size > 0)
    {
        accum |= (*tag1++ ^ *tag2++);
        --size;
    }
    accum = (accum - 1) >> 8;

    /* Destroy the plaintext if the tag match failed */
    while (plaintext_len > 0)
    {
        *plaintext++ &= accum;
        --plaintext_len;
    }

    /* If "accum" is 0, return -1, otherwise return 0 */
    return (int8_t)~accum;
}

int8_t xoodyak_aead_decrypt(
    unsigned char *m, uint8_t *mlen,
    const unsigned char *c, uint8_t clen,
    const unsigned char *ad, uint8_t adlen,
    const unsigned char *npub,
    const unsigned char *k)
{
    xoodoo_state_t state;
    uint8_t phase, domain;
    unsigned temp;
    unsigned char *mtemp = m;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < XOODYAK_TAG_SIZE)
        return -1;
    *mlen = clen - XOODYAK_TAG_SIZE;

    /* Initialize the state with the key */
    memcpy(state.B, k, XOODYAK_KEY_SIZE);
    memset(state.B + XOODYAK_KEY_SIZE, 0, sizeof(state.B) - XOODYAK_KEY_SIZE);
    state.B[XOODYAK_KEY_SIZE + 1] = 0x01; /* Padding */
    state.B[sizeof(state.B) - 1] = 0x02;  /* Domain separation */
    phase = XOODYAK_PHASE_DOWN;

    /* Absorb the nonce and associated data */
    xoodyak_absorb(&state, &phase, npub, XOODYAK_NONCE_SIZE);
    xoodyak_absorb(&state, &phase, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    domain = 0x80;
    clen -= XOODYAK_TAG_SIZE;
    while (clen > XOODYAK_SQUEEZE_RATE)
    {
        state.B[sizeof(state.B) - 1] ^= domain;
        xoodoo_permute(&state);
        lw_xor_block_swap(m, state.B, c, XOODYAK_SQUEEZE_RATE);
        state.B[XOODYAK_SQUEEZE_RATE] ^= 0x01; /* Padding */
        c += XOODYAK_SQUEEZE_RATE;
        m += XOODYAK_SQUEEZE_RATE;
        clen -= XOODYAK_SQUEEZE_RATE;
        domain = 0;
    }
    state.B[sizeof(state.B) - 1] ^= domain;
    xoodoo_permute(&state);
    temp = (unsigned)clen;
    lw_xor_block_swap(m, state.B, c, temp);
    state.B[temp] ^= 0x01; /* Padding */
    c += temp;

    /* Check the authentication tag */
    state.B[sizeof(state.B) - 1] ^= 0x40; /* Domain separation */
    xoodoo_permute(&state);
    return aead_check_tag(mtemp, *mlen, state.B, c, XOODYAK_TAG_SIZE);
}

void xoodyak_hash_absorb(xoodyak_hash_state_t *state, const unsigned char *in, uint8_t inlen)
{
    uint8_t domain;
    unsigned temp;

    /* If we were squeezing, then restart the absorb phase */
    if (state->s.mode == XOODYAK_HASH_MODE_SQUEEZE)
    {
        xoodoo_hash_permute(state);
        state->s.mode = XOODYAK_HASH_MODE_INIT_ABSORB;
        state->s.count = 0;
    }

    /* The first block needs a different domain separator to the others */
    domain = (state->s.mode == XOODYAK_HASH_MODE_INIT_ABSORB) ? 0x01 : 0x00;

    /* Absorb the input data into the state */
    while (inlen > 0)
    {
        if (state->s.count >= XOODYAK_HASH_RATE)
        {
            state->s.state[XOODYAK_HASH_RATE] ^= 0x01; /* Padding */
            state->s.state[sizeof(state->s.state) - 1] ^= domain;
            xoodoo_hash_permute(state);
            state->s.mode = XOODYAK_HASH_MODE_ABSORB;
            state->s.count = 0;
            domain = 0x00;
        }
        temp = XOODYAK_HASH_RATE - state->s.count;
        if (temp > inlen)
            temp = (unsigned)inlen;
        lw_xor_block(state->s.state + state->s.count, in, temp);
        state->s.count += temp;
        in += temp;
        inlen -= temp;
    }
}

void xoodyak_hash_init(xoodyak_hash_state_t *state)
{
    memset(state, 0, sizeof(xoodyak_hash_state_t));
    state->s.mode = XOODYAK_HASH_MODE_INIT_ABSORB;
}

void xoodyak_hash_squeeze(xoodyak_hash_state_t *state, unsigned char *out, size_t outlen)
{
    uint8_t domain;
    unsigned temp;

    /* If we were absorbing, then terminate the absorb phase */
    if (state->s.mode != XOODYAK_HASH_MODE_SQUEEZE)
    {
        domain = (state->s.mode == XOODYAK_HASH_MODE_INIT_ABSORB) ? 0x01 : 0x00;
        state->s.state[state->s.count] ^= 0x01; /* Padding */
        state->s.state[sizeof(state->s.state) - 1] ^= domain;
        xoodoo_hash_permute(state);
        state->s.mode = XOODYAK_HASH_MODE_SQUEEZE;
        state->s.count = 0;
    }

    /* Squeeze data out of the state */
    while (outlen > 0)
    {
        if (state->s.count >= XOODYAK_HASH_RATE)
        {
            /* Padding is always at index 0 for squeezing subsequent
             * blocks because the number of bytes we have absorbed
             * since the previous block was squeezed out is zero */
            state->s.state[0] ^= 0x01;
            xoodoo_hash_permute(state);
            state->s.count = 0;
        }
        temp = XOODYAK_HASH_RATE - state->s.count;
        if (temp > outlen)
            temp = (unsigned)outlen;
        memcpy(out, state->s.state + state->s.count, temp);
        state->s.count += temp;
        out += temp;
        outlen -= temp;
    }
}

void xoodyak_hash_finalize(xoodyak_hash_state_t *state, unsigned char *out)
{
    xoodyak_hash_squeeze(state, out, XOODYAK_HASH_SIZE);
}

void xoodyak_hash_pad(xoodyak_hash_state_t *state)
{
    if (state->s.mode == XOODYAK_HASH_MODE_SQUEEZE)
    {
        /* We were squeezing output, so re-enter the absorb phase
         * which will implicitly align on a rate block boundary */
        xoodyak_hash_absorb(state, (unsigned char*)0, (uint8_t)0);
    }
    else if (state->s.count != 0 && state->s.count != XOODYAK_HASH_RATE)
    {
        /* Not currently aligned, so finish off the current block */
        state->s.count = XOODYAK_HASH_RATE;
    }
}

int xoodyak_hash(unsigned char *out, const unsigned char *in, uint8_t inlen)
{
    xoodyak_hash_state_t state;
    xoodyak_hash_init(&state);
    xoodyak_hash_absorb(&state, in, inlen);
    xoodyak_hash_squeeze(&state, out, XOODYAK_HASH_SIZE);
    return 0;
}

/* Permutes the Xoodoo state (in little-endian) */
void xoodoo_permute(xoodoo_state_t *state)
{
    static uint16_t const rc[12] = {// 12 Xoodoo rounds
                                    0x0058, 0x0038, 0x03C0, 0x00D0, 0x0120, 0x0014,
                                    0x0060, 0x002C, 0x0380, 0x00F0, 0x01A0, 0x0012};

    uint8_t round;
    uint32_t x00, x01, x02, x03;
    uint32_t x10, x11, x12, x13;
    uint32_t x20, x21, x22, x23;
    uint32_t t1, t2;

    /* Load the state and convert from little-endian byte order */
    x00 = state->S[0][0];
    x01 = state->S[0][1];
    x02 = state->S[0][2];
    x03 = state->S[0][3];
    x10 = state->S[1][0];
    x11 = state->S[1][1];
    x12 = state->S[1][2];
    x13 = state->S[1][3];
    x20 = state->S[2][0];
    x21 = state->S[2][1];
    x22 = state->S[2][2];
    x23 = state->S[2][3];

    /* Perform all permutation rounds (12) */
    for (round = 0; round < 12; ++round)
    {
        /* Optimization ideas from the Xoodoo implementation here:
         * https://github.com/XKCP/XKCP/tree/master/lib/low/Xoodoo/Optimized */

        /* Step theta: Mix column parity */
        t1 = x03 ^ x13 ^ x23;
        t2 = x00 ^ x10 ^ x20;
        t1 = leftRotate5(t1) ^ leftRotate14(t1);
        t2 = leftRotate5(t2) ^ leftRotate14(t2);
        x00 ^= t1;
        x10 ^= t1;
        x20 ^= t1;
        t1 = x01 ^ x11 ^ x21;
        t1 = leftRotate5(t1) ^ leftRotate14(t1);
        x01 ^= t2;
        x11 ^= t2;
        x21 ^= t2;
        t2 = x02 ^ x12 ^ x22;
        t2 = leftRotate5(t2) ^ leftRotate14(t2);
        x02 ^= t1;
        x12 ^= t1;
        x22 ^= t1;
        x03 ^= t2;
        x13 ^= t2;
        x23 ^= t2;

        /* Step rho-west: Plane shift */
        t1 = x13;
        x13 = x12;
        x12 = x11;
        x11 = x10;
        x10 = t1;
        x20 = leftRotate11(x20);
        x21 = leftRotate11(x21);
        x22 = leftRotate11(x22);
        x23 = leftRotate11(x23);

        /* Step iota: Add the round constant to the state */
        x00 ^= rc[round];

        /* Step chi: Non-linear layer */
        x00 ^= (~x10) & x20;
        x10 ^= (~x20) & x00;
        x20 ^= (~x00) & x10;
        x01 ^= (~x11) & x21;
        x11 ^= (~x21) & x01;
        x21 ^= (~x01) & x11;
        x02 ^= (~x12) & x22;
        x12 ^= (~x22) & x02;
        x22 ^= (~x02) & x12;
        x03 ^= (~x13) & x23;
        x13 ^= (~x23) & x03;
        x23 ^= (~x03) & x13;

        /* Step rho-east: Plane shift */
        x10 = leftRotate1(x10);
        x11 = leftRotate1(x11);
        x12 = leftRotate1(x12);
        x13 = leftRotate1(x13);
        t1 = leftRotate8(x22);
        t2 = leftRotate8(x23);
        x22 = leftRotate8(x20);
        x23 = leftRotate8(x21);
        x20 = t1;
        x21 = t2;
    }

    /* Convert back into little-endian and store to the output state */
    state->S[0][0] = x00;
    state->S[0][1] = x01;
    state->S[0][2] = x02;
    state->S[0][3] = x03;
    state->S[1][0] = x10;
    state->S[1][1] = x11;
    state->S[1][2] = x12;
    state->S[1][3] = x13;
    state->S[2][0] = x20;
    state->S[2][1] = x21;
    state->S[2][2] = x22;
    state->S[2][3] = x23;
}

/* Absorbs data into the Xoodoo permutation state */
static void xoodyak_absorb(
    xoodoo_state_t *state,     /* Xoodoo permutation state                 */
    uint8_t *phase,            /* Points to the current phase, up or down  */
    const unsigned char *data, /* Points to the data to be absorbed        */
    size_t len)                /* Length of the data to be absorbed        */
{
    uint8_t domain = 0x03;
    unsigned temp;
    while (len > XOODYAK_ABSORB_RATE)
    {
        if (*phase != XOODYAK_PHASE_UP)
            xoodoo_permute(state);
        lw_xor_block(state->B, data, XOODYAK_ABSORB_RATE);
        state->B[XOODYAK_ABSORB_RATE] ^= 0x01; /* Padding */
        state->B[sizeof(state->B) - 1] ^= domain;
        data += XOODYAK_ABSORB_RATE;
        len -= XOODYAK_ABSORB_RATE;
        domain = 0x00;
        *phase = XOODYAK_PHASE_DOWN;
    }
    temp = (unsigned)len;
    if (*phase != XOODYAK_PHASE_UP)
        xoodoo_permute(state);
    lw_xor_block(state->B, data, temp);
    state->B[temp] ^= 0x01; /* Padding */
    state->B[sizeof(state->B) - 1] ^= domain;
    *phase = XOODYAK_PHASE_DOWN;
}

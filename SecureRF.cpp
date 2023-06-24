
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

#include "SecureRF.h"

/*********** Includes ***********/
#include <string.h>

/*********** Macros ***********/
#define ascon_absorb_8(state, data, offset) \
    ascon_absorb_sliced((state), (data), (offset) / 8)

#define ascon_absorb_16(state, data, offset) \
    do { \
        ascon_absorb_sliced((state), (data), (offset) / 8); \
        ascon_absorb_sliced((state), (data) + 8, (offset) / 8 + 1); \
    } while (0)

#define ascon_absorb_partial(state, data, offset, count) \
    ascon_add_bytes((state), (data), (offset), (count))

#define ascon_absorb_sliced(state, data, offset) \
    do { \
        ascon_state_t *s = (state); \
        uint32_t high = be_load_word32((data)); \
        uint32_t low  = be_load_word32((data) + 4); \
        ascon_separate(high); \
        ascon_separate(low); \
        s->W[(offset) * 2] ^= (high << 16) | (low & 0x0000FFFFU); \
        s->W[(offset) * 2 + 1] ^= (high & 0xFFFF0000U) | (low >> 16); \
    } while (0)

#define ascon_absorb_word64(state, value, offset) \
    do { \
        ascon_state_t *s = (state); \
        uint32_t high = (uint32_t)((value) >> 32); \
        uint32_t low  = (uint32_t)(value); \
        ascon_separate(high); \
        ascon_separate(low); \
        s->W[(offset) * 2] ^= (high << 16) | (low & 0x0000FFFFU); \
        s->W[(offset) * 2 + 1] ^= (high & 0xFFFF0000U) | (low >> 16); \
    } while (0)

#define ascon_bit_permute_step(_y, mask, shift) \
    do { \
        uint32_t y = (_y); \
        uint32_t t = ((y >> (shift)) ^ y) & (mask); \
        (_y) = (y ^ t) ^ (t << (shift)); \
    } while (0)

#define ascon_combine(x) \
    do { \
        ascon_bit_permute_step((x), 0x0000aaaa, 15); \
        ascon_bit_permute_step((x), 0x0000cccc, 14); \
        ascon_bit_permute_step((x), 0x0000f0f0, 12); \
        ascon_bit_permute_step((x), 0x0000ff00, 8); \
    } while (0)

#define ascon_decrypt_8(state, dest, src, offset) \
    ascon_decrypt_sliced((state), (dest), (src), (offset) / 8)

#define ascon_decrypt_partial(state, dest, src, offset, count) \
    ascon_extract_and_overwrite_bytes((state), (src), (dest), (offset), (count))

#define ascon_decrypt_sliced(state, m, c, offset) \
    do { \
        ascon_state_t *s = (state); \
        uint32_t high, low, high2, low2; \
        high = be_load_word32((c)); \
        low  = be_load_word32((c) + 4); \
        ascon_separate(high); \
        ascon_separate(low); \
        high2 = high ^ ((s->W[(offset) * 2] >> 16) | \
                        (s->W[(offset) * 2 + 1] & 0xFFFF0000U)); \
        low2 = low ^ ((s->W[(offset) * 2] & 0x0000FFFFU) | \
                    (s->W[(offset) * 2 + 1] << 16)); \
        s->W[(offset) * 2] = (high << 16) | (low & 0x0000FFFFU); \
        s->W[(offset) * 2 + 1] = (high & 0xFFFF0000U) | (low >> 16); \
        ascon_combine(high2); \
        ascon_combine(low2); \
        be_store_word32((m), high2); \
        be_store_word32((m) + 4, low2); \
    } while (0)

#define ascon_encrypt_8(state, dest, src, offset) \
    ascon_encrypt_sliced((state), (dest), (src), (offset) / 8)

#define ascon_encrypt_partial(state, dest, src, offset, count) \
    do { \
        ascon_add_bytes((state), (src), (offset), (count)); \
        ascon_extract_bytes((state), (dest), (offset), (count)); \
    } while (0)

#define ascon_encrypt_sliced(state, c, m, offset) \
    do { \
        ascon_state_t *s = (state); \
        uint32_t high = be_load_word32((m)); \
        uint32_t low  = be_load_word32((m) + 4); \
        ascon_separate(high); \
        ascon_separate(low); \
        s->W[(offset) * 2] ^= (high << 16) | (low & 0x0000FFFFU); \
        s->W[(offset) * 2 + 1] ^= (high & 0xFFFF0000U) | (low >> 16); \
        high = (s->W[(offset) * 2] >> 16) | \
            (s->W[(offset) * 2 + 1] & 0xFFFF0000U); \
        low  = (s->W[(offset) * 2] & 0x0000FFFFU) | \
            (s->W[(offset) * 2 + 1] << 16); \
        ascon_combine(high); \
        ascon_combine(low); \
        be_store_word32((c), high); \
        be_store_word32((c) + 4, low); \
    } while (0)

#define ascon_pad(state, offset) \
    ((state)->W[((offset) / 8) * 2 + 1] ^= \
            (0x80000000U >> (((offset) & 7) * 4)))

#define ascon_separator(state) ((state)->W[8] ^= 0x01)

#define ascon_separate(x) \
    do { \
        ascon_bit_permute_step((x), 0x22222222, 1); \
        ascon_bit_permute_step((x), 0x0c0c0c0c, 2); \
        ascon_bit_permute_step((x), 0x00f000f0, 4); \
        ascon_bit_permute_step((x), 0x0000ff00, 8); \
    } while (0)

#define ascon_set_sliced(state, data, offset) \
    do { \
        ascon_state_t *s = (state); \
        uint32_t high = be_load_word32((data)); \
        uint32_t low  = be_load_word32((data) + 4); \
        ascon_separate(high); \
        ascon_separate(low); \
        s->W[(offset) * 2] = (high << 16) | (low & 0x0000FFFFU); \
        s->W[(offset) * 2 + 1] = (high & 0xFFFF0000U) | (low >> 16); \
    } while (0)

#define ascon_set_word64(state, value, offset) \
    do { \
        ascon_state_t *s = (state); \
        uint32_t high = (uint32_t)((value) >> 32); \
        uint32_t low  = (uint32_t)(value); \
        ascon_separate(high); \
        ascon_separate(low); \
        s->W[(offset) * 2] = (high << 16) | (low & 0x0000FFFFU); \
        s->W[(offset) * 2 + 1] = (high & 0xFFFF0000U) | (low >> 16); \
    } while (0)

#define ascon_squeeze_8(state, data, offset) \
    ascon_squeeze_sliced((state), (data), (offset) / 8)

#define ascon_squeeze_16(state, data, offset) \
    do { \
        ascon_squeeze_sliced((state), (data), (offset) / 8); \
        ascon_squeeze_sliced((state), (data) + 8, (offset) / 8 + 1); \
    } while (0)

#define ascon_squeeze_partial(state, data, offset, count) \
    ascon_extract_bytes((state), (data), (offset), (count))

#define ascon_squeeze_sliced(state, data, offset) \
    do { \
        const ascon_state_t *s = (state); \
        uint32_t high, low; \
        high = (s->W[(offset) * 2] >> 16) | \
            (s->W[(offset) * 2 + 1] & 0xFFFF0000U); \
        low  = (s->W[(offset) * 2] & 0x0000FFFFU) | \
            (s->W[(offset) * 2 + 1] << 16); \
        ascon_combine(high); \
        ascon_combine(low); \
        be_store_word32((data), high); \
        be_store_word32((data) + 4, low); \
    } while (0)

#define ascon_squeeze_word64(state, value, offset) \
    do { \
        const ascon_state_t *s = (state); \
        uint32_t high, low; \
        high = (s->W[(offset) * 2] >> 16) | \
            (s->W[(offset) * 2 + 1] & 0xFFFF0000U); \
        low  = (s->W[(offset) * 2] & 0x0000FFFFU) | \
            (s->W[(offset) * 2 + 1] << 16); \
        ascon_combine(high); \
        ascon_combine(low); \
        (value) = (((uint64_t)high) << 32) | low; \
    } while (0)

#define be_load_word32(ptr) \
    ((((uint32_t)((ptr)[0])) << 24) | \
    (((uint32_t)((ptr)[1])) << 16) | \
    (((uint32_t)((ptr)[2])) << 8) | \
    ((uint32_t)((ptr)[3])))

#define be_store_word32(ptr, x) \
    do { \
        uint32_t _x = (x); \
        (ptr)[0] = (uint8_t)(_x >> 24); \
        (ptr)[1] = (uint8_t)(_x >> 16); \
        (ptr)[2] = (uint8_t)(_x >> 8); \
        (ptr)[3] = (uint8_t)_x; \
    } while (0)

#define rightRotate(a, bits) \
    (__extension__ ({ \
        uint32_t _temp = (a); \
        (_temp >> (bits)) | (_temp << (32 - (bits))); \
    }))

#define rightRotate1(a)  (rightRotate((a), 1))
#define rightRotate2(a)  (rightRotate((a), 2))
#define rightRotate3(a)  (rightRotate((a), 3))
#define rightRotate4(a)  (rightRotate((a), 4))
#define rightRotate5(a)  (rightRotate((a), 5))
#define rightRotate9(a)  (rightRotate((a), 9))
#define rightRotate10(a) (rightRotate((a), 10))
#define rightRotate11(a) (rightRotate((a), 11))
#define rightRotate17(a) (rightRotate((a), 17))
#define rightRotate19(a) (rightRotate((a), 19))
#define rightRotate20(a) (rightRotate((a), 20))

#define ROUND_CONSTANT_PAIR(rc1, rc2) (~((uint32_t)(rc1))), (~((uint32_t)(rc2)))

/*********** Variables ***********/
unsigned char SecureRF::PLAINTEXT[RFM69_MAX_PAYLOAD_SIZE - 1 - ASCON128_TAG_SIZE + 1];
unsigned char SecureRF::ASSOCIATED[MAX_AD_SIZE + 1];
unsigned char SecureRF::SECURE_PAYLOAD[RFM69_MAX_PAYLOAD_SIZE + 1];
uint8_t SecureRF::PLAINTEXT_LEN;
uint8_t SecureRF::ASSOCIATED_LEN;
uint8_t SecureRF::SECURE_PAYLOAD_LEN;
uint8_t const ASCON128_IV[8] = { 0x80, 0x40, 0x0c, 0x06, 0x00, 0x00, 0x00, 0x00 };

/*********** Private function prototypes ***********/
int8_t ascon128_aead_encrypt (
    unsigned char *c, uint8_t *clen,
    const unsigned char *m, uint8_t mlen,
    const unsigned char *ad, uint8_t adlen,
    const unsigned char *npub,
    const unsigned char *k );

int8_t ascon128_aead_decrypt (
    unsigned char *m, uint8_t *mlen,
    const unsigned char *c, uint8_t clen,
    const unsigned char *ad, uint8_t adlen,
    const unsigned char *npub,
    const unsigned char *k );

void ascon_add_bytes (
    ascon_state_t *state,
    const uint8_t *data,
    unsigned offset,
    unsigned size );

void ascon_aead_absorb_8 (
    ascon_state_t *state,
    const unsigned char *data,
    size_t len,
    uint8_t first_round,
    int last_permute );

int ascon_aead_check_tag (
    unsigned char *plaintext,
    size_t plaintext_len,
    const unsigned char *tag1,
    const unsigned char *tag2,
    size_t size );

unsigned char ascon_aead_decrypt_8 (
    ascon_state_t *state,
    unsigned char *dest,
    const unsigned char *src,
    size_t len,
    uint8_t first_round,
    unsigned char partial );

unsigned char ascon_aead_encrypt_8 (
    ascon_state_t *state,
    unsigned char *dest,
    const unsigned char *src,
    size_t len,
    uint8_t first_round,
    unsigned char partial );

void ascon_clean(void *buf, unsigned size);

void ascon_extract_and_overwrite_bytes (
    ascon_state_t *state,
    const uint8_t *input,
    uint8_t *output,
    unsigned offset,
    unsigned size );

void ascon_extract_bytes (
    const ascon_state_t *state,
    uint8_t *data,
    unsigned offset,
    unsigned size );

void ascon_free(ascon_state_t *state);

void ascon_hash(unsigned char *out, const unsigned char *in, size_t inlen);

void ascon_hash_init(ascon_hash_state_t *state);

void ascon_overwrite_bytes (
    ascon_state_t *state,
    const uint8_t *data,
    unsigned offset,
    unsigned size );

void ascon_permute(ascon_state_t *state, uint8_t first_round);

void emptyMem(unsigned char *ptr, uint8_t bytes);

void ascon_xof_absorb (
    ascon_xof_state_t *state,
    const unsigned char *in,
    size_t inlen );

void ascon_xof_free(ascon_xof_state_t *state);

void ascon_xof_squeeze (
    ascon_xof_state_t *state,
    unsigned char *out,
    size_t outlen );

/*********** Public functions ***********/

SecureRF::SecureRF()
{
    keysSet = false;
    PLAINTEXT_LEN = 0;
    ASSOCIATED_LEN = 0;
    SECURE_PAYLOAD_LEN = 0;
    nErrorCounter = 0;
    incomingAEAD = false;

    emptyMem(PLAINTEXT, RFM69_MAX_PAYLOAD_SIZE - 1 - ASCON128_TAG_SIZE + 1);
    emptyMem(ASSOCIATED, MAX_AD_SIZE + 1);
    emptyMem(SECURE_PAYLOAD, RFM69_MAX_PAYLOAD_SIZE + 1);
}

void SecureRF::setKeys(const unsigned char *kx, const unsigned char *kh)
{
    if (keysSet == false)
    {
        memcpy(keyX, kx, ASCON128_KEY_SIZE);
        memcpy(keyH, kh, ASCON128_KEY_SIZE);
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

    if (keysSet)
    {
        ascon_hash(nReqHash, in, 24);

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
        if(nErrorCounter < 1321) // 20 days (@1000ms)
        {
            nErrorCounter++;
            nonceMinGenTime += nErrorCounter * 2 * NONCE_MIN_GEN_TIME;
        }
        return false;
    }

    /* Buffer to be hashed */
    unsigned char in[36];
    memcpy(in, nReq, 8);
    memcpy(in + 8, keyH, 16);

    /* Check integrity of nonce request */
    unsigned char nReqHash[4];
    ascon_hash(nReqHash, (const unsigned char*)in, 24);

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

        ascon_hash(nRes, in, 36);
        memcpy(nRes + 4, n, 16);
        nRes[20] = 0;
        incomingAEAD = true;
        return setNonce(n);
    }

    /* If nonce request fails checks, increase error */
    if(nErrorCounter < 1321) // 20 days (@1000ms)
    {
        nErrorCounter++;
        nonceMinGenTime += nErrorCounter * 2 * NONCE_MIN_GEN_TIME;
    }
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
    ascon_hash(nResTag, (const unsigned char*)in, 36);

    /* Check nonce response tag is valid */
    if (memcmp(nRes, nResTag, 4) == 0)
    {
        /* Save received nonce value */
        return setNonce(nRes, 4);
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
        if (adLength <= MAX_AD_SIZE && messageLength <= RFM69_MAX_PAYLOAD_SIZE - adLength - ASCON128_TAG_SIZE)
        {
            /* Append protocol-specific AD information byte to ad */
            memmove(ad + 1, ad, 4);
            memset(ad, ((adLength - 1) > 1 ? (adLength - 1) << 6 : (adLength - 1) << 7) | (messageLength & 0x3F), 1);

            /* ASCON AEAD Encrypt */
            if (ascon128_aead_encrypt((unsigned char *)SECURE_PAYLOAD, &outLen, message, messageLength, ad, adLength, nonce, keyX) == 0)
            {
                /* Check cipher+tag length is OK */
                if (outLen == messageLength + ASCON128_TAG_SIZE)
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
    emptyMem(PLAINTEXT, RFM69_MAX_PAYLOAD_SIZE - 1 - ASCON128_TAG_SIZE + 1);
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
        adLen = (in[0] >> 6);
        msgLen = in[0] & 0x3F;

        /* Split AD and Ciphertext+Tag: IN -> AD + (CIPH+TAG)*/
        memcpy(tmp_ad, in, adLen);
        memcpy(tmp_ciphtag, in + adLen, msgLen + ASCON128_TAG_SIZE);

        /* Xoodyak AEAD Decrypt and validation */
        if (ascon128_aead_decrypt((unsigned char *)PLAINTEXT, &msgLen, tmp_ciphtag, msgLen + ASCON128_TAG_SIZE, tmp_ad, adLen, nonce, keyX) == 0)
        {
            /* Check ad+cipher+tag length is OK */
            if (adLen + msgLen + ASCON128_TAG_SIZE <= RFM69_MAX_PAYLOAD_SIZE)
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
    emptyMem(PLAINTEXT, RFM69_MAX_PAYLOAD_SIZE - 1 - ASCON128_TAG_SIZE + 1);
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
        if (memcmp(n + offset, nonce, ASCON128_NONCE_SIZE) == 0)
        {
            return false;
        }
        memcpy(nonce, n + offset, ASCON128_NONCE_SIZE);
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

void ascon_init(ascon_state_t *state)
{
    state->S[0] = 0;
    state->S[1] = 0;
    state->S[2] = 0;
    state->S[3] = 0;
    state->S[4] = 0;
}

void ascon_permute(ascon_state_t *state, uint8_t first_round)
{
    static const uint32_t RC[12 * 2] = {
        ROUND_CONSTANT_PAIR(12, 12),
        ROUND_CONSTANT_PAIR( 9, 12),
        ROUND_CONSTANT_PAIR(12,  9),
        ROUND_CONSTANT_PAIR( 9,  9),
        ROUND_CONSTANT_PAIR( 6, 12),
        ROUND_CONSTANT_PAIR( 3, 12),
        ROUND_CONSTANT_PAIR( 6,  9),
        ROUND_CONSTANT_PAIR( 3,  9),
        ROUND_CONSTANT_PAIR(12,  6),
        ROUND_CONSTANT_PAIR( 9,  6),
        ROUND_CONSTANT_PAIR(12,  3),
        ROUND_CONSTANT_PAIR( 9,  3)
    };
    const uint32_t *rc = RC + first_round * 2;
    uint32_t t0, t1, t2, t3, t4;

    /* Load the state into local variables */
    uint32_t x0_e = state->W[0];
    uint32_t x0_o = state->W[1];
    uint32_t x1_e = state->W[2];
    uint32_t x1_o = state->W[3];
    uint32_t x2_e = state->W[4];
    uint32_t x2_o = state->W[5];
    uint32_t x3_e = state->W[6];
    uint32_t x3_o = state->W[7];
    uint32_t x4_e = state->W[8];
    uint32_t x4_o = state->W[9];

    /* We move the "x2 = ~x2" term of the substitution layer outside
    * the loop.  The round constants are modified to "NOT value" to
    * apply "x2 = ~x2" automatically each round.  Then we only
    * need to invert x2 for real before and after the loop. */
    x2_e = ~x2_e;
    x2_o = ~x2_o;

    /* Perform all permutation rounds */
    while (first_round < 12) {
        /* Add the round constants for this round to the state */
        x2_e ^= rc[0];
        x2_o ^= rc[1];
        rc += 2;

        /* Substitution layer */
        #define ascon_sbox(x0, x1, x2, x3, x4) \
            do { \
                x0 ^= x4;   x4 ^= x3;   x2 ^= x1; \
                t0 = ~x0;   t1 = ~x1;   t2 = ~x2;   t3 = ~x3;   t4 = ~x4; \
                t0 &= x1;   t1 &= x2;   t2 &= x3;   t3 &= x4;   t4 &= x0; \
                x0 ^= t1;   x1 ^= t2;   x2 ^= t3;   x3 ^= t4;   x4 ^= t0; \
                x1 ^= x0;   x0 ^= x4;   x3 ^= x2;   /* x2 = ~x2; */ \
            } while (0)
        ascon_sbox(x0_e, x1_e, x2_e, x3_e, x4_e);
        ascon_sbox(x0_o, x1_o, x2_o, x3_o, x4_o);

        /* Linear diffusion layer */
        /* x0 ^= rightRotate19_64(x0) ^ rightRotate28_64(x0); */
        t0 = x0_e ^ rightRotate4(x0_o);
        t1 = x0_o ^ rightRotate5(x0_e);
        x0_e ^= rightRotate9(t1);
        x0_o ^= rightRotate10(t0);
        /* x1 ^= rightRotate61_64(x1) ^ rightRotate39_64(x1); */
        t0 = x1_e ^ rightRotate11(x1_e);
        t1 = x1_o ^ rightRotate11(x1_o);
        x1_e ^= rightRotate19(t1);
        x1_o ^= rightRotate20(t0);
        /* x2 ^= rightRotate1_64(x2)  ^ rightRotate6_64(x2); */
        t0 = x2_e ^ rightRotate2(x2_o);
        t1 = x2_o ^ rightRotate3(x2_e);
        x2_e ^= t1;
        x2_o ^= rightRotate1(t0);
        /* x3 ^= rightRotate10_64(x3) ^ rightRotate17_64(x3); */
        t0 = x3_e ^ rightRotate3(x3_o);
        t1 = x3_o ^ rightRotate4(x3_e);
        x3_e ^= rightRotate5(t0);
        x3_o ^= rightRotate5(t1);
        /* x4 ^= rightRotate7_64(x4)  ^ rightRotate41_64(x4); */
        t0 = x4_e ^ rightRotate17(x4_e);
        t1 = x4_o ^ rightRotate17(x4_o);
        x4_e ^= rightRotate3(t1);
        x4_o ^= rightRotate4(t0);

        /* Move onto the next round */
        ++first_round;
    }

    /* Apply the final NOT to x2 */
    x2_e = ~x2_e;
    x2_o = ~x2_o;

    /* Write the local variables back to the state */
    state->W[0] = x0_e;
    state->W[1] = x0_o;
    state->W[2] = x1_e;
    state->W[3] = x1_o;
    state->W[4] = x2_e;
    state->W[5] = x2_o;
    state->W[6] = x3_e;
    state->W[7] = x3_o;
    state->W[8] = x4_e;
    state->W[9] = x4_o;
}

int8_t ascon128_aead_encrypt (
    unsigned char *c, uint8_t *clen,
    const unsigned char *m, uint8_t mlen,
    const unsigned char *ad, uint8_t adlen,
    const unsigned char *npub,
    const unsigned char *k )
{
    ascon_state_t state;
    unsigned char partial;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ASCON128_TAG_SIZE;

    /* Check if ciphertext + associated data length can be send by RFM69 */
    if (*clen + adlen > RFM69_MAX_PAYLOAD_SIZE || adlen > MAX_AD_SIZE)
    {
        return -1;
    }

    /* Initialize the ASCON state */
    ascon_init(&state);
    ascon_overwrite_bytes(&state, ASCON128_IV, 0, 8);
    ascon_overwrite_bytes(&state, k, 8, ASCON128_KEY_SIZE);
    ascon_overwrite_bytes(&state, npub, 24, ASCON128_NONCE_SIZE);
    ascon_permute(&state, 0);
    ascon_absorb_16(&state, k, 24);

    /* Absorb the associated data into the state */
    if (adlen > 0)
    {
        ascon_aead_absorb_8(&state, ad, adlen, 6, 1);
    }

    /* Separator between the associated data and the payload */
    ascon_separator(&state);

    /* Encrypt the plaintext to create the ciphertext */
    partial = ascon_aead_encrypt_8(&state, c, m, mlen, 6, 0);
    ascon_pad(&state, partial);


    /* Finalize and compute the authentication tag */
    ascon_absorb_16(&state, k, 8);
    ascon_permute(&state, 0);
    ascon_absorb_16(&state, k, 24);
    ascon_squeeze_partial(&state, c + mlen, 24, ASCON128_TAG_SIZE);
    ascon_free(&state);

    return 0;
}

int8_t ascon128_aead_decrypt (
    unsigned char *m, uint8_t *mlen,
    const unsigned char *c, uint8_t clen,
    const unsigned char *ad, uint8_t adlen,
    const unsigned char *npub,
    const unsigned char *k )
{
    ascon_state_t state;
    unsigned char tag[ASCON128_TAG_SIZE];
    unsigned char partial;
    int result;

    /* Set the length of the returned plaintext */
    if (clen < ASCON128_TAG_SIZE)
        return -1;
    *mlen = clen - ASCON128_TAG_SIZE;

    /* Initialize the ASCON state */
    ascon_init(&state);
    ascon_overwrite_bytes(&state, ASCON128_IV, 0, 8);
    ascon_overwrite_bytes(&state, k, 8, ASCON128_KEY_SIZE);
    ascon_overwrite_bytes(&state, npub, 24, ASCON128_NONCE_SIZE);
    ascon_permute(&state, 0);
    ascon_absorb_16(&state, k, 24);

    /* Absorb the associated data into the state */
    if (adlen > 0)
    {
        ascon_aead_absorb_8(&state, ad, adlen, 6, 1);
    }

    /* Separator between the associated data and the payload */
    ascon_separator(&state);

    /* Decrypt the ciphertext to create the plaintext */
    partial = ascon_aead_decrypt_8(&state, m, c, *mlen, 6, 0);
    ascon_pad(&state, partial);

    /* Finalize and check the authentication tag */
    ascon_absorb_16(&state, k, 8);
    ascon_permute(&state, 0);
    ascon_absorb_16(&state, k, 24);
    ascon_squeeze_16(&state, tag, 24);
    result = ascon_aead_check_tag(m, *mlen, tag, c + *mlen, ASCON128_TAG_SIZE);
    ascon_clean(tag, sizeof(tag));
    ascon_free(&state);

    return (uint8_t)result;
}

void ascon_aead_absorb_8 (
    ascon_state_t *state,
    const unsigned char *data,
    size_t len,
    uint8_t first_round,
    int last_permute )
{
    while (len >= 8) {
        ascon_absorb_8(state, data, 0);
        ascon_permute(state, first_round);
        data += 8;
        len -= 8;
    }
    if (len > 0)
        ascon_absorb_partial(state, data, 0, len);
    ascon_pad(state, len);
    if (last_permute)
        ascon_permute(state, first_round);
}

unsigned char ascon_aead_encrypt_8 (
    ascon_state_t *state,
    unsigned char *dest,
    const unsigned char *src,
    size_t len,
    uint8_t first_round,
    unsigned char partial )
{
    /* Deal with a partial left-over block from last time */
    if (partial != 0) {
        size_t temp = 8U - partial;
        if (temp > len) {
            ascon_encrypt_partial(state, dest, src, partial, len);
            return (unsigned char)(partial + len);
        }
        ascon_encrypt_partial(state, dest, src, partial, temp);
        ascon_permute(state, first_round);
        dest += temp;
        src += temp;
        len -= temp;
    }

    /* Deal with full rate blocks */
    while (len >= 8) {
        ascon_encrypt_8(state, dest, src, 0);
        ascon_permute(state, first_round);
        dest += 8;
        src += 8;
        len -= 8;
    }

    /* Deal with the partial left-over block on the end */
    if (len > 0)
        ascon_encrypt_partial(state, dest, src, 0, len);
    return (unsigned char)len;
}

unsigned char ascon_aead_decrypt_8 (
    ascon_state_t *state,
    unsigned char *dest,
    const unsigned char *src,
    size_t len,
    uint8_t first_round,
    unsigned char partial )
{
    /* Deal with a partial left-over block from last time */
    if (partial != 0) {
        size_t temp = 8U - partial;
        if (temp > len) {
            ascon_decrypt_partial(state, dest, src, partial, len);
            return (unsigned char)(partial + len);
        }
        ascon_decrypt_partial(state, dest, src, partial, temp);
        ascon_permute(state, first_round);
        dest += temp;
        src += temp;
        len -= temp;
    }

    /* Deal with full rate blocks */
    while (len >= 8) {
        ascon_decrypt_8(state, dest, src, 0);
        ascon_permute(state, first_round);
        dest += 8;
        src += 8;
        len -= 8;
    }

    /* Deal with the partial left-over block on the end */
    if (len > 0)
        ascon_decrypt_partial(state, dest, src, 0, len);
    return (unsigned char)len;
}

void ascon_add_bytes (
    ascon_state_t *state,
    const uint8_t *data,
    unsigned offset,
    unsigned size )
{
    uint64_t value;
    unsigned posn, shift, ofs, len;
    ofs = offset & 7U;
    if (ofs != 0U) {
        shift = (7U - ofs) * 8U;
        len = 8U - ofs;
        value = 0;
        for (posn = 0; posn < len && posn < size; ++posn, shift -= 8U) {
            value |= ((uint64_t)(data[posn])) << shift;
        }
        ascon_absorb_word64(state, value, offset / 8U);
        data += posn;
        offset += posn;
        size -= posn;
    }
    while (size >= 8U) {
        ascon_absorb_sliced(state, data, offset / 8U);
        data += 8;
        offset += 8;
        size -= 8;
    }
    if (size > 0U) {
        shift = 56U;
        value = 0;
        for (posn = 0; posn < size; ++posn, shift -= 8U) {
            value |= ((uint64_t)(data[posn])) << shift;
        }
        ascon_absorb_word64(state, value, offset / 8U);
    }
}

void ascon_extract_bytes (
    const ascon_state_t *state,
    uint8_t *data,
    unsigned offset,
    unsigned size )
{
    uint64_t value;
    unsigned posn, shift, ofs, len;
    ofs = offset & 7U;
    if (ofs != 0U) {
        ascon_squeeze_word64(state, value, offset / 8U);
        shift = (7U - ofs) * 8U;
        len = 8U - ofs;
        for (posn = 0; posn < len && posn < size; ++posn, shift -= 8U) {
            data[posn] = (uint8_t)(value >> shift);
        }
        data += posn;
        offset += posn;
        size -= posn;
    }
    while (size >= 8U) {
        ascon_squeeze_sliced(state, data, offset / 8U);
        data += 8;
        offset += 8;
        size -= 8;
    }
    if (size > 0U) {
        ascon_squeeze_word64(state, value, offset / 8U);
        shift = 56U;
        for (posn = 0; posn < size; ++posn, shift -= 8U) {
            data[posn] = (uint8_t)(value >> shift);
        }
    }
}

void ascon_extract_and_overwrite_bytes
    (ascon_state_t *state, const uint8_t *input, uint8_t *output,
    unsigned offset, unsigned size)
{
    uint64_t value;
    unsigned posn, shift, ofs, len;
    uint8_t in;
    ofs = offset & 7U;
    if (ofs != 0U) {
        ascon_squeeze_word64(state, value, offset / 8U);
        shift = (7U - ofs) * 8U;
        len = 8U - ofs;
        for (posn = 0; posn < len && posn < size; ++posn, shift -= 8U) {
            in = input[posn];
            output[posn] = in ^ (uint8_t)(value >> shift);
            value &= ~(((uint64_t)0xFFU) << shift);
            value |= ((uint64_t)in) << shift;
        }
        ascon_set_word64(state, value, offset / 8U);
        output += posn;
        input += posn;
        offset += posn;
        size -= posn;
    }
    while (size >= 8U) {
        ascon_decrypt_sliced(state, output, input, offset / 8U);
        output += 8;
        input += 8;
        offset += 8;
        size -= 8;
    }
    if (size > 0U) {
        ascon_squeeze_word64(state, value, offset / 8U);
        shift = 56U;
        for (posn = 0; posn < size; ++posn, shift -= 8U) {
            in = input[posn];
            output[posn] = in ^ (uint8_t)(value >> shift);
            value &= ~(((uint64_t)0xFFU) << shift);
            value |= ((uint64_t)in) << shift;
        }
        ascon_set_word64(state, value, offset / 8U);
    }
}

void ascon_clean(void *buf, unsigned size)
{
    /* The safest way to do this is using SecureZeroMemory(), memset_s(), or
    * explicit_bzero() so that the compiler will not optimise away the
    * call to memset() by accident.  If that doesn't work, then we fall
    * back to using volatile pointers which usually works to trick the
    * compiler, but may not. */
#if defined(_WIN32) || defined(_WIN64)
    SecureZeroMemory(buf, size);
#elif defined(__STDC_LIB_EXT1__) || defined(HAVE_MEMSET_S)
    memset_s(buf, (rsize_t)size, 0, (rsize_t)size);
#elif defined(HAVE_EXPLICIT_BZERO)
    explicit_bzero(buf, size);
#else
    volatile unsigned char *d = (volatile unsigned char *)buf;
    while (size > 0) {
        *d++ = 0;
        --size;
    }
#endif
}

void ascon_free(ascon_state_t *state)
{
    if (state) {
        //ascon_backend_free(state);
        ascon_clean(state, sizeof(ascon_state_t));
    }
}

int ascon_aead_check_tag (
    unsigned char *plaintext,
    size_t plaintext_len,
    const unsigned char *tag1,
    const unsigned char *tag2,
    size_t size )
{
    /* Set "accum" to -1 if the tags match, or 0 if they don't match */
    int accum = 0;
    while (size > 0) {
        accum |= (*tag1++ ^ *tag2++);
        --size;
    }
    accum = (accum - 1) >> 8;

    /* Destroy the plaintext if the tag match failed */
    while (plaintext_len > 0) {
        *plaintext++ &= accum;
        --plaintext_len;
    }

    /* If "accum" is 0, return -1, otherwise return 0 */
    return ~accum;
}

void ascon_hash_init(ascon_hash_state_t *state)
{
    /* IV for ASCON-HASH after processing it with the permutation */
#if defined(ASCON_BACKEND_SLICED64)
    static uint64_t const iv[5] = {
        0xee9398aadb67f03dULL, 0x8bb21831c60f1002ULL,
        0xb48a92db98d5da62ULL, 0x43189921b8f8e3e8ULL,
        0x348fa5c9d525e140ULL
    };
    memcpy(state->xof.state.S, iv, sizeof(iv));
#elif defined(ASCON_BACKEND_SLICED32)
    static uint32_t const iv[10] = {
        0xa540dbc7, 0xf9afb5c6, 0x1445a340, 0xbd249301,
        0x604d4fc8, 0xcb9ba8b5, 0x94514c98, 0x12a4eede,
        0x6339f398, 0x4bca84c0
    };
    memcpy(state->xof.state.W, iv, sizeof(iv));
#else
    static uint8_t const iv[40] = {
        0xee, 0x93, 0x98, 0xaa, 0xdb, 0x67, 0xf0, 0x3d,
        0x8b, 0xb2, 0x18, 0x31, 0xc6, 0x0f, 0x10, 0x02,
        0xb4, 0x8a, 0x92, 0xdb, 0x98, 0xd5, 0xda, 0x62,
        0x43, 0x18, 0x99, 0x21, 0xb8, 0xf8, 0xe3, 0xe8,
        0x34, 0x8f, 0xa5, 0xc9, 0xd5, 0x25, 0xe1, 0x40
    };
#if defined(ASCON_BACKEND_DIRECT_XOR)
    memcpy(state->xof.state.B, iv, sizeof(iv));
#else
    ascon_init(&(state->xof.state));
    ascon_overwrite_bytes(&(state->xof.state), iv, 0, sizeof(iv));
    //ascon_release(&(state->xof.state));
#endif
#endif
    state->xof.count = 0;
    state->xof.mode = 0;
}

void ascon_xof_squeeze (
    ascon_xof_state_t *state,
    unsigned char *out,
    size_t outlen )
{
    unsigned temp;

    /* Acquire access to shared hardware if necessary */
    //ascon_acquire(&(state->state));

    /* Pad the final input block if we were still in the absorb phase */
    if (!state->mode) {
        ascon_pad(&(state->state), state->count);
        state->count = 0;
        state->mode = 1;
    }

    /* Handle left-over partial blocks from last time */
    if (state->count) {
        temp = ASCON_XOF_RATE - state->count;
        if (temp > outlen) {
            temp = (unsigned)outlen;
            ascon_squeeze_partial(&(state->state), out, state->count, temp);
            state->count += temp;
            //ascon_release(&(state->state));
            return;
        }
        ascon_squeeze_partial(&(state->state), out, state->count, temp);
        out += temp;
        outlen -= temp;
        state->count = 0;
    }

    /* Handle full blocks */
    while (outlen >= ASCON_XOF_RATE) {
        ascon_permute(&(state->state), 0);
        ascon_squeeze_8(&(state->state), out, 0);
        out += ASCON_XOF_RATE;
        outlen -= ASCON_XOF_RATE;
    }

    /* Handle the left-over block */
    if (outlen > 0) {
        temp = (unsigned)outlen;
        ascon_permute(&(state->state), 0);
        ascon_squeeze_partial(&(state->state), out, 0, temp);
        state->count = temp;
    }

    /* Release access to the shared hardware */
    //ascon_release(&(state->state));
}

void ascon_xof_absorb (
    ascon_xof_state_t *state,
    const unsigned char *in,
    size_t inlen )
{
    unsigned temp;

    /* Acquire access to shared hardware if necessary */
    //(&(state->state));

    /* If we were squeezing output, then go back to the absorb phase */
    if (state->mode) {
        state->mode = 0;
        state->count = 0;
        ascon_permute(&(state->state), 0);
    }

    /* Handle the partial left-over block from last time */
    if (state->count) {
        temp = ASCON_XOF_RATE - state->count;
        if (temp > inlen) {
            temp = (unsigned)inlen;
            ascon_absorb_partial(&(state->state), in, state->count, temp);
            state->count += temp;
            //ascon_release(&(state->state));
            return;
        }
        ascon_absorb_partial(&(state->state), in, state->count, temp);
        state->count = 0;
        in += temp;
        inlen -= temp;
        ascon_permute(&(state->state), 0);
    }

    /* Process full blocks that are aligned at state->s.count == 0 */
    while (inlen >= ASCON_XOF_RATE) {
        ascon_absorb_8(&(state->state), in, 0);
        in += ASCON_XOF_RATE;
        inlen -= ASCON_XOF_RATE;
        ascon_permute(&(state->state), 0);
    }

    /* Process the left-over block at the end of the input */
    temp = (unsigned)inlen;
    if (temp > 0)
        ascon_absorb_partial(&(state->state), in, 0, temp);
    state->count = temp;

    /* Release access to the shared hardware */
    //ascon_release(&(state->state));
}

void ascon_xof_free(ascon_xof_state_t *state)
{
    if (state) {
        //ascon_acquire(&(state->state));
        ascon_free(&(state->state));
        state->count = 0;
        state->mode = 0;
    }
}

void ascon_hash(unsigned char *out, const unsigned char *in, size_t inlen)
{
    ascon_hash_state_t state;
    ascon_hash_init(&state);
    ascon_xof_absorb(&(state.xof), in, inlen);
    ascon_xof_squeeze(&(state.xof), out, ASCON_HASH_SIZE);
    ascon_xof_free(&(state.xof));
}


void ascon_overwrite_bytes (ascon_state_t *state, const uint8_t *data, unsigned offset, unsigned size)
{
    uint64_t value;
    unsigned posn, shift, ofs, len;
    ofs = offset & 7U;
    if (ofs != 0U) {
        ascon_squeeze_word64(state, value, offset / 8U);
        ofs = offset & 7U;
        shift = (7U - ofs) * 8U;
        len = 8U - ofs;
        for (posn = 0; posn < len && posn < size; ++posn, shift -= 8U) {
            value &= ~(((uint64_t)0xFFU) << shift);
            value |= ((uint64_t)(data[posn])) << shift;
        }
        ascon_set_word64(state, value, offset / 8U);
        data += posn;
        offset += posn;
        size -= posn;
    }
    while (size >= 8U) {
        ascon_set_sliced(state, data, offset / 8U);
        data += 8;
        offset += 8;
        size -= 8;
    }
    if (size > 0U) {
        ascon_squeeze_word64(state, value, offset / 8U);
        shift = 56U;
        for (posn = 0; posn < size; ++posn, shift -= 8U) {
            value &= ~(((uint64_t)0xFFU) << shift);
            value |= ((uint64_t)(data[posn])) << shift;
        }
        ascon_set_word64(state, value, offset / 8U);
    }
}

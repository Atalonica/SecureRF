
/*************************************************************************/
/***************** SecureRF RECEIVER node example sketch *****************/
/*************************************************************************/

/*
   Copyright (C) 2021 Atalonica

   Permission is hereby granted, free of charge, to any person obtaining a
   copy of this software and associated documentation files (the "Software"),
   to deal in the Software without restriction, including without limitation
   the rights to use, copy, modify, merge, publish, distribute, sublicense,f
   and/or sell copies of the Software, and to permit persons to whom the
   Software is furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included
   in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
   OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
   DEALINGS IN THE SOFTWARE.
*/


/* ************************** LIBRARIES ************************** */
#include <RFM69.h>      // http://github.com/lowpowerlab/rfm69
#include <RFM69_ATC.h>  // https://github.com/lowpowerlab/rfm69
#include <SPI.h>
#include <SPIFlash.h>  // https://github.com/LowPowerLab/SPIFlash
#include <SecureRF.h>  // https://github.com/Atalonica/SecureRF


/* **************** BUILT-IN BOARD CONFIGURATIONS **************** */
#define IS_HW_HCW  // (Comment if RFM69 module is not RFM69HW/RFM69HCW)
const uint16_t FLASH_ID = 0x1F44;

/* *************** SOFTWARE CONSTANTS CONFIGURATIONS *************** */
#define ENABLE_DEBUG  // (comment to disable serial monitor)
#define ENABLE_ATC
#define ATC_RSSI -80                  // Increase for far away nodes
const uint16_t NODE_ID = 200;         // (0-1023)
const uint16_t SENDER_NODE_ID = 100;  // (0-1023)
const uint8_t NETWORD_ID = 123;
const char MY_RFM69_AES_KEY[16] = {
  0x4d, 0x59, 0x20, 0x52, 0x46, 0x4d, 0x36, 0x39, 0x20, 0x41, 0x45, 0x53, 0x20, 0x4b, 0x45, 0x59
};
const unsigned char XDYK_AEAD_RF_KEY[16] = {
  0x58, 0x44, 0x59, 0x4b, 0x5f, 0x41, 0x45, 0x41, 0x44, 0x5f, 0x52, 0x46, 0x5f, 0x4b, 0x45, 0x59
};
const unsigned char XDYK_HASH_RF_KEY[16] = {
  0x58, 0x44, 0x59, 0x4b, 0x5f, 0x48, 0x41, 0x53, 0x48, 0x5f, 0x52, 0x46, 0x5f, 0x4b, 0x45, 0x59
};

/* ***************** GLOBAL VARIABLES & CONSTANTS ***************** */
uint8_t msgBuff[50] = "";
uint8_t adBuff[5] = "";
uint8_t randomBytes[16] = "";

#ifdef ENABLE_ATC
RFM69_ATC radio(INTERNAL_RFM69_SPI_CS, INTERNAL_RFM69_IRQ);
#else
RFM69 radio(INTERNAL_RFM69_SPI_CS, INTERNAL_RFM69_IRQ);
#endif

SPIFlash flash(SS_FLASHMEM, FLASH_ID);

SecureRF secure;

#ifdef ENABLE_DEBUG
#define Debug(x)    {Serial.print(x);}
#define Debugln(x)  {Serial.println(x);}
#define DebugHex(x) {if(x < 0x10){Serial.print("0");}Serial.print(x,HEX);}
#else
#define Debug(x)
#define Debugln(x)
#define DebugHex(x)
#endif

void setup() {

  pinMode(LED_BUILTIN, OUTPUT);
  pinMode(INTERNAL_FLASH_EN, OUTPUT);

#ifdef ENABLE_DEBUG
  while (!Serial);
  Debug("["); Debug(NODE_ID); Debugln("]: STARTED");
  delay(500);
#endif

  /* Built-in flash memory initialization & sleep */
  digitalWrite(INTERNAL_FLASH_EN, HIGH); delay(10);
  if (flash.initialize()) {
    flash.sleep();
    Debug("["); Debug(NODE_ID); Debugln("]: FLASH INIT OK");
    Debug("["); Debug(NODE_ID); Debugln("]: FLASH SLEEP");
  }
  else
  {
    Debug("["); Debug(NODE_ID); Debugln("]: FLASH INIT ERROR");
  }

  /* Built-in RFM69 module initialization & sleep */
  if (radio.initialize(RF69_868MHZ, NODE_ID, NETWORD_ID))
  {
    Debug("["); Debug(NODE_ID); Debugln("]: RFM69 INIT OK");
      radio.sleep();
#ifdef IS_HW_HCW
  radio.setHighPower();  //must include this only for RFM69HW/HCW!
#endif
  radio.encrypt(MY_RFM69_AES_KEY);
#ifdef ENABLE_ATC
  radio.enableAutoPower(ATC_RSSI);
#endif
  }
  else
  {
    Debug("["); Debug(NODE_ID); Debugln("]: RFM69 INIT ERROR");
  }

  /* SecureRF master key initialization */
  secure.setKeys(XDYK_AEAD_RF_KEY, XDYK_HASH_RF_KEY);

#if !defined(SAML21)
  /* Pseudo Random number initialization
   * Use only if no TRNG available!
   */
  randomSeed(analogRead(A0));  // (floating/unconnected pin)
#endif
}

void loop() {

  /* Wait for incoming messages... */
  if (radio.receiveDone()) {

    /* Check sender and target ID's are the expected */
    if ( radio.SENDERID == SENDER_NODE_ID && radio.TARGETID == NODE_ID ) {

      /* DEBUG... */
      Debug("["); Debug(NODE_ID); Debug("]: RECEIVED NEW DATA (SENDER:");
      Debug(SENDER_NODE_ID); Debug(") -> ("); Debug(radio.DATALEN); Debug("){")
      for (uint8_t i = 0; i < radio.DATALEN; i++) {
        DebugHex(radio.DATA[i]);
        if (i < radio.DATALEN - 1) Debug(":");
      }
      Debugln(" }");

      /* Check if message is a nonce request (first check) */
      if( radio.DATALEN == 12 && memcmp(radio.DATA, "NREQ", 4) == 0 )
      {
        /* It is probably a nonce request,
         * generate 16-byte random nonce
         */
        tRandomBytes(randomBytes, 16);

        if( secure.onNonceRequest(radio.DATA, randomBytes, msgBuff) )
        {
          /* It really is a nonce request.
           * Send ACK with nonce (as soon as possible)
           */
          if( radio.ACKRequested() )
          {
            radio.sendACK(msgBuff, 20); // (4+16 bytes)

            /* DEBUG... */
            Debug("["); Debug(NODE_ID); Debugln("]: VALID NONCE REQUEST RECEIVED");
            Debug("["); Debug(NODE_ID); Debug("]: SENDING NEW NONCE -> (20){ ");
            for (uint8_t i = 0; i < 20; i++) {
              DebugHex(msgBuff[i]);
              if (i < 20 - 1) Debug(":");
            }
            Debugln(" }");
          }
        }
      }

      /* Try to decrypt authenticate and validate message (if it is expected) */
      else if (secure.waitingSecureMessage() && radio.DATALEN >= 17) {

        if( secure.onSecureMessage(radio.DATA) ) {

          /* Send ACK if successfully decrypted */
          if (radio.ACKRequested()) {
            radio.sendACK();

            Debug("["); Debug(NODE_ID); Debugln("]: RECEIVED VALID AEAD DATA:");
            Debug("          -> ASSOCIATED ("); Debug(secure.ASSOCIATED_LEN); Debug("): ");
            for (uint8_t i = 0; i < secure.ASSOCIATED_LEN; i++) {
              Debug((char)secure.ASSOCIATED[i]);
            }
            Debugln();
            Debug("          -> MESSAGE ("); Debug(secure.PLAINTEXT_LEN); Debug("): ");
            for (uint8_t i = 0; i < secure.PLAINTEXT_LEN; i++) {
              Debug((char)secure.PLAINTEXT[i]);
            }
            Debugln();

            /* Do something with received data...
             * For example turn ON/OFF the built-in LED
             * based on the message and associated data.
            */
            if (memcmp(secure.PLAINTEXT, "Change LED state", secure.PLAINTEXT_LEN) == 0) {
              if (secure.ASSOCIATED_LEN == 2) {
                if (secure.ASSOCIATED[0] == 'O' && secure.ASSOCIATED[1] == 'N')
                  digitalWrite(LED_BUILTIN, HIGH);
                else if (secure.ASSOCIATED[0] == 'O' && secure.ASSOCIATED[1] == 'F')
                  digitalWrite(LED_BUILTIN, LOW);
              }
            }
          }
        } else {
          /* DEBUG... */
          Debug("["); Debug(NODE_ID); Debugln("]: AEAD DATA ERROR !");
        }
      }

      /* Handle other unencrypted, unauthenticated messages */
      //  else if (...) {
      //    (...)
      //  }
    }
  }

  /* Do other things not related to RF reception... */

}

#if !defined(SAML21)
/*
 * Custom implementation of tRandomBytes()
 * Only use it if MCU doesn't support TRNG
 * This will output PSEUDO random numbers!
*/
void tRandomBytes(uint8_t *r, uint8_t n) {
  for (uint8_t i = 0; i < n; i++) {
    r[i] = (uint8_t)random(256);
  }
}
#endif

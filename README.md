# SecureRF Library

By Atalonica
<br/>
SecureRF library intended to be used together with LowPowerLab's RFM69 Arduino library.
<br/>
The latest examples, new features and bug fixes are found in the [original repository](https://github.com/Atalonica/SecureRF) of this library.

## License
MIT. See [LICENCE](https://github.com/Atalonica/SecureRF/blob/main/LICENSE) file (license and copyright notice shall be included in copies or portions of code).

## Features
- Authentication Encryption with Associated Data lightweight protocol (ASCON128)
- Ephemeral nonce exchange for replay prevention
- Exponential halt timer for nonce attack prevention
- 41-44 bytes max message length
- 3-1 bytes of associated data
- (All is hardware AES-128 encrypted/decrypted by RFM69)

### Library Installation (Arduino IDE)
Go to you Arduino IDE then click on `Sketch > Include Library > Add .ZIP Library...` and select the latest .zip file found in releases.

If it doesn't work:<br />
Copy the contents of this library in a new folder called "SecureRF" located in "Arduino/libraries/".
<br />
To find your Arduino folder go to `File > Preferences` in the Arduino IDE.
<br/>
See [this tutorial](https://www.arduino.cc/en/Guide/Libraries) on Arduino libraries.

### Hardware & programming
This library should work with most RFM69 based boards, however not all of them have good enough random generation sources (see Warnings below).

### Warnings
- Providing weak or not true random nonces can strongly reduce or break the AEAD scheme, thus it is encouraged to use a compliant hardware-based TRNG (or a decrement/increment-only hardware counter). Nonce misuse (not fulfilling those requirements) is part of the user.
- All PSK keys saved in flash can be obtained easily. If unallowed tampering is a risk, don't use this library (use a pre-programmed crypto IC).

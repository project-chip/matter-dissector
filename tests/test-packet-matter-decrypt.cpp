/*
 *  Copyright (c) 2021-2023 Project CHIP Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdint.h>
#include <assert.h>

#include <openssl/bn.h>

#include "../packet-matter-decrypt.h"


#define MATTER_MAX_MESSAGE_SIZE     1280

const char *sTestKeys[] = {
    // SecureSession::InitFromSecret(Secret = "Test secret for key derivation", size=30, Salt = null)
    "44d43c91d227f3ba0824c5d87cb81b33", // Initiator-to-Responder Test key 
    "acc18f06c7bc9be8246a678cb1f8ba3d"  // Responder-to-Initiator Test key
};

/**
 * These input test vectors use the test secret I2R key above, and have
 * fixed headers with full source and destination node ids.
 */
const char *sTestVectorIns[] = {
    // Echo Request 
    // Source Node Id: 0x000000000001B669
    // Destination Node Id: 0x0000000000BC5C01
    // Session Id: 0000
    //      Generated via capture of `./out/debug/linux_x64_clang/chip-echo-requester 127.0.0.1`
    //      IV[12]: 69b601000000000001000000
    //      AAD[24]: 25110100000069b6010000000000015cbc00000000000000
    "25110100000069b6010000000000015cbc00000000000000"  // header
    "69c1148a4c853d439cc9492ab3a5364ecf41780712"        // encrypted payload
    "e287304edcf8cff0e368039dba2e1fe8",                 // tag

    // Echo Response 
    // Source Node Id: 0x0000000000BC5C01
    // Destination Node Id: 0x000000000001B669
    // Session Id: 0000
    //      Generated via capture of `./out/debug/linux_x64_clang/chip-echo-responder`
    "251104000000015cbc000000000069b60100000000000000"  // header
    "4251a252588cb14c8717"                              // encrypted payload
    "9514abf95c11ecf2f229cb6e3a6c3ca2"                  // tag
};

const char *sTestVectorOuts[] = {
    // Echo Request decrypted
    //      Generated via brk at "SecureSession::Encode" of
    //      `gdb --args ./out/debug/linux_x64_clang/chip-echo-requester 127.0.0.1`
    "25110100000069b6010000000000015c"
    "bc00000000000000"
    "0501699801004563686f204d65737361676520300a"
};

int sTestVectorInsSize = (sizeof(sTestVectorIns) / sizeof(const char *));

/**
 * Converts the given hex string to a binary byte array.
 */
int Hex2Bin(const char *aHex, uint8_t *aBin, uint16_t aBinLength)
{
    BIGNUM *input = BN_new();
    int resultLength;
    int inputLength = BN_hex2bn(&input, aHex);
    inputLength = (inputLength + 1) / 2; // BN_hex2bn() returns number of hex digits

    assert(aBinLength >= inputLength);
    resultLength = BN_bn2bin(input, aBin);

    assert(resultLength == inputLength);
    return resultLength;
}

int TryDecryptVector(uint8_t *aMessage, uint16_t aMessageLength)
{
    bool verified;

    const uint8_t *encData;
    uint8_t *unencData;
    uint32_t encDataLen;
    const uint8_t *aad;
    uint32_t aadLen;
    packet_info *pinfo;
    MatterMessageInfo msgInfo;
    MessageEncryptionKey key;

    verified = TryDecryptMessage_AES128CCM(encData, unencData, encDataLen, aad, aadLen, pinfo, msgInfo, key);

    return 0;
}

int DecryptVector(uint8_t *aMessage, uint16_t aMessageLength)
{
    MATTER_ERROR err;
    const uint8_t * ciphertext;
    size_t ciphertextLength;
    const uint8_t * aad;
    size_t aadLength;
    const uint8_t * tag;
    size_t tagLength;
    const uint8_t * key;
    size_t keyLength;
    const uint8_t * iv;
    size_t ivLength;
    uint8_t * plaintext;

    err = AES_CCM_decrypt(ciphertext, ciphertextLength, aad, aadLength, tag, tagLength, 
                          key, keyLength, iv, ivLength, plaintext);

    return err;
}

int main() {
    MATTER_ERROR err;
    MATTER_ERROR errAny = MATTER_NO_ERROR;

    uint8_t message[MATTER_MAX_MESSAGE_SIZE];
    uint16_t messageLength;

    for (int i=0; i < sTestVectorInsSize; i++) {
        printf("Testing decrypt[%d]: ", i);

        messageLength = Hex2Bin(sTestVectorIns[i], message, sizeof(message));
        err = DecryptVector(message, messageLength);

        if (err) {
            printf("FAIL: %d\n",err);
            errAny = err;
        } else {
            printf("PASS\n");
        }
    }
    return errAny;
}

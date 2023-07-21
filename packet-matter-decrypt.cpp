/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include "packet-matter-decrypt.h"

#include <openssl/opensslv.h>
#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <openssl/modes.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

using namespace matter;

#define MATTER_MSG_NONCE_LENGTH     13

#if OPENSSL_VERSION_NUMBER > 0x10100000L

static bool _isValidTagLength(size_t tag_length)
{
    return tag_length == 16;
}

static bool _isValidKeyLength(size_t length)
{
    // 16 bytes key for AES-CCM-128, 32 for AES-CCM-256
    return length == 16 || length == 32;
}

MATTER_ERROR AES_CCM_decrypt(const uint8_t * ciphertext, size_t ciphertext_length, const uint8_t * aad, size_t aad_length,
                             const uint8_t * tag, size_t tag_length, const uint8_t * key, size_t key_length, const uint8_t * iv,
                             size_t iv_length, uint8_t * plaintext)
{
    EVP_CIPHER_CTX * context = nullptr;
    int error         = MATTER_NO_ERROR;
    int bytesOutput          = 0;
    int result               = 1;
    const EVP_CIPHER * type  = nullptr;

    VerifyOrExit(ciphertext != nullptr, error = MATTER_ERROR_INVALID_ARGUMENT);
    VerifyOrExit(ciphertext_length > 0, error = MATTER_ERROR_INVALID_ARGUMENT);
    VerifyOrExit(tag != nullptr, error = MATTER_ERROR_INVALID_ARGUMENT);
    VerifyOrExit(_isValidTagLength(tag_length), error = MATTER_ERROR_INVALID_ARGUMENT);
    VerifyOrExit(key != nullptr, error = MATTER_ERROR_INVALID_ARGUMENT);
    VerifyOrExit(_isValidKeyLength(key_length), error = MATTER_ERROR_INVALID_ARGUMENT);
    VerifyOrExit(iv != nullptr, error = MATTER_ERROR_INVALID_ARGUMENT);
    VerifyOrExit(iv_length > 0, error = MATTER_ERROR_INVALID_ARGUMENT);

    // 16 bytes key for AES-CCM-128
    type = (key_length == 16) ? EVP_aes_128_ccm() : EVP_aes_256_ccm();

    context = EVP_CIPHER_CTX_new();
    VerifyOrExit(context != nullptr, error = MATTER_ERROR_INTERNAL);

    // Pass in cipher
    result = EVP_DecryptInit_ex(context, type, nullptr, nullptr, nullptr);
    VerifyOrExit(result == 1, error = MATTER_ERROR_INTERNAL);

    // Pass in IV length
    VerifyOrExit(CanCastTo<int>(iv_length), error = MATTER_ERROR_INVALID_ARGUMENT);
    result = EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_CCM_SET_IVLEN, static_cast<int>(iv_length), nullptr);
    VerifyOrExit(result == 1, error = MATTER_ERROR_INTERNAL);

    // Pass in expected tag
    // Removing "const" from |tag| here should hopefully be safe as
    // we're writing the tag, not reading.
    VerifyOrExit(CanCastTo<int>(tag_length), error = MATTER_ERROR_INVALID_ARGUMENT);
    result = EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_CCM_SET_TAG, static_cast<int>(tag_length),
                                 const_cast<void *>(static_cast<const void *>(tag)));
    VerifyOrExit(result == 1, error = MATTER_ERROR_INTERNAL);

    // Pass in key + iv
    result = EVP_DecryptInit_ex(context, nullptr, nullptr, reinterpret_cast<const unsigned char *>(key), reinterpret_cast<const unsigned char *>(iv));
    VerifyOrExit(result == 1, error = MATTER_ERROR_INTERNAL);

    // Pass in cipher text length
    VerifyOrExit(CanCastTo<int>(ciphertext_length), error = MATTER_ERROR_INVALID_ARGUMENT);
    result = EVP_DecryptUpdate(context, nullptr, &bytesOutput, nullptr, static_cast<int>(ciphertext_length));
    VerifyOrExit(result == 1, error = MATTER_ERROR_INTERNAL);

    // Pass in aad
    if (aad_length > 0 && aad != nullptr)
    {
        VerifyOrExit(CanCastTo<int>(aad_length), error = MATTER_ERROR_INVALID_ARGUMENT);
        result = EVP_DecryptUpdate(context, nullptr, &bytesOutput,  reinterpret_cast<const unsigned char *>(aad), static_cast<int>(aad_length));
        VerifyOrExit(result == 1, error = MATTER_ERROR_INTERNAL);
    }

    // Pass in ciphertext. We wont get anything if validation fails.
    VerifyOrExit(CanCastTo<int>(ciphertext_length), error = MATTER_ERROR_INVALID_ARGUMENT);
    result = EVP_DecryptUpdate(context, reinterpret_cast<unsigned char *>(plaintext), &bytesOutput,  reinterpret_cast<const unsigned char *>(ciphertext),
                               static_cast<int>(ciphertext_length));
    VerifyOrExit(result == 1, error = MATTER_ERROR_INTERNAL);

exit:
    if (context != nullptr)
    {
        EVP_CIPHER_CTX_free(context);
        context = nullptr;
    }

    return error;
}


#endif

#if 0

MATTER_ERROR GetIV(const PacketHeader & header, uint8_t * iv, size_t len)
{

    VerifyOrReturnError(len == kAESCCMIVLen, MATTER_ERROR_INVALID_ARGUMENT);

    Encoding::LittleEndian::BufferWriter bbuf(iv, len);

    bbuf.Put64(header.GetSourceNodeId().ValueOr(0));
    bbuf.Put32(header.GetMessageId());

    return bbuf.Fit() ? MATTER_NO_ERROR : MATTER_ERROR_NO_MEMORY;
}

MATTER_ERROR GetAdditionalAuthData(const PacketHeader & header, uint8_t * aad, uint16_t & len)
{
    VerifyOrReturnError(len >= header.EncodeSizeBytes(), MATTER_ERROR_INVALID_ARGUMENT);

    // Use unencrypted part of header as AAD. This will help
    // integrity protect the whole message
    uint16_t actualEncodedHeaderSize;

    ReturnErrorOnFailure(header.Encode(aad, len, &actualEncodedHeaderSize));
    VerifyOrReturnError(len >= actualEncodedHeaderSize, MATTER_ERROR_INVALID_ARGUMENT);

    len = actualEncodedHeaderSize;

    return MATTER_NO_ERROR;
}


MATTER_ERROR DecryptMatterMessage(const uint8_t * input, size_t inputLength, uint8_t * output, const uint8_t *aKey, const PacketHeader & header,
                                  const MessageAuthenticationCode & mac) const
{
    const size_t keyLength = AES_BLOCK_SIZE;
    const size_t tagLength = AES_BLOCK_SIZE;
    const size_t ivLength = MATTER_MSG_NONCE_LENGTH;
    const uint8_t * tag = mac.GetTag();
    uint8_t IV[ivLength];
    uint8_t AAD[kMaxAADLen];
    uint16_t aadLen = sizeof(AAD);

    VerifyOrReturnError(mKeyAvailable, MATTER_ERROR_INVALID_USE_OF_SESSION_KEY);
    VerifyOrReturnError(input != nullptr, MATTER_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(input_length > 0, MATTER_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(output != nullptr, MATTER_ERROR_INVALID_ARGUMENT);

    ReturnErrorOnFailure(GetIV(header, IV, sizeof(IV)));
    ReturnErrorOnFailure(GetAdditionalAuthData(header, AAD, aadLen));

    return AES_CCM_decrypt(input, inputLength, AAD, aadLen, tag, tagLength, aKey, keyLength, IV, sizeof(IV),
                           output);
}

#endif // 0

bool
TryDecryptMessage_AES128CCM(const uint8_t *encData, uint8_t *unencData, uint32_t encDataLen, const uint8_t *aad, uint32_t aadLen,
        packet_info *pinfo, const MatterMessageInfo& msgInfo, const MessageEncryptionKey& key)
{
    size_t tagLength = AES_BLOCK_SIZE;
    size_t nonceLength = MATTER_MSG_NONCE_LENGTH;

    uint8_t nonce[nonceLength];

    if (key.dataEncKeyLen != kDataEncKeyLength_AES128CCM) {
        return false;
    }

    // Initialize the CTR-mode nonce
    memset(nonce, 0, sizeof(nonce));

    nonce[0]  = (uint8_t) (msgInfo.secFlags);
    nonce[1]  = (uint8_t) (msgInfo.msgId);
    nonce[2]  = (uint8_t) (msgInfo.msgId >> (1 * 8));
    nonce[3]  = (uint8_t) (msgInfo.msgId >> (2 * 8));
    nonce[4]  = (uint8_t) (msgInfo.msgId >> (3 * 8));
    nonce[5]  = (uint8_t) (msgInfo.srcNodeId);
    nonce[6]  = (uint8_t) (msgInfo.srcNodeId >> (1 * 8));
    nonce[7]  = (uint8_t) (msgInfo.srcNodeId >> (2 * 8));
    nonce[8]  = (uint8_t) (msgInfo.srcNodeId >> (3 * 8));
    nonce[9]  = (uint8_t) (msgInfo.srcNodeId >> (4 * 8));
    nonce[10] = (uint8_t) (msgInfo.srcNodeId >> (5 * 8));
    nonce[11] = (uint8_t) (msgInfo.srcNodeId >> (6 * 8));
    nonce[12] = (uint8_t) (msgInfo.srcNodeId >> (7 * 8));

    const uint8_t *tag = encData + encDataLen - tagLength;
    encDataLen -= tagLength;
 
    return (AES_CCM_decrypt(encData, (size_t)encDataLen, aad, aadLen, tag, tagLength, (const uint8_t *)key.dataEncKey, 
                            key.dataEncKeyLen, nonce, nonceLength, unencData) == MATTER_NO_ERROR);
}

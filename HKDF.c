/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdint.h>
#include <string.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>

int HKDF_extract(const EVP_MD *md, const uint8_t *salt, size_t saltLen, const uint8_t *inKey, size_t inKeyLen, uint8_t *prKeyBuf, size_t *prKeyLen)
{
    unsigned int outLen;

    if (HMAC(md, salt, saltLen, inKey, inKeyLen, prKeyBuf, &outLen) == NULL)
        return 0;

    *prKeyLen = (size_t)outLen;

    return 1;
}

int HKDF_expand(const EVP_MD *md, const uint8_t *prKey, size_t prKeyLen, const uint8_t *info, size_t infoLen, uint8_t *outKey, size_t outKeyLen)
{
    int res = 0;
    uint8_t hashNum = 1;
    size_t hashSize = EVP_MD_size(md);
    unsigned int finalLen;

#if OPENSSL_VERSION_NUMBER > 0x10100000L
    HMAC_CTX *hmac = HMAC_CTX_new();
#else
    HMAC_CTX hmacObj;
    HMAC_CTX *hmac = &hmacObj;
    HMAC_CTX_init(hmac);
#endif

    if (outKeyLen < 1 || outKeyLen > 255 * hashSize)
        goto exit;

    while (1) {

        if (!HMAC_Init_ex(hmac, prKey, prKeyLen, md, NULL))
            return 0;

        if (hashNum > 1) {
            if (!HMAC_Update(hmac, outKey - hashSize, hashSize))
                goto exit;
        }

        if (info != NULL && infoLen > 0) {
            if (!HMAC_Update(hmac, info, infoLen))
                goto exit;
        }

        if (!HMAC_Update(hmac, &hashNum, 1))
            goto exit;

        if (outKeyLen < hashSize)
        {
            uint8_t finalHash[EVP_MAX_MD_SIZE];

            if (!HMAC_Final(hmac, finalHash, &finalLen))
                goto exit;

            memcpy(outKey, finalHash, outKeyLen);

            break;
        }

        if (!HMAC_Final(hmac, outKey, &finalLen))
            goto exit;

        outKey += hashSize;
        outKeyLen -= hashSize;
        hashNum++;
    }

    res = 1;

exit:
#if OPENSSL_VERSION_NUMBER > 0x10100000L
    HMAC_CTX_free(hmac);
#else
    HMAC_CTX_cleanup(hmac);
#endif
    return res;
}

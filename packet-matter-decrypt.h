/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __PACKET_MATTER_DECRYPT_H__
#define __PACKET_MATTER_DECRYPT_H__

#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
//#include <epan/wmem/wmem.h>

#include <Matter/Core/MatterCore.h>
#include <Matter/Support/CodeUtils.h>
#include <Matter/Support/SafeInt.h>

#include "MessageEncryptionKey.h"

#include "packet-matter.h"

#define MATTER_CRYPTO_TAG_LENGTH    16

MATTER_ERROR AES_CCM_decrypt(const uint8_t * ciphertext, size_t ciphertext_length, const uint8_t * aad, size_t aad_length,
                             const uint8_t * tag, size_t tag_length, const uint8_t * key, size_t key_length, const uint8_t * iv,
                             size_t iv_length, uint8_t * plaintext);

bool
TryDecryptMessage_AES128CCM(const uint8_t *encData, uint8_t *unencData, uint32_t encDataLen, const uint8_t *aad, uint32_t aadLen,
        packet_info *pinfo, const MatterMessageInfo& msgInfo, const MessageEncryptionKey& key);

#endif // __PACKET_MATTER_DECRYPT_H__

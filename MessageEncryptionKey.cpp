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

#include <glib.h>
#include "config.h"

#include <epan/packet.h>

#include "packet-matter.h"
#include "MessageEncryptionKey.h"


wmem_tree_t *MessageEncryptionKeyTable::sKeys = NULL;

void MessageEncryptionKeyTable::Init()
{
    sKeys = wmem_tree_new(wmem_epan_scope());
}

const MessageEncryptionKey* MessageEncryptionKeyTable::FindKeysById(uint16_t keyId)
{
    return (const MessageEncryptionKey *)wmem_tree_lookup32(sKeys, keyId);
}

const MessageEncryptionKey *MessageEncryptionKeyTable::AddKey(const MessageEncryptionKey& keyData)
{
    MessageEncryptionKey *existingKeys = (MessageEncryptionKey *)wmem_tree_lookup32(sKeys, keyData.keyId);

    for (MessageEncryptionKey *key = existingKeys; key != NULL; key = key->nextKey) {
        if (key->IsSameKey(keyData))
            return key;
    }

    MessageEncryptionKey *newKey = wmem_new(wmem_epan_scope(), MessageEncryptionKey);
    memset(newKey, 0, sizeof(*newKey));
    newKey->keyId = keyData.keyId;
    newKey->sessionType = keyData.sessionType;
    newKey->dataEncKey = (char *)wmem_alloc(wmem_epan_scope(), keyData.dataEncKeyLen);
    memcpy(newKey->dataEncKey, keyData.dataEncKey, keyData.dataEncKeyLen);
    newKey->dataEncKeyLen = keyData.dataEncKeyLen;
    newKey->nextKey = existingKeys;

    wmem_tree_insert32(sKeys, newKey->keyId, newKey);

    return newKey;
}

bool MessageEncryptionKey::IsSameKey(const MessageEncryptionKey& otherKey) const
{
    if (&otherKey != this) {
        if (sessionType != otherKey.sessionType)
            return false;
        if (dataEncKeyLen != otherKey.dataEncKeyLen)
            return false;
        if (memcmp(dataEncKey, otherKey.dataEncKey, dataEncKeyLen) != 0)
            return false;
    }
    return true;
}


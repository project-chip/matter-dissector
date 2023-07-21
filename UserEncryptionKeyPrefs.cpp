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

#include <glib.h>
#include "config.h"

#include <epan/packet.h>
#include <epan/proto_data.h>
#include <epan/uat.h>
#include <epan/prefs.h>

#include <Matter/Core/MatterCore.h>
#include <Matter/Support/CodeUtils.h>

#include "packet-matter.h"
#include "UserEncryptionKeyPrefs.h"
#include "MessageEncryptionKey.h"

uat_t *UserEncryptionKeyPrefs::sUAT = NULL;
MessageEncryptionKey *UserEncryptionKeyPrefs::sKeyList = NULL;
guint UserEncryptionKeyPrefs::sKeyCount = 0;

UAT_BUFFER_CB_DEF(MessageEncryptionKey, encKey, MessageEncryptionKey, dataEncKey, dataEncKeyLen);

static gboolean
MessageEncryptionKey_encKey_check_cb(void *rec, const char *ptr, unsigned len, const void *chk_data, const void *fld_data, char **err)
{
    if (len != kDataEncKeyLength_AES128CCM) {
        *err = g_strdup("Invalid data encryption key length");
        return FALSE;
    }

    return TRUE;
}

static void *
MessageEncryptionKey_copy_cb(void *dest, const void *orig, size_t len _U_)
{
    MessageEncryptionKey *d = (MessageEncryptionKey *)dest;
    MessageEncryptionKey *o = (MessageEncryptionKey *)orig;

    d->keyId = o->keyId;
    d->sessionType = o->sessionType;

    d->dataEncKey = (char *)g_memdup(o->dataEncKey, o->dataEncKeyLen);
    d->dataEncKeyLen = o->dataEncKeyLen;

    return dest;
}

static gboolean
MessageEncryptionKey_update_cb(void *rec _U_, char **err _U_)
{
    MessageEncryptionKey *r = (MessageEncryptionKey *)rec;

    r->keyId = matter::MatterSessionId::kNone;
    r->sessionType = matter::kMatterEncryptionType_AES128CCM;

    *err = NULL;

    return TRUE;
}

static void
MessageEncryptionKey_free_cb(void *rec)
{
    MessageEncryptionKey *r = (MessageEncryptionKey *)rec;

    g_free(r->dataEncKey);
}

static void
MessageEncryptionKey_post_update_cb(void)
{
    // No action required.
}


void UserEncryptionKeyPrefs::Init(module_t* prefs)
{
#ifndef UAT_FLD_BUFFER_OTHER
#define UAT_FLD_BUFFER_OTHER(basename,field_name,title,desc) \
    {#field_name, title, PT_TXTMOD_HEXBYTES,{ basename ## _ ## field_name ## _check_cb ,basename ## _ ## field_name ## _set_cb,basename ## _ ## field_name ## _tostr_cb},{0,0,0},0,desc,FLDFILL}
#endif

    static uat_field_t keyDataUATFields[] = {
        UAT_FLD_BUFFER_OTHER(MessageEncryptionKey, encKey, "Data Encryption Key", "Matter message data encryption key"),
        UAT_END_FIELDS
    };

    sUAT = uat_new("Message Encryption Keys",
                   sizeof(MessageEncryptionKey),
                   "matter_message_enc_keys",
                   TRUE,
                   &sKeyList,
                   &sKeyCount,
                   UAT_AFFECTS_DISSECTION,
                   NULL,
                   MessageEncryptionKey_copy_cb,
                   MessageEncryptionKey_update_cb,
                   MessageEncryptionKey_free_cb,
                   MessageEncryptionKey_post_update_cb,
                   NULL,
                   keyDataUATFields);

    prefs_register_uat_preference(prefs, "message_enc_keys",
                                  "Message Encryption Keys",
                                  "A table of keys for decrypting Matter messages",
                                  sUAT);

    char *err;
    uat_load(sUAT, nullptr, &err);

    for (guint i = 0; i < sKeyCount; i++) {
        sKeyList[i].keyId = matter::MatterSessionId::kNone;
        sKeyList[i].sessionType = matter::kMatterEncryptionType_AES128CCM;
    }
}

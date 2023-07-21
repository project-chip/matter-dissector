/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef USERENCRYPTIONKEYPREFS_H_
#define USERENCRYPTIONKEYPREFS_H_

#include "MessageEncryptionKey.h"

class UserEncryptionKeyPrefs
{
public:
    static void Init(module_t *prefs);
    static guint GetKeyCount() { return sKeyCount; }
    static const MessageEncryptionKey *GetKey(size_t index) { return (index < sKeyCount) ? &sKeyList[index] : NULL; }

private:
    static uat_t *sUAT;
    static MessageEncryptionKey *sKeyList;
    static guint sKeyCount;
};

#endif /* USERENCRYPTIONKEYPREFS_H_ */

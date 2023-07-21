/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MATTER_MESSAGE_LAYER_H
#define MATTER_MESSAGE_LAYER_H

namespace matter {

typedef enum MatterMessageVersion
{
    kMatterMessageVersion_V1                             = 1,
    kMatterMessageVersion_V2                             = 2
} MatterMessageVersion;

typedef enum MatterSessionType
{
    kMatterSessionType_Unicast                           = 0,
    kMatterSessionType_Group                             = 1,
} MatterSessionType;

typedef enum MatterSessionIds
{
    kMatterSessionId_Unsecured                           = 0,
} MatterSessionIds;

typedef enum MatterEncryptionType
{
    kMatterEncryptionType_None                           = 0,
    kMatterEncryptionType_AES128CCM                      = 1
} MatterEncryptionType;

typedef enum MatterDestSizeType
{
    kMatterDestSizeType_None                             = 0,
    kMatterDestSizeType_NodeId                           = 1,
    kMatterDestSizeType_GroupId                          = 2
} MatterDestSizeType;


typedef enum MatterMessageFlags
{
    kMatterMessageFlag_SourceNodeId                      = 0x04,
    kMatterMessageFlag_DestGroupId                       = 0x02,
    kMatterMessageFlag_DestNodeId                        = 0x01,
} MatterMessageFlags;

typedef enum MatterSecurityFlags
{
    kMatterSecurityFlag_Privacy                          = 0x80,
    kMatterSecurityFlag_ControlMsg                       = 0x40,
    kMatterSecurityFlag_MsgExtensions                    = 0x20,
} MatterSecurityFlags;

enum
{
    kMsgHeaderField_MessageVersionMask                  = 0xF0,
    kMsgHeaderField_MessageVersionShift                 = 4,
    kMsgHeaderField_EncryptionTypeMask                  = 0x03,
    kMsgHeaderField_EncryptionTypeShift                 = 0,
};

inline uint64_t IPv6InterfaceIdToMatterNodeId(uint64_t interfaceId)
{
    return (interfaceId & ~(0x0200000000000000ULL));
}

} // namespace matter

#endif // MATTER_MESSAGE_LAYER_H

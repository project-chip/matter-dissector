/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __PACKET_MATTER_H__
#define __PACKET_MATTER_H__

enum {
    kMatterProtoData_MessageRecord   = 1
};

class MatterMessageRecord;

struct MatterMessageInfo
{
    MatterMessageRecord *msgRec;
    uint8_t msgVersion;
    uint8_t msgFlags;
    uint8_t secFlags;
    uint64_t srcNodeId;
    uint64_t destNodeId;
    uint32_t msgId;
    uint32_t ackMsgCntr;
    MatterMessageRecord *ackedMsg;
    uint16_t msgProtocolId;
    uint16_t msgProtocolVendorId;
    char msgProfileIdStr[10];
    const char *msgProfileName;
    uint16_t exchId;
    MatterMessageRecord *exchangeStartMsg;
    uint8_t sessionType;
    uint16_t sessionId;
    uint8_t exchHeader;
    uint8_t msgType;
    char msgTypeStr[4];
    const char *msgTypeName;
    uint16_t msgLen;
    uint16_t headerLen;
    uint16_t payloadLen;
    uint16_t trailerLen;
    uint16_t encDataLen;
    MatterMessageRecord *retransOfMsg;
    uint32_t retransNum;
    uint32_t totalRetrans;
    MatterMessageRecord *reusesMsgCntrFrom;

    MatterMessageInfo()
    {
        memset(this, 0, sizeof(*this));
    }
};

extern int proto_matter;

extern void proto_register_matter(void);
extern void proto_reg_handoff_matter(void);
extern void proto_register_matter_common(void);
extern void proto_reg_handoff_matter_common(void);
extern void proto_register_matter_echo(void);
extern void proto_reg_handoff_matter_echo(void);
extern void proto_register_matter_security(void);
extern void proto_reg_handoff_matter_security(void);
extern void proto_register_matter_im(void);
extern void proto_reg_handoff_matter_im(void);

extern void AddMessageTypeToInfoColumn(packet_info *pinfo, const MatterMessageInfo& msgInfo);


#endif // __PACKET_MATTER_H__

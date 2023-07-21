/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include <glib.h>
#include "config.h"

#include <epan/packet.h>
#include <epan/proto_data.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/crc32-tvb.h>
#include <wsutil/report_message.h>
#include <wsutil/crc32.h>

#include <Matter/Core/MatterCore.h>
#include <Matter/Core/MatterSessionIds.h>
#include <Matter/Support/CodeUtils.h>

#include "packet-matter.h"
#include "MatterMessageTracker.h"

using namespace matter;

wmem_tree_t *MatterMessageTracker::gMessageIdTable_UnencryptedUDP = NULL;
wmem_tree_t *MatterMessageTracker::gMessageIdTable_SessionEncryptedUDP = NULL;
wmem_tree_t *MatterMessageTracker::gMessageIdTable_GroupEncryptedUDP = NULL;
wmem_tree_t *MatterMessageTracker::gMessageIdTable_UnencryptedTCP = NULL;
wmem_tree_t *MatterMessageTracker::gMessageIdTable_SessionEncryptedTCP = NULL;
wmem_tree_t *MatterMessageTracker::gMessageIdTable_GroupEncryptedTCP = NULL;

wmem_tree_t *MatterMessageTracker::gExchangeTable = NULL;

MatterMessageRecord *MatterMessageTracker::FindMessageRecord(packet_info *pinfo)
{
    // Look for an already existing message record attached as proto_data to the current packet.
    return (MatterMessageRecord *)p_get_proto_data(wmem_file_scope(), pinfo, proto_matter, kMatterProtoData_MessageRecord);
}

MatterMessageRecord* MatterMessageTracker::FindOrCreateMessageRecord(tvbuff_t* tvb, packet_info* pinfo, MatterMessageInfo& msgInfo)
{
    MatterMessageRecord *msgRec;

    InitTables();

    // Look for an already existing message record attached as proto_data to the current packet.
    msgRec = (MatterMessageRecord *)p_get_proto_data(wmem_file_scope(), pinfo, proto_matter, kMatterProtoData_MessageRecord);

    // If no record exists...
    if (msgRec == NULL) {

        // Initialize a new message record for the message.
        msgRec = wmem_new(wmem_file_scope(), MatterMessageRecord);
        memset(msgRec, 0, sizeof(*msgRec));
        msgRec->frameNum = pinfo->fd->num;

        // Compute a fingerprint for the message that can be used to quickly compare its contents.
        msgRec->fingerprint = ComputeMessageFingerprint(tvb, msgInfo);

        // Add the new message to the appropriate message id table.
        bool isTCP = (pinfo->ptype == PT_TCP);
        uint32_t tcpStreamId = (isTCP) ? get_tcp_conversation_data(NULL, pinfo)->stream : 0;
        AddMessageToMessageIdTable(msgInfo.srcNodeId, msgInfo.msgId, msgInfo.sessionType, msgInfo.sessionId, isTCP, tcpStreamId, msgRec);

        // Add the new message to the exchange table.
        uint64_t initiatorNodeId = (msgInfo.exchHeader & kMatterExchangeFlag_Initiator) != 0 ? msgInfo.srcNodeId : msgInfo.destNodeId;
        uint64_t respNodeId = (msgInfo.exchHeader & kMatterExchangeFlag_Initiator) != 0 ? msgInfo.destNodeId : msgInfo.srcNodeId;
        AddMessageToExchangeTable(initiatorNodeId, respNodeId, msgInfo.exchId, msgRec);

        p_add_proto_data(wmem_file_scope(), pinfo, proto_matter, kMatterProtoData_MessageRecord, msgRec);
    }

    return msgRec;
}

void
MatterMessageTracker::FindRetransmissions(packet_info *pinfo, MatterMessageRecord *msgRec, MatterMessageInfo& msgInfo)
{
    uint32_t msgFingerprint = msgRec->fingerprint;

    msgInfo.retransOfMsg = NULL;
    msgInfo.retransNum = 0;
    msgInfo.totalRetrans = 0;

    // Search for retransmissions / message id reuse before the current message was sent.
    for (MatterMessageRecord *p = msgRec->prevByMsgCntr; p != NULL; p = p->prevByMsgCntr) {
        if (msgFingerprint == p->fingerprint) {
            if (msgInfo.retransOfMsg == NULL || p->frameNum < msgInfo.retransOfMsg->frameNum) {
                msgInfo.retransOfMsg = p;
            }
            msgInfo.retransNum++;
            msgInfo.totalRetrans++;
        }
    }

    // Count additional retransmissions after the current message.
    for (MatterMessageRecord *p = msgRec->nextByMsgCntr; p != NULL; p = p->nextByMsgCntr) {
        if (msgFingerprint == p->fingerprint) {
            msgInfo.totalRetrans++;
        }
    }
}

void MatterMessageTracker::FindReusedMessageIds(packet_info *pinfo, MatterMessageRecord* msgRec, MatterMessageInfo& msgInfo)
{
    uint32_t msgFingerprint = msgRec->fingerprint;

    msgInfo.reusesMsgCntrFrom = NULL;

    // Search for messages sent before the current message that use the same message id but have different content.
    // Track the earliest of these in the message info reusesMsgCntrFrom field.
    for (MatterMessageRecord *p = msgRec->prevByMsgCntr; p != NULL; p = p->prevByMsgCntr) {
        if (msgFingerprint != p->fingerprint) {
            if (msgInfo.reusesMsgCntrFrom == NULL || p->frameNum < msgInfo.reusesMsgCntrFrom->frameNum) {
                msgInfo.reusesMsgCntrFrom = p;
            }
        }
    }
}

void MatterMessageTracker::FindAckedMessages(packet_info *pinfo, MatterMessageRecord* msgRec, MatterMessageInfo& msgInfo)
{
    MatterMessageRecord *ackMsgRecList;

    // If message contains a WRM ACK, find the ACKed message(s) and update the ackedBy fields.
    if (pinfo->ptype == PT_UDP && msgInfo.msgVersion > 1 && (msgInfo.exchHeader & kMatterExchangeFlag_AckId) != 0) {

        // Get the list of messages that match the acknowledged message id from the appropriate message id table.  This list
        // will contain multiples messages if, for example, the original message was retransmitted.
        ackMsgRecList = GetMessagesByMessageId(msgInfo.destNodeId, msgInfo.ackMsgCntr, msgInfo.sessionType, msgInfo.sessionId, FALSE, 0);

        // Scan thru all messages with a frame number *less* than the acknowledging message.
        // Update the ackedByMsgRec field in the acknowledged message with a pointer to current message *if* this message
        // is the earliest message to have acknowledged the original message.
        // At the same time, set the ackedMsgRec field in the current message info to point at the *latest* acknowledged message.
        for (MatterMessageRecord *p = ackMsgRecList; p != NULL; p = p->nextByMsgCntr) {
            if (p->frameNum < msgRec->frameNum) {
                if (p->ackedByMsgRec == NULL || msgRec->frameNum < p->ackedByMsgRec->frameNum) {
                    p->ackedByMsgRec = msgRec;
                }
                if (msgInfo.ackedMsg == NULL || p->frameNum > msgInfo.ackedMsg->frameNum) {
                    msgInfo.ackedMsg = p;
                }
            }
        }
    }
}

MatterMessageRecord *MatterMessageTracker::FindStartOfExchange(MatterMessageRecord *msgRec)
{
    // TODO: improve this to detect exchange boundaries in cases where exchange ids are reused.

    for (; msgRec->prevByExchange != NULL; msgRec = msgRec->prevByExchange);

    return msgRec;
}

void MatterMessageTracker::InitTables()
{
    if (gMessageIdTable_UnencryptedUDP == NULL) {
        gMessageIdTable_UnencryptedUDP = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
        gMessageIdTable_SessionEncryptedUDP = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
        gMessageIdTable_GroupEncryptedUDP = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
        gMessageIdTable_UnencryptedTCP = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
        gMessageIdTable_SessionEncryptedTCP = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
        gMessageIdTable_GroupEncryptedTCP = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
        gExchangeTable = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    }
}

MatterMessageRecord *MatterMessageTracker::GetMessagesByMessageId(uint64_t srcNodeId, uint32_t msgId,
                                                                uint8_t msgEncType, uint32_t msgSessionId,
                                                                bool isTCP, uint32_t tcpStreamId)
{
    wmem_tree_t *msgIdTable;
    wmem_tree_key_t msgIdKey[5];

    // Find the correct message id table and create a key for looking up the given message.
    GetMessageIdTableAndKey(srcNodeId, msgId, msgEncType, msgSessionId,
                            isTCP, tcpStreamId, msgIdTable, msgIdKey);

    // Return the list of messages from the associated table with the same source node and message id.
    return (MatterMessageRecord *)wmem_tree_lookup32_array(msgIdTable, msgIdKey);
}

void MatterMessageTracker::AddMessageToMessageIdTable(uint64_t srcNodeId, uint32_t msgId,
                                                     uint8_t msgEncType, uint32_t msgSessionId,
                                                     bool isTCP, uint32_t tcpStreamId,
                                                     MatterMessageRecord *msgRec)
{
    wmem_tree_t *msgIdTable;
    wmem_tree_key_t msgIdKey[5];
    MatterMessageRecord *msgsByMsgCntr, *lastMsgRec;

    // Find the correct message id table and create a key for looking up the given message.
    GetMessageIdTableAndKey(srcNodeId, msgId, msgEncType, msgSessionId,
                            isTCP, tcpStreamId, msgIdTable, msgIdKey);

    // Get the list of messages with the same source node and message id.
    msgsByMsgCntr = (MatterMessageRecord *)wmem_tree_lookup32_array(msgIdTable, msgIdKey);

    // Add the new message to the end of the list.
    lastMsgRec = NULL;
    for (MatterMessageRecord *p = msgsByMsgCntr; p != NULL; p = p->nextByMsgCntr) {
        lastMsgRec = p;
    }
    if (lastMsgRec != NULL) {
        lastMsgRec->nextByMsgCntr = msgRec;
        msgRec->prevByMsgCntr = lastMsgRec;
    }
    else {
        wmem_tree_insert32_array(msgIdTable, msgIdKey, msgRec);
    }
}

MatterMessageRecord *MatterMessageTracker::GetMessagesByExchange(uint64_t initiatorNodeId, uint64_t respNodeId, uint32_t exchangeId)
{
    wmem_tree_key_t exchangeKey[4];

    // Form a key to look up the list of messages by exchange in the exchange table.
    exchangeKey[0].length = 2;
    exchangeKey[0].key = (guint32 *)&initiatorNodeId;
    exchangeKey[1].length = 2;
    exchangeKey[1].key = (guint32 *)&respNodeId;
    exchangeKey[2].length = 1;
    exchangeKey[2].key = &exchangeId;
    exchangeKey[3].length = 0;
    exchangeKey[3].key = NULL;

    // Return the list of messages associated with the exchange.
    return (MatterMessageRecord *)wmem_tree_lookup32_array(gExchangeTable, exchangeKey);
}

void MatterMessageTracker::AddMessageToExchangeTable(uint64_t initiatorNodeId, uint64_t respNodeId, uint32_t exchangeId, MatterMessageRecord *msgRec)
{
    wmem_tree_key_t exchangeKey[4];
    MatterMessageRecord *msgsByExchange, *lastMsgRec;

    // Form a key to look up the list of messages by exchange in the exchange table.
    exchangeKey[0].length = 2;
    exchangeKey[0].key = (guint32 *)&initiatorNodeId;
    exchangeKey[1].length = 2;
    exchangeKey[1].key = (guint32 *)&respNodeId;
    exchangeKey[2].length = 1;
    exchangeKey[2].key = &exchangeId;
    exchangeKey[3].length = 0;
    exchangeKey[3].key = NULL;

    // Get the list of messages associated with the exchange.
    msgsByExchange = (MatterMessageRecord *)wmem_tree_lookup32_array(gExchangeTable, exchangeKey);

    // Add the new message to the end of the list.
    lastMsgRec = NULL;
    for (MatterMessageRecord *p = msgsByExchange; p != NULL; p = p->nextByExchange) {
        lastMsgRec = p;
    }
    if (lastMsgRec != NULL) {
        lastMsgRec->nextByExchange = msgRec;
        msgRec->prevByExchange = lastMsgRec;
    }
    else {
        wmem_tree_insert32_array(gExchangeTable, exchangeKey, msgRec);
    }
}

void MatterMessageTracker::GetMessageIdTableAndKey(uint64_t& srcNodeId, uint32_t& msgId,
                                                  uint8_t msgEncType, uint32_t& msgSessionId,
                                                  bool isTCP, uint32_t& tcpStreamId,
                                                  wmem_tree_t *& msgIdTable, wmem_tree_key_t msgIdKey[5])
{
    // Form a key for looking up the message in the appropriate message table.
    msgIdKey[0].length = 2;
    msgIdKey[0].key = (guint32 *)&srcNodeId;
    msgIdKey[1].length = 1;
    msgIdKey[1].key = &msgId;
    msgIdKey[2].length = 0;
    msgIdKey[2].key = NULL;

    if (isTCP) {

        msgIdKey[2].length = 1;
        msgIdKey[2].key = &tcpStreamId;
        msgIdKey[3].length = 0;
        msgIdKey[3].key = NULL;

        if (msgEncType == kMatterEncryptionType_None) {
            msgIdTable = gMessageIdTable_UnencryptedTCP;
        }
        else if (MatterSessionId::GetType(msgSessionId) == MatterSessionId::kType_Session) {

            msgIdKey[3].length = 1;
            msgIdKey[3].key = &msgSessionId;
            msgIdKey[4].length = 0;
            msgIdKey[4].key = NULL;

            msgIdTable = gMessageIdTable_SessionEncryptedTCP;
        }
        else {
            msgIdTable = gMessageIdTable_GroupEncryptedTCP;
        }
    }

    else {

        if (msgEncType == kMatterEncryptionType_None) {
            msgIdTable = gMessageIdTable_UnencryptedUDP;
        }
        else if (MatterSessionId::GetType(msgSessionId) == MatterSessionId::kType_Session) {

            msgIdKey[2].length = 1;
            msgIdKey[2].key = &msgSessionId;
            msgIdKey[3].length = 0;
            msgIdKey[3].key = NULL;

            msgIdTable = gMessageIdTable_SessionEncryptedUDP;
        }
        else {
            msgIdTable = gMessageIdTable_GroupEncryptedUDP;
        }
    }
}

uint32_t MatterMessageTracker::ComputeMessageFingerprint(tvbuff_t* tvb, MatterMessageInfo& msgInfo)
{
    struct PseudoHeader
    {
        uint8_t msgFlags;
        uint16_t sessionId;
        uint8_t secFlags;
        uint32_t msgId;
        uint64_t srcNodeId;
        uint64_t destNodeId;
        uint16_t payloadLen;
        uint8_t msgVersion;
        uint8_t sessionType;
    } pseudoHeader;

    memset(&pseudoHeader, 0, sizeof(pseudoHeader));
    pseudoHeader.msgFlags = msgInfo.msgFlags;
    pseudoHeader.sessionId = msgInfo.sessionId;
    pseudoHeader.secFlags = msgInfo.secFlags;
    pseudoHeader.msgId = msgInfo.msgId;
    pseudoHeader.srcNodeId = msgInfo.srcNodeId;
    pseudoHeader.destNodeId = msgInfo.destNodeId;
    pseudoHeader.payloadLen = msgInfo.payloadLen;
    pseudoHeader.msgVersion = msgInfo.msgVersion;
    pseudoHeader.sessionType = msgInfo.sessionType;

    uint32_t fingerprint = crc32_ccitt((const guint8 *)&pseudoHeader, (guint)sizeof(pseudoHeader));
    fingerprint = crc32_ccitt_tvb_offset_seed(tvb, msgInfo.headerLen, msgInfo.msgLen - msgInfo.headerLen, ~fingerprint);

    return fingerprint;
}

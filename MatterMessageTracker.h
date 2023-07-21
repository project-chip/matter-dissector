/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MATTERMESSAGETRACKER_H_
#define MATTERMESSAGETRACKER_H_

class CASEExchangeRecord;

class MatterMessageRecord
{
public:
    uint32_t frameNum;
    uint32_t fingerprint;
    uint64_t imSubscription;
    MatterMessageRecord *ackedByMsgRec;
    MatterMessageRecord *nextByMsgCntr;
    MatterMessageRecord *prevByMsgCntr;
    MatterMessageRecord *nextByExchange;
    MatterMessageRecord *prevByExchange;
    CASEExchangeRecord *caseExchangeRec;
};

class MatterMessageTracker
{
public:
    static MatterMessageRecord *FindMessageRecord(packet_info *pinfo);
    static MatterMessageRecord *FindOrCreateMessageRecord(tvbuff_t *tvb, packet_info *pinfo, MatterMessageInfo& msgInfo);

    static void FindRetransmissions(packet_info *pinfo, MatterMessageRecord *msgRec, MatterMessageInfo& msgInfo);
    static void FindReusedMessageIds(packet_info *pinfo, MatterMessageRecord *msgRec, MatterMessageInfo& msgInfo);
    static void FindAckedMessages(packet_info *pinfo, MatterMessageRecord *msgRec, MatterMessageInfo& msgInfo);
    static MatterMessageRecord *FindStartOfExchange(MatterMessageRecord *msgRec);

private:
    static wmem_tree_t *gMessageIdTable_UnencryptedUDP;
    static wmem_tree_t *gMessageIdTable_SessionEncryptedUDP;
    static wmem_tree_t *gMessageIdTable_GroupEncryptedUDP;
    static wmem_tree_t *gMessageIdTable_UnencryptedTCP;
    static wmem_tree_t *gMessageIdTable_SessionEncryptedTCP;
    static wmem_tree_t *gMessageIdTable_GroupEncryptedTCP;
    static wmem_tree_t *gExchangeTable;

    MatterMessageTracker(); // Not defined
    ~MatterMessageTracker(); // Not defined

    static void InitTables();

    static MatterMessageRecord *GetMessagesByMessageId(uint64_t srcNodeId, uint32_t msgId,
                                                      uint8_t msgEncType, uint32_t msgSessionId,
                                                      bool isTCP, uint32_t tcpStreamId);
    static void AddMessageToMessageIdTable(uint64_t srcNodeId, uint32_t msgId,
                                           uint8_t msgEncType, uint32_t msgSessionId,
                                           bool isTCP, uint32_t tcpStreamId,
                                           MatterMessageRecord *msgRec);

    static MatterMessageRecord *GetMessagesByExchange(uint64_t initiatorNodeId, uint64_t respNodeId, uint32_t exchangeId);
    static void AddMessageToExchangeTable(uint64_t initiatorNodeId, uint64_t respNodeId, uint32_t exchangeId, MatterMessageRecord *msgRec);

    static void GetMessageIdTableAndKey(uint64_t& srcNodeId, uint32_t& msgId,
                                        uint8_t msgEncType, uint32_t& msgSessionId,
                                        bool isTCP, uint32_t& tcpStreamId,
                                        wmem_tree_t *& msgIdTable, wmem_tree_key_t msgIdKey[5]);

    static uint32_t ComputeMessageFingerprint(tvbuff_t* tvb, MatterMessageInfo& msgInfo);
};

#endif /* MATTERMESSAGETRACKER_H_ */

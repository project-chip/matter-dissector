/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * packet-matter.cpp
 *
 */

#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <utime.h>
#include <ctype.h>
#include <errno.h>

#include <glib.h>
#include "config.h"

#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/proto_data.h>
#include <epan/conversation_filter.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/crc32-tvb.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include <wsutil/report_message.h>
#include <wsutil/filesystem.h>

#include <Matter/Core/MatterCore.h>
#include <Matter/Core/MatterEncoding.h>
#include <Matter/Support/MatterNames.h>
#include <Matter/Core/MatterSessionIds.h>
#include <Matter/Support/CodeUtils.h>
#include <Matter/Support/SafeInt.h>

#include "packet-matter.h"
#include "packet-matter-decrypt.h"

#include "MessageEncryptionKey.h"
#include "MatterMessageTracker.h"
#include "UserEncryptionKeyPrefs.h"

using namespace matter;

#ifndef PLUGIN_VERSION
#define PLUGIN_VERSION "0.0.0"
#endif

#if defined(__APPLE__) || defined(__NetBSD__)
#define st_atim st_atimespec
#define st_ctim st_ctimespec
#define st_mtim st_mtimespec
#endif

extern "C" {
// Targets Wireshark version 3.6
WS_DLL_PUBLIC const int plugin_want_major = 3;
WS_DLL_PUBLIC const int plugin_want_minor = 6;

WS_DLL_PUBLIC const gchar plugin_version[] = PLUGIN_VERSION;
WS_DLL_PUBLIC const gchar plugin_release[] = "3.6";
WS_DLL_PUBLIC void plugin_register(void);
}

enum {
    kMatterTCPMessageLengthFieldSize = 2
};

int proto_matter = -1;

static int ett_matter = -1;

static int hf_Matter_MsgFlags = -1;
static int hf_Matter_Version = -1;
static int hf_Matter_SFlag = -1;
static int hf_Matter_DSIZ = -1;
static int hf_Matter_SecFlags = -1;
static int hf_Matter_PFlag = -1;
static int hf_Matter_CFlag = -1;
static int hf_Matter_MXFlag = -1;
static int hf_Matter_EncType = -1;
static int hf_Matter_MsgCntr = -1;
static int hf_Matter_SessionId = -1;
static int hf_Matter_SourceNodeId = -1;
static int hf_Matter_DestNodeId = -1;
static int hf_Matter_ExchangeHeader = -1;
static int hf_Matter_VFlag = -1;
static int hf_Matter_SXFlag = -1;
static int hf_Matter_RFlag = -1;
static int hf_Matter_AFlag = -1;
static int hf_Matter_IFlag = -1;
static int hf_Matter_ProtocolOpcode = -1;
static int hf_Matter_ExchangeId = -1;
static int hf_Matter_ExchangeStartFrameNum = -1;
static int hf_Matter_ProtocolId = -1;
static int hf_Matter_ProtocolVendorId = -1;
static int hf_Matter_AckMsgCntr = -1;
static int hf_Matter_AckMsgFrameNum = -1;
static int hf_Matter_AckedByFrameNum = -1;
static int hf_Matter_Payload = -1;
static int hf_Matter_EncData = -1;
static int hf_Matter_IntegrityCheck = -1;
static int hf_Matter_RetransFrameNum = -1;
static int hf_Matter_MsgCntrReuseFrameNum = -1;

static dissector_table_t matter_subdissector_table;

static gboolean pref_ShowNodeIds = true;

const value_string sessionTypeNames[] = {
    { kMatterSessionType_Unicast, "Unicast" },
    { kMatterSessionType_Group, "Group" },
    { 0, NULL }
};

const value_string dsizTypeNames[] = {
    { kMatterDestSizeType_None, "None" },
    { kMatterDestSizeType_NodeId, "64-bit Destination NodeId" },
    { kMatterDestSizeType_GroupId, "16-bit Destination GroupId" },
    { 0, NULL }
};

static char *pluginDirName = NULL;

static dissector_handle_t ip_handle;


static bool MessageIsEncrypted(const MatterMessageInfo& msgInfo)
{
    // Unsecured session is defined as unicast session with session ID of 0.
    return !(msgInfo.sessionType == kMatterSessionType_Unicast && msgInfo.sessionId == kMatterSessionId_Unsecured);
}

static tvbuff_t *
TryDecryptMessage(tvbuff_t *tvb, int encDataOffset, packet_info *pinfo, const MatterMessageInfo& msgInfo)
{
    tvbuff_t *unencMsgTVB;
    uint32_t dataLen;
    uint8_t *encData, *unencData, *aadData;
    bool success = false;

    if (MessageIsEncrypted(msgInfo)) {

        dataLen = msgInfo.msgLen - encDataOffset;
        encData = (uint8_t *)tvb_memdup(pinfo->pool, tvb, encDataOffset, dataLen);
        aadData = (uint8_t *)tvb_memdup(pinfo->pool, tvb, 0, encDataOffset);
        unencData = (uint8_t *)g_malloc(dataLen);

        // Search the list of keys in the encryption key table with a matching key id for one that
        // successfully decrypts the message.
        const MessageEncryptionKey *keys = MessageEncryptionKeyTable::FindKeysById(msgInfo.sessionId);
        for (; keys != NULL && !success; keys = keys->nextKey) {
            success = TryDecryptMessage_AES128CCM(encData, unencData, dataLen, aadData, encDataOffset, pinfo, msgInfo, *keys);
        }

        // If no matching key was found...
        if (!success) {
            MessageEncryptionKey userPrefKey;

            // Search the keys in the user encryption key preferences table for a key that can decrypt the message.
            for (size_t i = 0; !success && i < UserEncryptionKeyPrefs::GetKeyCount(); i++) {
                userPrefKey = *UserEncryptionKeyPrefs::GetKey(i);
                success = TryDecryptMessage_AES128CCM(encData, unencData, dataLen, aadData, encDataOffset, pinfo, msgInfo, userPrefKey);
            }

            // If a matching key was found, copy it to the main encryption key table, indexed by the key id.
            if (success) {
                userPrefKey.keyId = msgInfo.sessionId;
                MessageEncryptionKeyTable::AddKey(userPrefKey);
            }
        }

        if (success) {
            unencMsgTVB = tvb_new_real_data(unencData, dataLen, dataLen);
            tvb_set_child_real_data_tvbuff(tvb, unencMsgTVB);
            return unencMsgTVB;
        }
        else {
            g_free(unencData);
            return NULL;
        }
    }
    else {
        return NULL;
    }
}

static void
DisplayInternalUseAlert(void)
{
    char *timestampFileName = NULL;
    struct stat fs;
    struct utimbuf ut;
    time_t curTime;

    static bool alertShown = false;

    enum {
        kDisplayInterval = 86400
    };

    timestampFileName = get_persconffile_path("matter_internal_use_alert", FALSE);

    if (::stat(timestampFileName, &fs) == 0) {

        ::time(&curTime);

        if (fs.st_mtim.tv_sec + kDisplayInterval > curTime) {
            ExitNow();
        }

        ut.actime = fs.st_atim.tv_sec;
        ut.modtime = curTime;
        utime(timestampFileName, &ut);
    }

    else {
        int fd = ::open(timestampFileName, O_CREAT|O_TRUNC|O_RDWR, 0600);
        if (fd >= 0)
            close(fd);
    }

    if (!alertShown) {
        report_failure("DISCLAIMER: The Matter Protocol Wireshark dissector is an experimental tool.\n");
        alertShown = true;
    }

exit:
    if (timestampFileName != NULL)
        g_free(timestampFileName);
}

static void
InitMatterDissector(void)
{
    struct stat fs;

    if (pluginDirName == NULL) {
        const char *homeDir = getenv("HOME");
        if (homeDir != NULL) {
            pluginDirName = g_strdup_printf("%s/.matter_wireshark_plugin", homeDir);
        }
    }

    if (pluginDirName != NULL) {

        if (::stat(pluginDirName, &fs) == 0 && S_ISREG(fs.st_mode) && fs.st_size == 0) {
            unlink(pluginDirName);
        }

        if (::stat(pluginDirName, &fs) != 0 && errno == ENOENT) {
            mkdir(pluginDirName, 0700);
        }

        if (::stat(pluginDirName, &fs) != 0 || !S_ISDIR(fs.st_mode)) {
            g_free(pluginDirName);
            pluginDirName = NULL;
        }
    }

    DisplayInternalUseAlert();
}

void
AddMessageTypeToInfoColumn(packet_info *pinfo, const MatterMessageInfo& msgInfo)
{
    if (msgInfo.msgTypeName != NULL) {
        col_prepend_fstr(pinfo->cinfo, COL_INFO, "%s:%s ", msgInfo.msgProfileName, msgInfo.msgTypeName);
    }
    else {
        col_prepend_fstr(pinfo->cinfo, COL_INFO, "%04X:%s ", msgInfo.msgProtocolId, msgInfo.msgTypeStr);
    }
}

static void
GetMessageSessionTypeDescription(uint8_t secureFlags, char *descBuf, size_t descBufSize)
{
    uint8_t sessionType = secureFlags & MatterSessionId::kMask_SessionType;

    switch (sessionType) {
    case MatterSessionId::kSessionType_Unicast:
        snprintf(descBuf, descBufSize, "Unicast");
        break;
    case MatterSessionId::kSessionType_Group:
        snprintf(descBuf, descBufSize, "Group");
        break;
    default:
        descBuf[0] = 0;
        break;
    }
}

static int
DissectMatter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    MatterMessageInfo msgInfo;
    tvbuff_t *unencMsgTVB, *payloadTVB;
    int parsePoint = 0, payloadOffset, profileDissectorRes;
    uint32_t nodeIdLen;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Matter");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *top = proto_tree_add_item(tree, proto_matter, tvb, 0, -1, ENC_NA);
    proto_tree *matter_tree = proto_item_add_subtree(top, ett_matter);

    if (pinfo->ptype == PT_TCP) {
        msgInfo.msgLen = tvb_get_letohs(tvb, 0);
        tvb = tvb_new_subset_remaining(tvb, kMatterTCPMessageLengthFieldSize);
    }
    else {
        msgInfo.msgLen = tvb_reported_length(tvb);
    }

    // Message Flags
    msgInfo.msgFlags = tvb_get_guint8(tvb, parsePoint);
    msgInfo.msgVersion = (uint8_t)((msgInfo.msgFlags & kMsgHeaderField_MessageVersionMask) >> kMsgHeaderField_MessageVersionShift);
 
    proto_tree_add_item(matter_tree, hf_Matter_MsgFlags, tvb, parsePoint, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(matter_tree, hf_Matter_Version, tvb, parsePoint, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(matter_tree, hf_Matter_SFlag, tvb, parsePoint, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(matter_tree, hf_Matter_DSIZ, tvb, parsePoint, 1, ENC_LITTLE_ENDIAN);

    parsePoint += 1;

    // Session Id
    msgInfo.sessionId = tvb_get_letohs(tvb, parsePoint);

    proto_tree_add_item(matter_tree, hf_Matter_SessionId, tvb, parsePoint, 2, ENC_LITTLE_ENDIAN);

    parsePoint += 2;

    // Security Flags
    msgInfo.secFlags = tvb_get_guint8(tvb, parsePoint);
    msgInfo.sessionType = (uint8_t)((msgInfo.secFlags & kMsgHeaderField_EncryptionTypeMask) >> kMsgHeaderField_EncryptionTypeShift);

    char sessionTypeDesc[64];
    GetMessageSessionTypeDescription(msgInfo.secFlags, sessionTypeDesc, sizeof(sessionTypeDesc));

    proto_tree_add_uint_format_value(matter_tree, hf_Matter_SecFlags, tvb, parsePoint, 1, msgInfo.sessionId,
            (sessionTypeDesc[0] != 0) ? "%02X (%s)" : "%02X", msgInfo.secFlags, sessionTypeDesc);

    proto_tree_add_item(matter_tree, hf_Matter_PFlag, tvb, parsePoint, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(matter_tree, hf_Matter_CFlag, tvb, parsePoint, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(matter_tree, hf_Matter_MXFlag, tvb, parsePoint, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(matter_tree, hf_Matter_EncType, tvb, parsePoint, 1, ENC_LITTLE_ENDIAN);

    parsePoint += 1;

    // Message Counter
    msgInfo.msgId = tvb_get_letohl(tvb, parsePoint);
    proto_tree_add_uint(matter_tree, hf_Matter_MsgCntr, tvb, parsePoint, 4, msgInfo.msgId);
    parsePoint += 4;

    if ((msgInfo.msgFlags & kMatterMessageFlag_SourceNodeId) != 0) {
        msgInfo.srcNodeId = tvb_get_letoh64(tvb, parsePoint);
        nodeIdLen = 8;
    }
    else {
        msgInfo.srcNodeId = 0;
        //(pinfo->net_src.type == AT_IPv6)
        //    ? IPv6InterfaceIdToMatterNodeId(Encoding::BigEndian::Get64(((const uint8_t *)pinfo->net_src.data) + 8))
        //    : 0;
        nodeIdLen = 0;
    }
    proto_tree_add_uint64_format_value(matter_tree, hf_Matter_SourceNodeId, tvb, parsePoint, nodeIdLen, msgInfo.srcNodeId,
            ("0x%0*" PRIX64), (msgInfo.srcNodeId < 65536) ? 1 : 16, msgInfo.srcNodeId);
    parsePoint += nodeIdLen;

    if ((msgInfo.msgFlags & kMatterMessageFlag_DestNodeId) != 0) {
        msgInfo.destNodeId = tvb_get_letoh64(tvb, parsePoint);
        nodeIdLen = 8;
    }
    else {
        msgInfo.destNodeId = 0;
        // (pinfo->net_dst.type == AT_IPv6)
        //    ? IPv6InterfaceIdToMatterNodeId(Encoding::BigEndian::Get64(((const uint8_t *)pinfo->net_dst.data) + 8))
        //    : 0;
        nodeIdLen = 0;
    }
    proto_tree_add_uint64_format_value(matter_tree, hf_Matter_DestNodeId, tvb, parsePoint, nodeIdLen, msgInfo.destNodeId,
            ("0x%0*" PRIX64), (msgInfo.destNodeId < 65536) ? 1 : 16, msgInfo.destNodeId);
    parsePoint += nodeIdLen;

    if (pref_ShowNodeIds) {
        col_add_fstr(pinfo->cinfo, COL_INFO, ("Src=%" PRIX64 " Dest=%" PRIX64 " MsgCntr=%08" PRIX32), msgInfo.srcNodeId, msgInfo.destNodeId, msgInfo.msgId);
    }
    else {
        col_add_fstr(pinfo->cinfo, COL_INFO, ("MsgCntr=%08" PRIX32), msgInfo.msgId);
    }

    msgInfo.headerLen = parsePoint;

    if (!MessageIsEncrypted(msgInfo)) {
        unencMsgTVB = tvb_new_subset_remaining(tvb, parsePoint);
    }

    else {
        unencMsgTVB = TryDecryptMessage(tvb, parsePoint, pinfo, msgInfo);
        if (unencMsgTVB != NULL) {
            add_new_data_source(pinfo, unencMsgTVB, "Decrypted Message Data");
            msgInfo.trailerLen += MATTER_CRYPTO_TAG_LENGTH;
        }
    }

    if (unencMsgTVB != NULL) {

        // Process the Protocol portion of the Matter Message payload...

        parsePoint = 0;

        msgInfo.exchHeader = tvb_get_guint8(unencMsgTVB, parsePoint);
        proto_tree_add_item(matter_tree, hf_Matter_ExchangeHeader, unencMsgTVB, parsePoint, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(matter_tree, hf_Matter_VFlag, unencMsgTVB, parsePoint, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(matter_tree, hf_Matter_SXFlag,unencMsgTVB, parsePoint, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(matter_tree, hf_Matter_RFlag, unencMsgTVB, parsePoint, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(matter_tree, hf_Matter_AFlag, unencMsgTVB, parsePoint, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(matter_tree, hf_Matter_IFlag, unencMsgTVB, parsePoint, 1, ENC_LITTLE_ENDIAN);
        parsePoint += 1;

        msgInfo.msgType = tvb_get_guint8(unencMsgTVB, parsePoint);
        parsePoint += 1;

        msgInfo.exchId = tvb_get_letohs(unencMsgTVB, parsePoint);
        parsePoint += 2;

        msgInfo.msgProtocolId = tvb_get_letohs(unencMsgTVB, parsePoint);
        msgInfo.msgProfileName = GetProtocolName(msgInfo.msgProtocolId);
        parsePoint += 2;

        if ((msgInfo.exchHeader & kMatterExchangeFlag_VendorProtocol) != 0) {
            msgInfo.msgProtocolVendorId = tvb_get_letohs(unencMsgTVB, parsePoint);
            parsePoint += 2;
        }
        msgInfo.msgTypeName = GetMessageName(msgInfo.msgProtocolId, msgInfo.msgType);

        // Back up and add annotations
        parsePoint = 1;
        proto_tree_add_uint_format_value(matter_tree, hf_Matter_ProtocolOpcode, unencMsgTVB, parsePoint, 1, msgInfo.msgType,
                (msgInfo.msgTypeName != NULL) ? "%d (%s)" : "%d", msgInfo.msgType, msgInfo.msgTypeName);
        parsePoint += 1;

        proto_tree_add_item(matter_tree, hf_Matter_ExchangeId, unencMsgTVB, parsePoint, 2, ENC_LITTLE_ENDIAN);
        parsePoint += 2;

        proto_tree_add_uint_format_value(matter_tree, hf_Matter_ProtocolId, unencMsgTVB, parsePoint, 2, msgInfo.msgProtocolId,
                (msgInfo.msgProfileName != NULL) ? "0x%04X (%s)" : "0x%04X", msgInfo.msgProtocolId, msgInfo.msgProfileName);
        parsePoint += 2;

        if ((msgInfo.exchHeader & kMatterExchangeFlag_VendorProtocol) != 0) {
            proto_tree_add_uint_format_value(
                matter_tree, hf_Matter_ProtocolVendorId, unencMsgTVB, parsePoint, 2, 
                msgInfo.msgProtocolVendorId, "0x%04X", msgInfo.msgProtocolVendorId);
            parsePoint += 2;
        }

        snprintf(msgInfo.msgProfileIdStr, sizeof(msgInfo.msgProfileIdStr), "%08X", msgInfo.msgProtocolId);
        snprintf(msgInfo.msgTypeStr, sizeof(msgInfo.msgTypeStr), "%d", msgInfo.msgType);
        col_append_fstr(pinfo->cinfo, COL_INFO, " ExchId=%02X", msgInfo.exchId);

        if ((msgInfo.exchHeader & kMatterExchangeFlag_AckId) != 0) {
            msgInfo.ackMsgCntr = tvb_get_letohl(unencMsgTVB, parsePoint);
            proto_tree_add_uint(matter_tree, hf_Matter_AckMsgCntr, unencMsgTVB, parsePoint, 4, msgInfo.ackMsgCntr);
            parsePoint += 4;
            col_append_fstr(pinfo->cinfo, COL_INFO, (" AckMsgCntr=%08" PRIX32), msgInfo.ackMsgCntr);
        }

        payloadOffset = parsePoint;
        msgInfo.payloadLen = tvb_captured_length(unencMsgTVB) - (parsePoint + msgInfo.trailerLen);

        if (msgInfo.payloadLen != 0) {
            proto_tree_add_bytes_item(matter_tree, hf_Matter_Payload, unencMsgTVB, parsePoint, msgInfo.payloadLen, ENC_LITTLE_ENDIAN, NULL, NULL, NULL);
            parsePoint += msgInfo.payloadLen;
        }

        if (MessageIsEncrypted(msgInfo)) {
            proto_tree_add_bytes_item(matter_tree, hf_Matter_IntegrityCheck, unencMsgTVB, parsePoint, MATTER_CRYPTO_TAG_LENGTH, ENC_LITTLE_ENDIAN, NULL, NULL, NULL);
            parsePoint += MATTER_CRYPTO_TAG_LENGTH;
        }

        msgInfo.msgRec = MatterMessageTracker::FindOrCreateMessageRecord(tvb, pinfo, msgInfo);

        msgInfo.exchangeStartMsg = MatterMessageTracker::FindStartOfExchange(msgInfo.msgRec);
        if (msgInfo.exchangeStartMsg != NULL) {
            proto_item *item;
            if (msgInfo.exchangeStartMsg == msgInfo.msgRec) {
                item = proto_tree_add_uint_format(matter_tree, hf_Matter_ExchangeStartFrameNum, unencMsgTVB, 0, 0, msgInfo.exchangeStartMsg->frameNum,
                    "Start of exchange in this frame");
            } else {
                item = proto_tree_add_uint(matter_tree, hf_Matter_ExchangeStartFrameNum, unencMsgTVB, 0, 0, msgInfo.exchangeStartMsg->frameNum);
            }
            PROTO_ITEM_SET_GENERATED(item);
        }

        MatterMessageTracker::FindRetransmissions(pinfo, msgInfo.msgRec, msgInfo);
        if (msgInfo.retransOfMsg != NULL) {
            proto_item *item = proto_tree_add_uint_format_value(matter_tree, hf_Matter_RetransFrameNum, unencMsgTVB, 0, 0, msgInfo.retransOfMsg->frameNum,
                    ("%" PRId32 " (retransmission %" PRId32 " of %" PRId32 ")"), msgInfo.retransOfMsg->frameNum, msgInfo.retransNum, msgInfo.totalRetrans);
            PROTO_ITEM_SET_GENERATED(item);
        }

        MatterMessageTracker::FindReusedMessageIds(pinfo, msgInfo.msgRec, msgInfo);
        if (msgInfo.reusesMsgCntrFrom != NULL) {
            proto_item *item = proto_tree_add_uint(matter_tree, hf_Matter_MsgCntrReuseFrameNum, unencMsgTVB, 0, 0, msgInfo.reusesMsgCntrFrom->frameNum);
            PROTO_ITEM_SET_GENERATED(item);
        }

        MatterMessageTracker::FindAckedMessages(pinfo, msgInfo.msgRec, msgInfo);
        if (msgInfo.ackedMsg != NULL) {
            proto_item *item = proto_tree_add_uint(matter_tree, hf_Matter_AckMsgFrameNum, unencMsgTVB, 0, 0, msgInfo.ackedMsg->frameNum);
            PROTO_ITEM_SET_GENERATED(item);
        }
        if (msgInfo.msgRec->ackedByMsgRec != NULL) {
            proto_item *item = proto_tree_add_uint(matter_tree, hf_Matter_AckedByFrameNum, unencMsgTVB, 0, 0, msgInfo.msgRec->ackedByMsgRec->frameNum);
            PROTO_ITEM_SET_GENERATED(item);
        }

        payloadTVB = tvb_new_subset_length(unencMsgTVB, payloadOffset, msgInfo.payloadLen);

        profileDissectorRes = dissector_try_uint_new(matter_subdissector_table, msgInfo.msgProtocolId, payloadTVB, pinfo, tree, false, &msgInfo);

        if (profileDissectorRes == 0) {
            AddMessageTypeToInfoColumn(pinfo, msgInfo);
        }

    } else {
        uint16_t encDataLen = msgInfo.msgLen - parsePoint;
        proto_tree_add_bytes_item(matter_tree, hf_Matter_EncData, tvb, parsePoint, encDataLen, ENC_LITTLE_ENDIAN, NULL, NULL, NULL);
    }

    return tvb_captured_length(tvb);
}

static guint GetMatterTCPMessageLength(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    return (guint)tvb_get_letohs(tvb, 0) + kMatterTCPMessageLengthFieldSize;
}

static int
DissectMatterTCP(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, kMatterTCPMessageLengthFieldSize, GetMatterTCPMessageLength, DissectMatter, data);

    return tvb_captured_length(tvb);
}

static gboolean MatterExchangeFilter_IsValid(struct _packet_info *pinfo)
{
    return proto_is_frame_protocol(pinfo->layers, "matter") && MatterMessageTracker::FindMessageRecord(pinfo) != NULL;
}

static gchar* MatterExchangeFilter_BuildFilterString(struct _packet_info *pinfo)
{
    MatterMessageRecord *msgRec = MatterMessageTracker::FindMessageRecord(pinfo);

    MatterMessageRecord *exchangeStartMsgRec = MatterMessageTracker::FindStartOfExchange(msgRec);

    return g_strdup_printf("matter.exchange_start_frame eq %d", exchangeStartMsgRec->frameNum);
}

void
proto_register_matter(void)
{
    static hf_register_info hf[] = {
        { &hf_Matter_MsgFlags,
            { "Message Flags", "matter.msg_flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_Matter_Version,
            { "Message Version", "matter.msg_flags.version",
            FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }
        },
        { &hf_Matter_SFlag,
            { "S Flag - Source Node Id Present", "matter.msg_flags.flags.s",
            FT_BOOLEAN, 8, NULL, kMatterMessageFlag_SourceNodeId, NULL, HFILL }
        },
        { &hf_Matter_DSIZ,
            { "Destination Size", "matter.msg_flags.dest_size",
            FT_UINT8, BASE_DEC, VALS(dsizTypeNames), 0x03, NULL, HFILL }
        },
        { &hf_Matter_SessionId,
            { "Session Id", "matter.session_id",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_Matter_SecFlags,
            { "Security Flags", "matter.sec_flags",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_Matter_PFlag,
            { "P Flag - Message Privacy Enabled", "matter.sec_flags.flags.p",
            FT_BOOLEAN, 8, NULL, kMatterSecurityFlag_Privacy, NULL, HFILL }
        },
        { &hf_Matter_CFlag,
            { "C Flag - Message Control Message", "matter.sec_flags.flags.c",
            FT_BOOLEAN, 8, NULL, kMatterSecurityFlag_ControlMsg, NULL, HFILL }
        },
        { &hf_Matter_MXFlag,
            { "MX Flag- Message Extensions", "matter.header.flags.mx",
            FT_BOOLEAN, 8, NULL, kMatterSecurityFlag_MsgExtensions, NULL, HFILL }
        },
        { &hf_Matter_EncType,
            { "Session Type", "matter.sec_flags.enc_type",
            FT_UINT8, BASE_DEC, VALS(sessionTypeNames), 0x03, NULL, HFILL }
        },
        { &hf_Matter_MsgCntr,
            { "Message Counter", "matter.message_id",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_Matter_SourceNodeId,
            { "Source Node Id", "matter.source_node_id",
            FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_Matter_DestNodeId,
            { "Destination Node Id", "matter.dest_node_id",
            FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_Matter_ExchangeHeader,
            { "Exchange Header", "matter.exchange_header",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_Matter_VFlag,
            { "V Flag - Vendor Protocol", "matter.header.flags.v",
            FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }
        },
        { &hf_Matter_SXFlag,
            { "SX Flag- Secure Extensions", "matter.header.flags.sx",
            FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }
        },
        { &hf_Matter_RFlag,
            { "R Flag - Ack Requested", "matter.header.flags.r",
            FT_BOOLEAN, 8, NULL, kMatterExchangeFlag_NeedsAck, NULL, HFILL }
        },
        { &hf_Matter_AFlag,
            { "A Flag - Contains Ack", "matter.header.flags.a",
            FT_BOOLEAN, 8, NULL, kMatterExchangeFlag_AckId, NULL, HFILL }
        },
        { &hf_Matter_IFlag,
            { "I Flag - From Initiator", "matter.header.flags.i",
            FT_BOOLEAN, 8, NULL, kMatterExchangeFlag_Initiator, NULL, HFILL }
        },
        { &hf_Matter_ProtocolOpcode,
            { "Protocol Opcode", "matter.protocol_opcode",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_Matter_ExchangeId,
            { "Exchange Id", "matter.exchange_id",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_Matter_ExchangeStartFrameNum,
            { "Start of exchange in frame", "matter.exchange_start_frame",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_NONE), 0x0, NULL, HFILL }
        },
        { &hf_Matter_ProtocolId,
            { "Protocol Id", "matter.protocol_id",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_Matter_ProtocolVendorId,
            { "Protocol Vendor Id", "matter.protocol_vendor_id",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_Matter_AckMsgCntr,
            { "Acknowledged Message Counter", "matter.ack_counter",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_Matter_AckMsgFrameNum,
            { "Acknowledges message in frame", "matter.ack_frame",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_ACK), 0x0, NULL, HFILL }
        },
        { &hf_Matter_AckedByFrameNum,
            { "Acknowledged by message in frame", "matter.acked_by_frame",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_NONE), 0x0, NULL, HFILL }
        },
        { &hf_Matter_RetransFrameNum,
            { "Retransmission of message in frame", "matter.retrans_frame",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_NONE), 0x0, NULL, HFILL }
        },
        { &hf_Matter_MsgCntrReuseFrameNum,
            { "Reuses message counter of message in frame", "matter.message_id_reuse_frame",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_NONE), 0x0, NULL, HFILL }
        },
        { &hf_Matter_Payload,
            { "Payload", "matter.payload",
            FT_BYTES, SEP_SPACE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_Matter_EncData,
            { "Encrypted Data", "matter.enc_data",
            FT_BYTES, SEP_SPACE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_Matter_IntegrityCheck,
            { "Integrity Check", "matter.integ_check",
            FT_BYTES, SEP_SPACE, NULL, 0x0, NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_matter
    };

    proto_matter = proto_register_protocol("Matter Message Format", "Matter", "matter");

    proto_register_field_array(proto_matter, hf, array_length(hf));

    proto_register_subtree_array(ett, array_length(ett));

    matter_subdissector_table = register_dissector_table("matter.profile_id", "Matter Profile", proto_matter, FT_UINT32, BASE_HEX);

    register_conversation_filter("matter", "Matter Exchange", MatterExchangeFilter_IsValid, MatterExchangeFilter_BuildFilterString);

    module_t *prefs_matter = prefs_register_protocol(proto_matter, NULL);

    prefs_register_bool_preference(prefs_matter,
            "show_node_ids", "Show node ids",
            "Show source and destination node ids in the packet information column",
            &pref_ShowNodeIds);

    register_init_routine(InitMatterDissector);

    UserEncryptionKeyPrefs::Init(prefs_matter);

    MessageEncryptionKeyTable::Init();
}

void
proto_reg_handoff_matter(void)
{
    static dissector_handle_t matterUDPHandle;
    static dissector_handle_t matterTCPHandle;

    ip_handle = find_dissector("ip");

    matterUDPHandle = create_dissector_handle(DissectMatter, proto_matter);
    dissector_add_uint("udp.port", MATTER_PORT, matterUDPHandle);

    matterTCPHandle = create_dissector_handle(DissectMatterTCP, proto_matter);
    dissector_add_uint("tcp.port", MATTER_PORT, matterTCPHandle);

    InitMatterDissector();
}

void plugin_register(void)
{
    static proto_plugin plugin_matter;
    static proto_plugin plugin_matter_common;
    static proto_plugin plugin_matter_echo;
    static proto_plugin plugin_matter_security;
    static proto_plugin plugin_matter_im;

    plugin_matter.register_protoinfo = proto_register_matter;
    plugin_matter.register_handoff = proto_reg_handoff_matter;
    proto_register_plugin(&plugin_matter);

    plugin_matter_common.register_protoinfo = proto_register_matter_common;
    plugin_matter_common.register_handoff = proto_reg_handoff_matter_common;
    proto_register_plugin(&plugin_matter_common);

    plugin_matter_echo.register_protoinfo = proto_register_matter_echo;
    plugin_matter_echo.register_handoff = proto_reg_handoff_matter_echo;
    proto_register_plugin(&plugin_matter_echo);

    plugin_matter_security.register_protoinfo = proto_register_matter_security;
    plugin_matter_security.register_handoff = proto_reg_handoff_matter_security;
    proto_register_plugin(&plugin_matter_security);

    plugin_matter_im.register_protoinfo = proto_register_matter_im;
    plugin_matter_im.register_handoff = proto_reg_handoff_matter_im;
    proto_register_plugin(&plugin_matter_im);
}

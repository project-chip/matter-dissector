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

#include <Matter/Core/MatterCore.h>
#include <Matter/Protocols/MatterProfiles.h>
#include <Matter/Protocols/common/CommonProfile.h>
#include <Matter/Protocols/security/MatterCASE.h>
#include <Matter/Support/MatterNames.h>
#include <Matter/Support/CodeUtils.h>
#include <Matter/Support/ErrorStr.h>

#include "packet-matter.h"

#include "TLVDissector.h"
#include "MatterMessageTracker.h"

using namespace matter;
using namespace matter::TLV;
using namespace matter::Profiles;
using namespace matter::Profiles::Common;
using namespace matter::Profiles::Security;

extern void AssociateWithIMSubscription(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, MatterMessageRecord *msgRec);

static int proto_MatterCommon = -1;

static int ett_MatterCommon = -1;

static int hf_StatusReport_ProfileId = -1;
static int hf_StatusReport_StatusCode = -1;
static int hf_StatusReport_TLV = -1;
static int hf_StatusReport_IsError = -1;

//static int ett_PBKDFParamRequest = -1;

//static int hf_PBKDFParamRequest = -1;
static int hf_PBKDFParamRequest_initiatorRandom = -1;
static int hf_PBKDFParamRequest_localSessionId = -1;
static int hf_PBKDFParamRequest_passcodeId = -1;
static int hf_PBKDFParamRequest_hasPbkdfParams = -1;

static int hf_PBKDFParamResponse_responderRandom = -1;
static int hf_PBKDFParamResponse_pbkdfIterationCount = -1;
static int hf_PBKDFParamResponse_pbkdfSaltLength = -1;
static int hf_PBKDFParamResponse_pbkdfSalt = -1;

static int hf_Pake1_pA = -1;
static int hf_Pake2_pB = -1;
static int hf_Pake2_cB = -1;
static int hf_Pake3_cA = -1;

static int hf_Session_destinationId = -1;
static int hf_Session_ephPublicKey = -1;
static int hf_Session_encrypted = -1;

static int
DissectStatusReport(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    proto_item *isErrorItem;
    uint16_t generalCode;
    uint32_t profileId;
    uint16_t statusCode;
    const char *profileName = NULL;
    const char *statusReportStr = NULL;
    int parsePoint = 0;
    bool isError;

    proto_item_append_text(proto_tree_get_parent(tree), ": Status Report");

    // General code
    generalCode = tvb_get_letohs(tvb, parsePoint);
    statusReportStr = matter::StatusReportStr(kMatterProfile_General, generalCode);
    proto_tree_add_uint_format_value(tree, hf_StatusReport_StatusCode, tvb, parsePoint, 2, generalCode, "%s", statusReportStr);
    parsePoint += 2;

    profileId = tvb_get_letohl(tvb, parsePoint);
    profileName = GetProtocolName(profileId);
    proto_tree_add_uint_format_value(tree, hf_StatusReport_ProfileId, tvb, parsePoint, 4, profileId,
            (profileName != NULL) ? "%08X (%s)" : "%08X", profileId, profileName);
    parsePoint += 4;

    statusCode = tvb_get_letohs(tvb, parsePoint);
    statusReportStr = matter::StatusReportStr(profileId, statusCode);
    proto_tree_add_uint_format_value(tree, hf_StatusReport_StatusCode, tvb, parsePoint, 2, statusCode, "%s", statusReportStr);
    parsePoint += 2;

    isError = (statusCode != General::kStatus_SUCCESS);
    col_prepend_fstr(pinfo->cinfo, COL_INFO, "StatusReport (%s) ", (isError) ? "ERROR" : "SUCCESS");

    if (parsePoint < msgInfo.payloadLen) {
        const uint8_t *msgData = (const uint8_t *)tvb_memdup(pinfo->pool, tvb, parsePoint, msgInfo.payloadLen - parsePoint);
        TLVDissector tlvDissector;

        tlvDissector.Init(msgData, msgInfo.payloadLen - parsePoint, parsePoint);

        err = tlvDissector.Next();
        SuccessOrExit(err);

        err = tlvDissector.AddGenericTLVItem(tree, hf_StatusReport_TLV, tvb, false);
        SuccessOrExit(err);
    }

    isErrorItem = proto_tree_add_boolean(tree, hf_StatusReport_IsError, tvb, 0, 0, isError);
    PROTO_ITEM_SET_HIDDEN(isErrorItem);

    AssociateWithIMSubscription(tvb, pinfo, tree, msgInfo.msgRec);

exit:
    return msgInfo.payloadLen;
}

static int
DissectStandaloneAck(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    proto_item_append_text(proto_tree_get_parent(tree), ": StandaloneAck");

    if ((msgInfo.exchHeader & kMatterExchangeFlag_AckId) != 0) {
        col_prepend_fstr(pinfo->cinfo, COL_INFO, "StandAloneACK ");
    }
    else {
        col_prepend_fstr(pinfo->cinfo, COL_INFO, "Null ");
    }

    AssociateWithIMSubscription(tvb, pinfo, tree, msgInfo.msgRec);

    return 1;
}

/**
 * Dissect PASE PBKDF Request message.

pbkdfparamreq-struct => STRUCTURE [ tag-order ]
{
  initiatorRandom    [1] : OCTET STRING [ length 32 ],
  initiatorSessionId [2] : UNSIGNED INTEGER [ range 16-bits ],
  passcodeId         [3] : UNSIGNED INTEGER [ length 16-bits ],
  hasPBKDFParameters [4] : BOOLEAN,
  initiatorMRPParams [5, optional] : mrp-parameter-struct
}

mrp-parameter-struct => STRUCTURE [ tag-order ]
{
  MRP_RETRY_INTERVAL_IDLE    [1, optional] : UNSIGNED INTEGER [ range 16-bits ],
  MRP_RETRY_INTERVAL_ACTIVE  [2, optional] : UNSIGNED INTEGER [ range 16-bits ]
}
*/
static int
DissectPBKDFParamRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    int parsePoint = 0;
    const uint8_t *msgData = (const uint8_t *)tvb_memdup(pinfo->pool, tvb, parsePoint, msgInfo.payloadLen - parsePoint);
    TLVDissector tlvDissector;
    //proto_tree *subTree;

    proto_item_append_text(proto_tree_get_parent(tree), ": PASE PBKDF Param Request");

    tlvDissector.Init(msgData, msgInfo.payloadLen - parsePoint, parsePoint);
    tlvDissector.ImplicitProfileId = kMatterProfile_Common;

    err = tlvDissector.Next();
    SuccessOrExit(err);

    //err = tlvDissector.AddSubTreeItem(tree, hf_PBKDFParamRequest, ett_PBKDFParamRequest, tvb, subTree);
    //SuccessOrExit(err);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true) {

        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV)
            break;
        SuccessOrExit(err);

        uint64_t tag = tlvDissector.GetTag();
        TLVType type = tlvDissector.GetType();

        VerifyOrExit(IsContextTag(tag), err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

        switch (TagNumFromTag(tag)) {
        case 1:
            VerifyOrExit(type == kTLVType_ByteString, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = tlvDissector.AddTypedItem(tree, hf_PBKDFParamRequest_initiatorRandom, tvb);
            SuccessOrExit(err);
            break;
        case 2:
            VerifyOrExit(type == kTLVType_UnsignedInteger, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = tlvDissector.AddTypedItem(tree, hf_PBKDFParamRequest_localSessionId, tvb);
            SuccessOrExit(err);
            break;
        case 3:
            VerifyOrExit(type == kTLVType_UnsignedInteger, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = tlvDissector.AddTypedItem(tree, hf_PBKDFParamRequest_passcodeId, tvb);
            SuccessOrExit(err);
            break;
        case 4:
            VerifyOrExit(type == kTLVType_Boolean, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = tlvDissector.AddTypedItem(tree, hf_PBKDFParamRequest_hasPbkdfParams, tvb);
            SuccessOrExit(err);
            break;
        case 5:
            // TODO: add support for mrp-parameter-struct 
            break;
        default:
            ExitNow(err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
        }
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}

/**
 * Dissect PASE PBKDF Parameter Response message.

pbkdfparamresp-struct => STRUCTURE [ tag-order ]
{
  initiatorRandom    [1] : OCTET STRING [ length 32 ],
  responderRandom    [2] : OCTET STRING [ length 32 ],
  responderSessionId [3] : UNSIGNED INTEGER [ range 16-bits ],
  pbkdf_parameters   [4] : Crypto_PBKDFParameterSet,
  responderMRPParams [5, optional] : mrp-parameter-struct
}

Crypto_PBKDFParameterSet => STRUCTURE [ tag-order ]
{
     iterations [1] : UNSIGNED INTEGER [ range 32-bits ],
     salt [2] : OCTET STRING [ length 16..32 ],
}

mrp-parameter-struct => STRUCTURE [ tag-order ]
{
  MRP_RETRY_INTERVAL_IDLE    [1, optional] : UNSIGNED INTEGER [ range 16-bits ],
  MRP_RETRY_INTERVAL_ACTIVE  [2, optional] : UNSIGNED INTEGER [ range 16-bits ]
}
 */
static int
DissectPBKDFParamResponse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    int parsePoint = 0;
    const uint8_t *msgData = (const uint8_t *)tvb_memdup(pinfo->pool, tvb, parsePoint, msgInfo.payloadLen - parsePoint);
    TLVDissector tlvDissector;

    proto_item_append_text(proto_tree_get_parent(tree), ": PASE PBKDF Param Response");

    tlvDissector.Init(msgData, msgInfo.payloadLen - parsePoint, parsePoint);
    tlvDissector.ImplicitProfileId = kMatterProfile_Common;

    err = tlvDissector.Next();
    SuccessOrExit(err);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true) {

        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV)
            break;
        SuccessOrExit(err);

        uint64_t tag = tlvDissector.GetTag();
        TLVType type = tlvDissector.GetType();

        VerifyOrExit(IsContextTag(tag), err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

        switch (TagNumFromTag(tag)) {
        case 1:
            VerifyOrExit(type == kTLVType_ByteString, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = tlvDissector.AddTypedItem(tree, hf_PBKDFParamRequest_initiatorRandom, tvb);
            SuccessOrExit(err);
            break;
        case 2:
            VerifyOrExit(type == kTLVType_ByteString, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = tlvDissector.AddTypedItem(tree, hf_PBKDFParamResponse_responderRandom, tvb);
            SuccessOrExit(err);
            break;
        case 3:
            VerifyOrExit(type == kTLVType_UnsignedInteger, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = tlvDissector.AddTypedItem(tree, hf_PBKDFParamRequest_localSessionId, tvb);
            SuccessOrExit(err);
            break;
        case 4:
            // TODO: add support for Crypto_PBKDFParameterSet
            break;
        case 5:
            // TODO: add support for mrp-parameter-struct 
            break;
        default:
            ExitNow(err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
        }
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}

/**
 * Dissect PASE Pake1 Message.

pake-1-struct => STRUCTURE [ tag-order ]
{
  pA [1] : OCTET STRING [ length CRYPTO_PUBLIC_KEY_SIZE_BYTES ],
}
 */
static int
DissectPasePake1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    int parsePoint = 0;
    const uint8_t *msgData = (const uint8_t *)tvb_memdup(pinfo->pool, tvb, parsePoint, msgInfo.payloadLen - parsePoint);
    TLVDissector tlvDissector;

    proto_item_append_text(proto_tree_get_parent(tree), ": PASE Pake1");

    tlvDissector.Init(msgData, msgInfo.payloadLen - parsePoint, parsePoint);
    tlvDissector.ImplicitProfileId = kMatterProfile_Common;

    err = tlvDissector.Next();
    SuccessOrExit(err);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true) {

        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV)
            break;
        SuccessOrExit(err);

        uint64_t tag = tlvDissector.GetTag();
        TLVType type = tlvDissector.GetType();

        VerifyOrExit(IsContextTag(tag), err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

        switch (TagNumFromTag(tag)) {
        case 1:
            VerifyOrExit(type == kTLVType_ByteString, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = tlvDissector.AddTypedItem(tree, hf_Pake1_pA, tvb);
            SuccessOrExit(err);
            break;
        default:
            ExitNow(err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
        }
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}

/**
 * Dissect PASE Pake2 message.

pake-2-struct => STRUCTURE [ tag-order ]
{
  pB [1] : OCTET STRING [ length CRYPTO_PUBLIC_KEY_SIZE_BYTES ],
  cB [2] : OCTET STRING [ length CRYPTO_HASH_LEN_BYTES],
}
 */
static int
DissectPasePake2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    int parsePoint = 0;
    const uint8_t *msgData = (const uint8_t *)tvb_memdup(pinfo->pool, tvb, parsePoint, msgInfo.payloadLen - parsePoint);
    TLVDissector tlvDissector;

    proto_item_append_text(proto_tree_get_parent(tree), ": PASE Pake2");

    tlvDissector.Init(msgData, msgInfo.payloadLen - parsePoint, parsePoint);
    tlvDissector.ImplicitProfileId = kMatterProfile_Common;

    err = tlvDissector.Next();
    SuccessOrExit(err);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true) {

        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV)
            break;
        SuccessOrExit(err);

        uint64_t tag = tlvDissector.GetTag();
        TLVType type = tlvDissector.GetType();

        VerifyOrExit(IsContextTag(tag), err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

        switch (TagNumFromTag(tag)) {
        case 1:
            VerifyOrExit(type == kTLVType_ByteString, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = tlvDissector.AddTypedItem(tree, hf_Pake2_pB, tvb);
            SuccessOrExit(err);
            break;
        case 2:
            VerifyOrExit(type == kTLVType_ByteString, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = tlvDissector.AddTypedItem(tree, hf_Pake2_cB, tvb);
            SuccessOrExit(err);
            break;
        default:
            ExitNow(err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
        }
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}

/**
 * Dissect PASE Pake3 message.

pake-3-struct => STRUCTURE [ tag-order ]
{
  cA [1] : OCTET STRING [length CRYPTO_HASH_LEN_BYTES],
}
 */
static int
DissectPasePake3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    int parsePoint = 0;
    const uint8_t *msgData = (const uint8_t *)tvb_memdup(pinfo->pool, tvb, parsePoint, msgInfo.payloadLen - parsePoint);
    TLVDissector tlvDissector;

    proto_item_append_text(proto_tree_get_parent(tree), ": PASE Pake3");

    tlvDissector.Init(msgData, msgInfo.payloadLen - parsePoint, parsePoint);
    tlvDissector.ImplicitProfileId = kMatterProfile_Common;

    err = tlvDissector.Next();
    SuccessOrExit(err);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true) {

        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV)
            break;
        SuccessOrExit(err);

        uint64_t tag = tlvDissector.GetTag();
        TLVType type = tlvDissector.GetType();

        VerifyOrExit(IsContextTag(tag), err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

        switch (TagNumFromTag(tag)) {
        case 1:
            VerifyOrExit(type == kTLVType_ByteString, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = tlvDissector.AddTypedItem(tree, hf_Pake3_cA, tvb);
            SuccessOrExit(err);
            break;
        default:
            ExitNow(err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
        }
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}

/**
sigma-error-enum => UNSIGNED INTEGER [ range 8bits ] {
  NoSharedTrustRoots = 0x01,
  InvalidParameter = 0x02,
}
 */
static int
DissectPasePakeError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    col_prepend_fstr(pinfo->cinfo, COL_INFO, "PASE Spake2 Err ");
    proto_item_append_text(proto_tree_get_parent(tree), ": PASE Spake2 Error");
    return 1;
}


/**
 * Dissect CASE Sigma1 message.

sigma-1-struct => STRUCTURE [ tag-order ]
{
  initiatorRandom    [1] : OCTET STRING [ length 32 ],
  initiatorSessionId [2] : UNSIGNED INTEGER [ range 16-bits ],
  destinationId      [3] : destination-identifier,
  initiatorEphPubKey [4] : ec-pub-key,
  initiatorMRPParams [5, optional] : mrp-parameter-struct,
  resumptionID       [6, optional] : OCTET STRING [ length 16 ],
  initiatorResumeMIC [7, optional] : OCTET STRING [ length CRYPTO_AEAD_MIC_LENGTH_BYTES ]
}
 */
static int
DissectCaseSigma1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    int parsePoint = 0;
    const uint8_t *msgData = (const uint8_t *)tvb_memdup(pinfo->pool, tvb, parsePoint, msgInfo.payloadLen - parsePoint);
    TLVDissector tlvDissector;

    proto_item_append_text(proto_tree_get_parent(tree), ": CASE Sigma1");

    tlvDissector.Init(msgData, msgInfo.payloadLen - parsePoint, parsePoint);
    tlvDissector.ImplicitProfileId = kMatterProfile_Common;

    err = tlvDissector.Next();
    SuccessOrExit(err);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true) {

        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV)
            break;
        SuccessOrExit(err);

        uint64_t tag = tlvDissector.GetTag();
        TLVType type = tlvDissector.GetType();

        VerifyOrExit(IsContextTag(tag), err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

        switch (TagNumFromTag(tag)) {
        case CASE::Sigma1::kTag_InitiatorRandom:
            VerifyOrExit(type == kTLVType_ByteString, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = tlvDissector.AddTypedItem(tree, hf_PBKDFParamRequest_initiatorRandom, tvb);
            SuccessOrExit(err);
            break;
        case CASE::Sigma1::kTag_InitiatorSessionId:
            VerifyOrExit(type == kTLVType_UnsignedInteger, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = tlvDissector.AddTypedItem(tree, hf_PBKDFParamRequest_localSessionId, tvb);
            SuccessOrExit(err);
            break;
        case CASE::Sigma1::kTag_DestinationId:
            VerifyOrExit(type == kTLVType_ByteString, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = tlvDissector.AddTypedItem(tree, hf_Session_destinationId, tvb);
            SuccessOrExit(err);
            break;
        case CASE::Sigma1::kTag_InitiatorEphPubKey:
            VerifyOrExit(type == kTLVType_ByteString, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = tlvDissector.AddTypedItem(tree, hf_Session_ephPublicKey, tvb);
            SuccessOrExit(err);
            break;
        case CASE::Sigma1::kTag_InitiatorSleepyParams:
        case CASE::Sigma1::kTag_ResumptionId:
        case CASE::Sigma1::kTag_InitiatorResumeMic:
            // TODO: add support for optional fields
            err = tlvDissector.AddGenericTLVItem(tree, hf_StatusReport_TLV, tvb, false);
            SuccessOrExit(err);
            break;

        default:
            ExitNow(err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
        }
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}

/**
 * Dissect CASE Sigma2 message.

sigma-2-struct => STRUCTURE [ tag-order ]
{
  responderRandom    [1] : OCTET STRING [ length 32 ],
  responderSessionId [2] : UNSIGNED INTEGER [ range 16-bits ],
  responderEphPubKey [3] : ec-pub-key,
  encrypted2         [4] : OCTET STRING,
  responderMRPParams [5, optional] : mrp-parameter-struct
}
 */
static int
DissectCaseSigma2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    int parsePoint = 0;
    const uint8_t *msgData = (const uint8_t *)tvb_memdup(pinfo->pool, tvb, parsePoint, msgInfo.payloadLen - parsePoint);
    TLVDissector tlvDissector;

    proto_item_append_text(proto_tree_get_parent(tree), ": CASE Sigma2");

    tlvDissector.Init(msgData, msgInfo.payloadLen - parsePoint, parsePoint);
    tlvDissector.ImplicitProfileId = kMatterProfile_Common;

    err = tlvDissector.Next();
    SuccessOrExit(err);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true) {

        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV)
            break;
        SuccessOrExit(err);

        uint64_t tag = tlvDissector.GetTag();
        TLVType type = tlvDissector.GetType();

        VerifyOrExit(IsContextTag(tag), err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

        switch (TagNumFromTag(tag)) {
        case CASE::Sigma2::kTag_ResponderRandom:
            VerifyOrExit(type == kTLVType_ByteString, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = tlvDissector.AddTypedItem(tree, hf_PBKDFParamResponse_responderRandom, tvb);
            SuccessOrExit(err);
            break;
        case CASE::Sigma2::kTag_ResponderSessionId:
            VerifyOrExit(type == kTLVType_UnsignedInteger, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = tlvDissector.AddTypedItem(tree, hf_PBKDFParamRequest_localSessionId, tvb);
            SuccessOrExit(err);
            break;
        case CASE::Sigma2::kTag_ResponderEphPubKey:
            VerifyOrExit(type == kTLVType_ByteString, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = tlvDissector.AddTypedItem(tree, hf_Session_ephPublicKey, tvb);
            SuccessOrExit(err);
            break;
        case CASE::Sigma2::kTag_Encrypted2:
            VerifyOrExit(type == kTLVType_ByteString, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = tlvDissector.AddTypedItem(tree, hf_Session_encrypted, tvb);
            SuccessOrExit(err);
            break;
        case CASE::Sigma2::kTag_ResponderSleepyParams:
            // TODO: add support for optional fields
            err = tlvDissector.AddGenericTLVItem(tree, hf_StatusReport_TLV, tvb, false);
            SuccessOrExit(err);
            break;

        default:
            ExitNow(err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
        }
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}

/**
 * Dissect CASE Sigma1 message.

sigma-3-struct => STRUCTURE [ tag-order ]
{
  encrypted3 [1] : OCTET STRING,
}
 */
static int
DissectCaseSigma3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    int parsePoint = 0;
    const uint8_t *msgData = (const uint8_t *)tvb_memdup(pinfo->pool, tvb, parsePoint, msgInfo.payloadLen - parsePoint);
    TLVDissector tlvDissector;

    proto_item_append_text(proto_tree_get_parent(tree), ": CASE Sigma3");

    tlvDissector.Init(msgData, msgInfo.payloadLen - parsePoint, parsePoint);
    tlvDissector.ImplicitProfileId = kMatterProfile_Common;

    err = tlvDissector.Next();
    SuccessOrExit(err);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true) {

        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV)
            break;
        SuccessOrExit(err);

        uint64_t tag = tlvDissector.GetTag();
        TLVType type = tlvDissector.GetType();

        VerifyOrExit(IsContextTag(tag), err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

        switch (TagNumFromTag(tag)) {
        case CASE::Sigma3::kTag_Encrypted3:
            VerifyOrExit(type == kTLVType_ByteString, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = tlvDissector.AddTypedItem(tree, hf_Session_encrypted, tvb);
            SuccessOrExit(err);
            break;
        default:
            ExitNow(err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
        }
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}

/**
 * Dissect CASE Sigma2 resume message.

sigma-2-resume-struct => STRUCTURE [ tag-order ]
{
  resumptionID       [1] : OCTET STRING [ length 16 ],
  sigma2ResumeMIC    [2] : OCTET STRING [ length 16 ],
  responderSessionID [3] : UNSIGNED INTEGER [ range 16-bits ],
  responderMRPParams [4, optional] : <<Glossary_of_params_MRP, mrp-parameter-struct>>
}
 */
static int
DissectCaseSigma2Resume(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    int parsePoint = 0;
    const uint8_t *msgData = (const uint8_t *)tvb_memdup(pinfo->pool, tvb, parsePoint, msgInfo.payloadLen - parsePoint);
    TLVDissector tlvDissector;

    proto_item_append_text(proto_tree_get_parent(tree), ": CASE Sigma2 Resume");

    tlvDissector.Init(msgData, msgInfo.payloadLen - parsePoint, parsePoint);
    tlvDissector.ImplicitProfileId = kMatterProfile_Common;

    err = tlvDissector.Next();
    SuccessOrExit(err);

    err = tlvDissector.EnterContainer();
    SuccessOrExit(err);

    while (true) {

        err = tlvDissector.Next();
        if (err == MATTER_END_OF_TLV)
            break;
        SuccessOrExit(err);

        uint64_t tag = tlvDissector.GetTag();
 
        VerifyOrExit(IsContextTag(tag), err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

        err = tlvDissector.AddGenericTLVItem(tree, hf_StatusReport_TLV, tvb, false);
        SuccessOrExit(err);

        /*
        TLVType type = tlvDissector.GetType();
        switch (TagNumFromTag(tag)) {
        // TODO: add support for parsing specific CASEResume fields
            case 1:
            case 2:
            case 3:
            case 4:
                break;
            default:
                ExitNow(err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
        }
        */
    }

    err = tlvDissector.ExitContainer();
    SuccessOrExit(err);

exit:
    return err;
}


static int
DissectMatterCommon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    const MatterMessageInfo& msgInfo = *(const MatterMessageInfo *)data;

    proto_item *top = proto_tree_add_item(tree, proto_MatterCommon, tvb, 0, -1, ENC_NA);
    proto_tree *common_tree = proto_item_add_subtree(top, ett_MatterCommon);

    switch (msgInfo.msgType) {
    case kMsgType_StatusReport:
        return DissectStatusReport(tvb, pinfo, common_tree, msgInfo);
    case kMsgType_StandaloneAck:
        return DissectStandaloneAck(tvb, pinfo, common_tree, msgInfo);

    // Dissect PASE Messages
    case kMsgType_PBKDFParamRequest:
        return DissectPBKDFParamRequest(tvb, pinfo, common_tree, msgInfo);
    case kMsgType_PBKDFParamResponse:
        return DissectPBKDFParamResponse(tvb, pinfo, common_tree, msgInfo);
    case kMsgType_PASE_Spake2p1:
        return DissectPasePake1(tvb, pinfo, common_tree, msgInfo);
    case kMsgType_PASE_Spake2p2:
        return DissectPasePake2(tvb, pinfo, common_tree, msgInfo);
    case kMsgType_PASE_Spake2p3:
        return DissectPasePake3(tvb, pinfo, common_tree, msgInfo);
    case kMsgType_PASE_Spake2pError:
        return DissectPasePakeError(tvb, pinfo, common_tree, msgInfo);

    // Dissect CASE Messages
    case kMsgType_CASE_Sigma1:
        return DissectCaseSigma1(tvb, pinfo, common_tree, msgInfo);
    case kMsgType_CASE_Sigma2:
        return DissectCaseSigma2(tvb, pinfo, common_tree, msgInfo);
    case kMsgType_CASE_Sigma3:
        return DissectCaseSigma3(tvb, pinfo, common_tree, msgInfo);
    case kMsgType_CASE_Sigma2_Resume:
        return DissectCaseSigma2Resume(tvb, pinfo, common_tree, msgInfo);

    default:
        return 0;
    }
}

void
proto_register_matter_common(void)
{
    static hf_register_info hf[] = {
        { &hf_StatusReport_ProfileId,
            { "Status Profile Id", "matter.status_report.profile_id",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_StatusReport_StatusCode,
            { "Status Code", "matter.status_report.status_code",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_StatusReport_TLV,
            { "TLV", "matter.status_report.tlv",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_StatusReport_IsError,
            { "Is Error", "matter.status_report.is_error",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        /*
        { &hf_PBKDFParamRequest,
            { "PASE PBKDF Param Request", "matter.pase.pbkdf_param_req",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        */
        { &hf_PBKDFParamRequest_initiatorRandom,
            { "Initiator Random", "matter.pase.initiator_random",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_PBKDFParamRequest_localSessionId,
            { "Local Session ID", "matter.pase.local_session_id",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_PBKDFParamRequest_passcodeId,
            { "Passcode ID", "matter.pase.passcode_id",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_PBKDFParamRequest_hasPbkdfParams,
            { "Has PBKDF Parameters", "matter.pase.has_pbkdf_params",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        { &hf_PBKDFParamResponse_responderRandom,
            { "Responder Random", "matter.pase.responder_random",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_PBKDFParamResponse_pbkdfIterationCount,
            { "PBKDF Iterations", "matter.pase.pbkdf_interation_count",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_PBKDFParamResponse_pbkdfSaltLength,
            { "PBKDF Salt Length", "matter.pase.pbkdf_salt_length",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_PBKDFParamResponse_pbkdfSalt,
            { "PBKDF Salt", "matter.pase.salt",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        { &hf_Pake1_pA,
            { "pA", "matter.pase.pake1.pA",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        { &hf_Pake2_pB,
            { "pB", "matter.pase.pake2.pB",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_Pake2_cB,
            { "cB", "matter.pase.pake2.cB",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        { &hf_Pake3_cA,
            { "cA", "matter.pase.pake3.cA",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        { &hf_Session_destinationId,
            { "Destination Node ID", "matter.session.destination_id",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_Session_ephPublicKey,
            { "Ephemeral public key", "matter.session.eph_public_key",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_Session_encrypted,
            { "Encrypted", "matter.session.encrypted",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

    };

    static gint *ett[] = {
        &ett_MatterCommon,
    };

    proto_MatterCommon = proto_register_protocol(
        "Matter Secure Channel Protocol",
        "Matter-Common",
        "matter-common"
    );

    proto_register_field_array(proto_MatterCommon, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_matter_common(void)
{
    static dissector_handle_t matter_common_handle;

    matter_common_handle = create_dissector_handle(DissectMatterCommon, proto_MatterCommon);
    dissector_add_uint("matter.profile_id", kMatterProfile_Common, matter_common_handle);
}

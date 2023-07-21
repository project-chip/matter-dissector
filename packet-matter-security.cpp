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
 * packet-matter-case.cpp
 */

#include <stdio.h>
#include <glib.h>
#include "config.h"

#include <epan/packet.h>

#include <openssl/sha.h>

#include <Matter/Core/MatterCore.h>
#include <Matter/Core/MatterEncoding.h>
#include <Matter/Core/MatterTLV.h>
#include <Matter/Protocols/MatterProfiles.h>
#include <Matter/Protocols/security/MatterCASE.h>
#include <Matter/Support/CodeUtils.h>
#include <Matter/Support/ErrorStr.h>

#include "packet-matter.h"
#include "MatterMessageTracker.h"
#include "TLVDissector.h"
#include "HKDF.h"
#include "MessageEncryptionKey.h"

using namespace matter;
using namespace matter::TLV;
using namespace matter::Encoding;
using namespace matter::Profiles;
using namespace matter::Profiles::Security;
using namespace matter::Profiles::Security::CASE;

#define CASE_MAX_HASH_SIZE SHA256_DIGEST_LENGTH

class CASEExchangeRecord
{
public:
    MatterMessageRecord *beginReqMsg;
    MatterMessageRecord *beginRespMsg;
    MatterMessageRecord *keyConfirmMsg;
    uint32_t config;
    uint32_t curveId;
    uint16_t keyId;
    uint8_t sessionType;
    uint8_t *reqECDHPublicKey;
    size_t reqECDHPublicKeyLen;
    uint8_t *respECDHPublicKey;
    size_t respECDHPublicKeyLen;
    uint8_t reqMsgHash[CASE_MAX_HASH_SIZE];
    uint8_t respMsgHash[CASE_MAX_HASH_SIZE];
    const MessageEncryptionKey *recoveredSessionKey;
};


static int proto_matter_security = -1;

static int ett_matter_security = -1;
static int ett_CASEBeginSessionRequest_AltConfigList = -1;
static int ett_CASEBeginSessionRequest_AltCurveList = -1;
static int ett_CASEBeginSessionRequest_CertInfo = -1;
static int ett_CASEBeginSessionRequest_Signature = -1;
static int ett_CertInfo_RelatedCertsList = -1;
static int ett_CertInfo_TrustAnchorsList = -1;
static int ett_Cert = -1;
static int ett_CertRef = -1;

static int hf_CASEBeginSessionRequest_ControlHeader = -1;
static int hf_CASEBeginSessionRequest_EncType = -1;
static int hf_CASEBeginSessionRequest_PerformKeyConfirmFlag = -1;
static int hf_CASEBeginSessionRequest_ProposedConfig = -1;
static int hf_CASEBeginSessionRequest_ProposedCurve = -1;
static int hf_CASEBeginSessionRequest_ProposedSessionId = -1;
static int hf_CASEBeginSessionRequest_AltConfigList = -1;
static int hf_CASEBeginSessionRequest_AltConfigListElem = -1;
static int hf_CASEBeginSessionRequest_AltCurveList = -1;
static int hf_CASEBeginSessionRequest_AltCurveListElem = -1;
static int hf_CASEBeginSessionRequest_ECDHPublicKey = -1;
static int hf_CASEBeginSessionRequest_CertInfo = -1;
static int hf_CASEBeginSessionRequest_Payload = -1;
static int hf_CASEBeginSessionRequest_Signature = -1;

static int hf_CASEBeginSessionResponse_ControlHeader = -1;
static int hf_CASEBeginSessionResponse_KeyConfirmHashLength = -1;
static int hf_CASEBeginSessionResponse_ECDHPublicKey = -1;
static int hf_CASEBeginSessionResponse_CertInfo = -1;
static int hf_CASEBeginSessionResponse_Payload = -1;
static int hf_CASEBeginSessionResponse_Signature = -1;
static int hf_CASEBeginSessionResponse_KeyConfirmHash = -1;

static int hf_CASEInitiatorKeyConfirm_KeyConfirmHash = -1;

static int hf_CASEReconfigure_ProposedAltConfig = -1;
static int hf_CASEReconfigure_ProposedAltCurve = -1;

static int hf_CertInfo_EntityCert = -1;
static int hf_CertInfo_EntityCertRef = -1;
static int hf_CertInfo_RelatedCertsList = -1;
static int hf_CertInfo_TrustAnchorsList = -1;

static int hf_Cert = -1;

static int hf_CertRef = -1;

static int hf_ECDSASig_r = -1;
static int hf_ECDSASig_s = -1;

static int hf_MessageCounterSyncResp_RequestMessageId = -1;

static int hf_KeyError_SessionId = -1;
static int hf_KeyError_EncType = -1;
static int hf_KeyError_MsgCntr = -1;
static int hf_KeyError_StatusCode = -1;

const value_string sessionTypeNames[] = {
    { kMatterSessionType_Unicast, "Unicast Session" },
    { kMatterSessionType_Group, "Group Session" },
    { 0, NULL }
};

static const value_string caseConfigNames[] = {
    { kCASEConfig_Config1, "Config1" },
    { kCASEConfig_Config2, "Config2" },
    { 0, NULL }
};

static const value_string matterCurveNames[] = {
    { kMatterCurveId_secp160r1,  "secp160r1"  },
    { kMatterCurveId_prime192v1, "prime192v1" },
    { kMatterCurveId_secp224r1,  "secp224r1"  },
    { kMatterCurveId_prime256v1, "prime256v1" },
    { 0, NULL }
};


static void
ComputeCASEMessageHash(tvbuff_t *tvb, uint16_t msgLenWithoutSig, uint32_t config, uint8_t *hashBuf)
{
    uint8_t *msgWithoutSig = (uint8_t *)tvb_memdup(NULL, tvb, 0, msgLenWithoutSig);

    if (config == kCASEConfig_Config1) {
        SHA_CTX hash;
        SHA1_Init(&hash);
        SHA1_Update(&hash, msgWithoutSig, msgLenWithoutSig);
        SHA1_Final(hashBuf, &hash);
    }
    else {
        SHA256_CTX hash;
        SHA256_Init(&hash);
        SHA256_Update(&hash, msgWithoutSig, msgLenWithoutSig);
        SHA256_Final(hashBuf, &hash);
    }

    wmem_free(NULL, msgWithoutSig);
}

static bool
IsCurveGenerator(uint32_t curveId, const uint8_t *encodedPoint, size_t encodedPointLen)
{
    static const uint8_t prime192v1_G[] = {
        0x04,
        0x18, 0x8d, 0xa8, 0x0e, 0xb0, 0x30, 0x90, 0xf6, 0x7c, 0xbf, 0x20, 0xeb, 0x43, 0xa1, 0x88, 0x00,
        0xf4, 0xff, 0x0a, 0xfd, 0x82, 0xff, 0x10, 0x12,
        0x07, 0x19, 0x2b, 0x95, 0xff, 0xc8, 0xda, 0x78, 0x63, 0x10, 0x11, 0xed, 0x6b, 0x24, 0xcd, 0xd5,
        0x73, 0xf9, 0x77, 0xa1, 0x1e, 0x79, 0x48, 0x11
    };
    static const uint8_t secp224r1_G[] = {
        0x04,
        0xb7, 0x0e, 0x0c, 0xbd, 0x6b, 0xb4, 0xbf, 0x7f, 0x32, 0x13, 0x90, 0xb9, 0x4a, 0x03, 0xc1, 0xd3,
        0x56, 0xc2, 0x11, 0x22, 0x34, 0x32, 0x80, 0xd6, 0x11, 0x5c, 0x1d, 0x21,
        0xbd, 0x37, 0x63, 0x88, 0xb5, 0xf7, 0x23, 0xfb, 0x4c, 0x22, 0xdf, 0xe6, 0xcd, 0x43, 0x75, 0xa0,
        0x5a, 0x07, 0x47, 0x64, 0x44, 0xd5, 0x81, 0x99, 0x85, 0x00, 0x7e, 0x34
    };
    static const uint8_t prime256v1_G[] = {
        0x04,
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
        0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
        0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5
    };

    switch (curveId) {
    case kMatterCurveId_prime192v1:
        return encodedPointLen == sizeof(prime192v1_G) && memcmp(encodedPoint, prime192v1_G, sizeof(prime192v1_G)) == 0;
    case kMatterCurveId_secp224r1:
        return encodedPointLen == sizeof(secp224r1_G) && memcmp(encodedPoint, secp224r1_G, sizeof(secp224r1_G)) == 0;
    case kMatterCurveId_prime256v1:
        return encodedPointLen == sizeof(prime256v1_G) && memcmp(encodedPoint, prime256v1_G, sizeof(prime256v1_G)) == 0;
    default:
        return false;
    }
}

static CASEExchangeRecord *
FindCASEExchangeRecord(MatterMessageRecord *msg)
{
    while (msg != NULL) {
        if (msg->caseExchangeRec != NULL)
            return msg->caseExchangeRec;
        msg = msg->prevByExchange;
    }
    return NULL;
}

static const MessageEncryptionKey *
DeriveCASESessionKey(CASEExchangeRecord *caseExchangeRec, const uint8_t *sharedSecret, size_t sharedSecretLen)
{
    MessageEncryptionKey keyData;
    uint8_t salt[CASE_MAX_HASH_SIZE * 2];
    uint8_t masterKey[CASE_MAX_HASH_SIZE];
    uint8_t sessionKeyData[kDataEncKeyLength_AES128CCM + CASE_MAX_HASH_SIZE];
    const EVP_MD *hashAlgo;
    size_t hashLen, masterKeyLen;

    if (caseExchangeRec->sessionType != kMatterEncryptionType_AES128CCM)
        return NULL;

    hashAlgo = (caseExchangeRec->config == kCASEConfig_Config1) ? EVP_sha1() : EVP_sha256();
    hashLen = EVP_MD_size(hashAlgo);

    memcpy(salt, caseExchangeRec->reqMsgHash, hashLen);
    memcpy(salt + hashLen, caseExchangeRec->respMsgHash, hashLen);

    if (!HKDF_extract(hashAlgo, salt, hashLen * 2, sharedSecret, sharedSecretLen, masterKey, &masterKeyLen))
        return NULL;

    if (!HKDF_expand(hashAlgo, masterKey, masterKeyLen, NULL, 0, sessionKeyData, sizeof(sessionKeyData)))
        return NULL;

    memset(&keyData, 0, sizeof(keyData));
    keyData.keyId = caseExchangeRec->keyId;
    keyData.sessionType = caseExchangeRec->sessionType;
    keyData.dataEncKey = (char *)sessionKeyData;
    keyData.dataEncKeyLen = kDataEncKeyLength_AES128CCM;

    return MessageEncryptionKeyTable::AddKey(keyData);
}

static void
RecoverCASESessionKey(CASEExchangeRecord *caseExchangeRec)
{
    const uint8_t *sharedSecret;
    size_t sharedSecretLen;

    // Only Config1 and Config2 supported.
    if (caseExchangeRec->config != kCASEConfig_Config1 && caseExchangeRec->config != kCASEConfig_Config2)
        return;

    // Only prime192v1, secp224r1 and prime256v1 curves supported.
    if (caseExchangeRec->curveId != kMatterCurveId_prime192v1 && caseExchangeRec->curveId != kMatterCurveId_secp224r1 && caseExchangeRec->curveId != kMatterCurveId_prime256v1)
        return;

    // Sanity check that both public keys are the same length.
    if (caseExchangeRec->reqECDHPublicKeyLen != caseExchangeRec->respECDHPublicKeyLen)
        return;

    // If either the initiator or responder are using the curve generator (G) value for the ECDH public key,
    // then the shared secret is the X value of the peer's public key.
    if (IsCurveGenerator(caseExchangeRec->curveId, caseExchangeRec->reqECDHPublicKey, caseExchangeRec->reqECDHPublicKeyLen)) {
        sharedSecret = caseExchangeRec->respECDHPublicKey + 1;
    }
    else if (IsCurveGenerator(caseExchangeRec->curveId, caseExchangeRec->respECDHPublicKey, caseExchangeRec->respECDHPublicKeyLen)) {
        sharedSecret = caseExchangeRec->reqECDHPublicKey + 1;
    }

    // Otherwise, neither party is using a well-known key, so session key recovery isn't possible.
    else
        return;

    sharedSecretLen = (caseExchangeRec->reqECDHPublicKeyLen - 1) / 2;

    caseExchangeRec->recoveredSessionKey = DeriveCASESessionKey(caseExchangeRec, sharedSecret, sharedSecretLen);
}

static MATTER_ERROR
AddCert(TLVDissector& tlvDissector, proto_tree *tree, tvbuff_t* tvb, int hfindex)
{
    MATTER_ERROR err;

    // TODO: implement proper cert dissector

    err = tlvDissector.AddGenericTLVItem(tree, hfindex, tvb, true);
    SuccessOrExit(err);

exit:
    return err;
}

static MATTER_ERROR
AddCert(TLVDissector& tlvDissector, proto_tree *tree, tvbuff_t* tvb)
{
    return AddCert(tlvDissector, tree, tvb, hf_Cert);
}


static MATTER_ERROR
AddCertRef(TLVDissector& tlvDissector, proto_tree *tree, tvbuff_t* tvb, int hfindex)
{
    MATTER_ERROR err;

    // TODO: implement proper cert ref dissector

    err = tlvDissector.AddGenericTLVItem(tree, hfindex, tvb, true);
    SuccessOrExit(err);

exit:
    return err;
}

static MATTER_ERROR
AddCertRef(TLVDissector& tlvDissector, proto_tree *tree, tvbuff_t* tvb)
{
    return AddCertRef(tlvDissector, tree, tvb, hf_CertRef);
}

static MATTER_ERROR
AddCertInfo(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int certInfoOffset, int certInfoLen, int hfindex, int ett)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    const uint8_t *certInfoData = (const uint8_t *)tvb_memdup(pinfo->pool, tvb, certInfoOffset, certInfoLen);
    TLVDissector tlvDissector;
    proto_tree *certInfoTree;

    tlvDissector.Init(certInfoData, certInfoLen, certInfoOffset);
    tlvDissector.ImplicitProfileId = kMatterProfile_Security;

    err = tlvDissector.Next(kTLVType_Structure, ProfileTag(kMatterProfile_Security, kTag_MatterCASECertificateInformation));
    SuccessOrExit(err);

    err = tlvDissector.AddSubTreeItem(tree, hfindex, ett, tvb, certInfoTree);
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
        case kTag_CASECertificateInfo_EntityCertificate:
            VerifyOrExit(type == kTLVType_Structure, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = AddCert(tlvDissector, certInfoTree, tvb, hf_CertInfo_EntityCert);
            SuccessOrExit(err);
            break;
        case kTag_CASECertificateInfo_EntityCertificateRef:
            VerifyOrExit(type == kTLVType_Structure, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = AddCertRef(tlvDissector, certInfoTree, tvb, hf_CertInfo_EntityCertRef);
            SuccessOrExit(err);
            break;
        case kTag_CASECertificateInfo_RelatedCertificates:
            VerifyOrExit(type == kTLVType_Path, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = tlvDissector.AddListItem(certInfoTree, hf_CertInfo_RelatedCertsList, ett_CertInfo_RelatedCertsList, tvb, AddCert);
            SuccessOrExit(err);
            break;
        case kTag_CASECertificateInfo_TrustAnchors:
            VerifyOrExit(type == kTLVType_Path, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = tlvDissector.AddListItem(certInfoTree, hf_CertInfo_RelatedCertsList, ett_CertInfo_RelatedCertsList, tvb, AddCertRef);
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

static MATTER_ERROR
AddECDSASig(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int sigOffset, int sigLen, int hfindex, int ett)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    const uint8_t *sigData = (const uint8_t *)tvb_memdup(pinfo->pool, tvb, sigOffset, sigLen);
    TLVDissector tlvDissector;
    proto_tree *sigTree;

    tlvDissector.Init(sigData, sigLen, sigOffset);
    tlvDissector.ImplicitProfileId = kMatterProfile_Security;

    err = tlvDissector.Next(kTLVType_Structure, ProfileTag(kMatterProfile_Security, kTag_MatterCASESignature));
    SuccessOrExit(err);

    err = tlvDissector.AddSubTreeItem(tree, hfindex, ett, tvb, sigTree);
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
        case kTag_ECDSASignature_r:
            VerifyOrExit(type == kTLVType_ByteString, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = tlvDissector.AddTypedItem(sigTree, hf_ECDSASig_r, tvb);
            SuccessOrExit(err);
            break;
        case kTag_ECDSASignature_s:
            VerifyOrExit(type == kTLVType_ByteString, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            err = tlvDissector.AddTypedItem(sigTree, hf_ECDSASig_s, tvb);
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

static int
DissectCASEBeginSessionRequest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    MATTER_ERROR err;
    int parsePoint = 0, ecdhPublicKeyOffset;
    uint8_t proposedEncType, altConfigCount, altCurveCount, ecdhPublicKeyLen;
    uint16_t proposedSessionId, certInfoLen, payloadLen, msgLenWithoutSig, sigLen;
    uint32_t proposedConfig, proposedCurveId;

    proto_item_append_text(proto_tree_get_parent(tree), ": CASE Begin Session Request");

    VerifyOrExit(msgInfo.payloadLen > 18, err = MATTER_ERROR_MESSAGE_INCOMPLETE);

    proposedEncType = tvb_get_guint8(tvb, parsePoint) & kCASEHeader_EncryptionTypeMask;
    proto_tree_add_item(tree, hf_CASEBeginSessionRequest_ControlHeader, tvb, parsePoint, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_CASEBeginSessionRequest_EncType, tvb, parsePoint, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_CASEBeginSessionRequest_PerformKeyConfirmFlag, tvb, parsePoint, 1, ENC_LITTLE_ENDIAN);
    parsePoint += 1;

    altConfigCount = tvb_get_guint8(tvb, parsePoint);
    parsePoint += 1;

    altCurveCount = tvb_get_guint8(tvb, parsePoint);
    parsePoint += 1;

    ecdhPublicKeyLen = tvb_get_guint8(tvb, parsePoint);
    parsePoint += 1;

    certInfoLen = tvb_get_letohs(tvb, parsePoint);
    parsePoint += 2;

    payloadLen = tvb_get_letohs(tvb, parsePoint);
    parsePoint += 2;

    proposedConfig = tvb_get_letohl(tvb, parsePoint);
    proto_tree_add_item(tree, hf_CASEBeginSessionRequest_ProposedConfig, tvb, parsePoint, 4, ENC_LITTLE_ENDIAN);
    parsePoint += 4;

    proposedCurveId = tvb_get_letohl(tvb, parsePoint);
    proto_tree_add_item(tree, hf_CASEBeginSessionRequest_ProposedCurve, tvb, parsePoint, 4, ENC_LITTLE_ENDIAN);
    parsePoint += 4;

    proposedSessionId = tvb_get_letohs(tvb, parsePoint);
    proto_tree_add_item(tree, hf_CASEBeginSessionRequest_ProposedSessionId, tvb, parsePoint, 2, ENC_LITTLE_ENDIAN);
    parsePoint += 2;

    msgLenWithoutSig = 18 + (altConfigCount * 4) + (altCurveCount * 4) + ecdhPublicKeyLen + certInfoLen + payloadLen;
    VerifyOrExit(msgInfo.payloadLen > msgLenWithoutSig, err = MATTER_ERROR_MESSAGE_INCOMPLETE);

    sigLen = msgInfo.payloadLen - msgLenWithoutSig;

    {
        proto_item *list = proto_tree_add_item(tree, hf_CASEBeginSessionRequest_AltConfigList, tvb, parsePoint, (altConfigCount * 4), ENC_NA);
        proto_tree *listTree = proto_item_add_subtree(list, ett_CASEBeginSessionRequest_AltConfigList);

        for (uint8_t i = 0; i < altConfigCount; i++) {
            proto_tree_add_item(listTree, hf_CASEBeginSessionRequest_AltConfigListElem, tvb, parsePoint, 4, ENC_LITTLE_ENDIAN);
            parsePoint += 4;
        }

        proto_item_append_text(list, " (%d)", (int)altConfigCount);
    }

    {
        proto_item *list = proto_tree_add_item(tree, hf_CASEBeginSessionRequest_AltCurveList, tvb, parsePoint, (altConfigCount * 4), ENC_NA);
        proto_tree *listTree = proto_item_add_subtree(list, ett_CASEBeginSessionRequest_AltCurveList);

        for (uint8_t i = 0; i < altCurveCount; i++) {
            proto_tree_add_item(listTree, hf_CASEBeginSessionRequest_AltCurveListElem, tvb, parsePoint, 4, ENC_LITTLE_ENDIAN);
            parsePoint += 4;
        }

        proto_item_append_text(list, " (%d)", (int)altCurveCount);
    }

    ecdhPublicKeyOffset = parsePoint;
    proto_tree_add_bytes_item(tree, hf_CASEBeginSessionRequest_ECDHPublicKey, tvb, parsePoint, ecdhPublicKeyLen, ENC_LITTLE_ENDIAN, NULL, NULL, NULL);
    parsePoint += ecdhPublicKeyLen;

    if (certInfoLen > 0) {
        err = AddCertInfo(tree, tvb, pinfo, parsePoint, certInfoLen, hf_CASEBeginSessionRequest_CertInfo, ett_CASEBeginSessionRequest_CertInfo);
        SuccessOrExit(err);
        parsePoint += certInfoLen;
    }

    if (payloadLen > 0) {
        proto_tree_add_bytes_item(tree, hf_CASEBeginSessionRequest_Payload, tvb, parsePoint, payloadLen, ENC_LITTLE_ENDIAN, NULL, NULL, NULL);
        parsePoint += payloadLen;
    }

    if (sigLen > 0) {
        err = AddECDSASig(tree, tvb, pinfo, parsePoint, sigLen, hf_CASEBeginSessionRequest_Signature, ett_CASEBeginSessionRequest_Signature);
        SuccessOrExit(err);
    }

    if (msgInfo.msgRec->caseExchangeRec == NULL) {

        CASEExchangeRecord *caseExchangeRec = wmem_new(wmem_file_scope(), CASEExchangeRecord);
        memset(caseExchangeRec, 0, sizeof(*caseExchangeRec));

        msgInfo.msgRec->caseExchangeRec = caseExchangeRec;
        caseExchangeRec->beginReqMsg = msgInfo.msgRec;

        caseExchangeRec->config = proposedConfig;
        caseExchangeRec->curveId = proposedCurveId;
        caseExchangeRec->sessionType = proposedEncType;
        caseExchangeRec->keyId = proposedSessionId;

        caseExchangeRec->reqECDHPublicKey = (uint8_t *)tvb_memdup(wmem_file_scope(), tvb, ecdhPublicKeyOffset, ecdhPublicKeyLen);
        caseExchangeRec->reqECDHPublicKeyLen = ecdhPublicKeyLen;

        ComputeCASEMessageHash(tvb, msgLenWithoutSig, proposedConfig, caseExchangeRec->reqMsgHash);
    }

exit:
    (void)err;
    return msgInfo.payloadLen;
}


static int
DissectCASEBeginSessionResponse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    MATTER_ERROR err;
    int parsePoint = 0, ecdhPublicKeyOffset;
    uint8_t controlHeader, ecdhPublicKeyLen;
    uint16_t certInfoLen, payloadLen, keyConfirmHashLen, signedMsgLen, msgLenWithoutSig, sigLen;

    proto_item_append_text(proto_tree_get_parent(tree), ": CASE Begin Session Response");

    VerifyOrExit(msgInfo.payloadLen > 6, err = MATTER_ERROR_MESSAGE_INCOMPLETE);

    controlHeader = tvb_get_guint8(tvb, parsePoint);

    switch (controlHeader & kCASEHeader_KeyConfirmHashLengthMask) {
    case kCASEKeyConfirmHashLength_0Bytes:
        keyConfirmHashLen = 0;
        break;
    case kCASEKeyConfirmHashLength_20Bytes:
        keyConfirmHashLen = 20;
        break;
    case kCASEKeyConfirmHashLength_32Bytes:
        keyConfirmHashLen = 32;
        break;
    default:
        ExitNow(err = MATTER_ERROR_INVALID_ARGUMENT);
    }

    proto_tree_add_item(tree, hf_CASEBeginSessionRequest_ControlHeader, tvb, parsePoint, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_uint_format_value(tree, hf_CASEBeginSessionResponse_KeyConfirmHashLength, tvb, parsePoint, 1, (controlHeader & kCASEHeader_KeyConfirmHashLengthMask), "%u", keyConfirmHashLen);
    parsePoint += 1;

    ecdhPublicKeyLen = tvb_get_guint8(tvb, parsePoint);
    parsePoint += 1;

    certInfoLen = tvb_get_letohs(tvb, parsePoint);
    parsePoint += 2;

    payloadLen = tvb_get_letohs(tvb, parsePoint);
    parsePoint += 2;

    signedMsgLen = 6 + ecdhPublicKeyLen + certInfoLen + payloadLen;
    msgLenWithoutSig = signedMsgLen + keyConfirmHashLen;
    VerifyOrExit(msgInfo.payloadLen > msgLenWithoutSig, err = MATTER_ERROR_MESSAGE_INCOMPLETE);

    sigLen = msgInfo.payloadLen - msgLenWithoutSig;

    ecdhPublicKeyOffset = parsePoint;
    proto_tree_add_bytes_item(tree, hf_CASEBeginSessionResponse_ECDHPublicKey, tvb, parsePoint, ecdhPublicKeyLen, ENC_LITTLE_ENDIAN, NULL, NULL, NULL);
    parsePoint += ecdhPublicKeyLen;

    if (certInfoLen > 0) {
        err = AddCertInfo(tree, tvb, pinfo, parsePoint, certInfoLen, hf_CASEBeginSessionResponse_CertInfo, ett_CASEBeginSessionRequest_CertInfo);
        SuccessOrExit(err);
        parsePoint += certInfoLen;
    }

    if (payloadLen > 0) {
        proto_tree_add_bytes_item(tree, hf_CASEBeginSessionResponse_Payload, tvb, parsePoint, payloadLen, ENC_LITTLE_ENDIAN, NULL, NULL, NULL);
        parsePoint += payloadLen;
    }

    if (sigLen > 0) {
        err = AddECDSASig(tree, tvb, pinfo, parsePoint, sigLen, hf_CASEBeginSessionResponse_Signature, ett_CASEBeginSessionRequest_Signature);
        SuccessOrExit(err);
        parsePoint += sigLen;
    }

    if (keyConfirmHashLen > 0) {
        proto_tree_add_bytes_item(tree, hf_CASEBeginSessionResponse_KeyConfirmHash, tvb, parsePoint, keyConfirmHashLen, ENC_LITTLE_ENDIAN, NULL, NULL, NULL);
        parsePoint += keyConfirmHashLen;
    }

    if (msgInfo.msgRec->caseExchangeRec == NULL) {

        CASEExchangeRecord *caseExchangeRec = FindCASEExchangeRecord(msgInfo.msgRec);

        if (caseExchangeRec != NULL) {

            msgInfo.msgRec->caseExchangeRec = caseExchangeRec;
            caseExchangeRec->beginRespMsg = msgInfo.msgRec;

            caseExchangeRec->respECDHPublicKey = (uint8_t *)tvb_memdup(wmem_file_scope(), tvb, ecdhPublicKeyOffset, ecdhPublicKeyLen);
            caseExchangeRec->respECDHPublicKeyLen = ecdhPublicKeyLen;

            ComputeCASEMessageHash(tvb, signedMsgLen, caseExchangeRec->config, caseExchangeRec->respMsgHash);

            RecoverCASESessionKey(caseExchangeRec);
        }
    }

exit:
    (void)err;
    return msgInfo.payloadLen;
}


static int
DissectCASEInitiatorKeyConfirm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    MATTER_ERROR err;
    int parsePoint = 0;
    uint16_t keyConfirmHashLen = msgInfo.payloadLen;

    proto_item_append_text(proto_tree_get_parent(tree), ": CASE Initiator Key Confirm");

    VerifyOrExit(msgInfo.payloadLen >= 20, err = MATTER_ERROR_MESSAGE_INCOMPLETE);

    proto_tree_add_bytes_item(tree, hf_CASEBeginSessionResponse_KeyConfirmHash, tvb, parsePoint, keyConfirmHashLen, ENC_LITTLE_ENDIAN, NULL, NULL, NULL);

    if (msgInfo.msgRec->caseExchangeRec == NULL) {
        CASEExchangeRecord *caseExchangeRec = FindCASEExchangeRecord(msgInfo.msgRec);
        if (caseExchangeRec != NULL) {
            msgInfo.msgRec->caseExchangeRec = caseExchangeRec;
            caseExchangeRec->keyConfirmMsg = msgInfo.msgRec;
        }
    }

exit:
    (void)err;
    return msgInfo.payloadLen;
}


static int
DissectCASEReconfigure(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    MATTER_ERROR err;
    int parsePoint = 0;

    proto_item_append_text(proto_tree_get_parent(tree), ": CASE Reconfigure");

    VerifyOrExit(msgInfo.payloadLen == 8, err = MATTER_ERROR_MESSAGE_INCOMPLETE);

    proto_tree_add_item(tree, hf_CASEReconfigure_ProposedAltConfig, tvb, parsePoint, 4, ENC_LITTLE_ENDIAN);
    parsePoint += 4;

    proto_tree_add_item(tree, hf_CASEReconfigure_ProposedAltCurve, tvb, parsePoint, 4, ENC_LITTLE_ENDIAN);
    parsePoint += 4;

exit:
    (void)err;
    return msgInfo.payloadLen;
}

static int
DissectMessageCounterSyncResp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    MATTER_ERROR err;
    int parsePoint = 0;

    proto_item_append_text(proto_tree_get_parent(tree), ": Message Counter Sync Response");

    VerifyOrExit(msgInfo.payloadLen == 4, err = MATTER_ERROR_MESSAGE_INCOMPLETE);

    proto_tree_add_item(tree, hf_MessageCounterSyncResp_RequestMessageId, tvb, parsePoint, 4, ENC_LITTLE_ENDIAN);
    parsePoint += 4;

exit:
    (void)err;
    return msgInfo.payloadLen;
}

static int
DissectKeyError(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, const MatterMessageInfo& msgInfo)
{
    MATTER_ERROR err;
    uint16_t statusCode;
    const char *statusReportStr = NULL;
    int parsePoint = 0;

    proto_item_append_text(proto_tree_get_parent(tree), ": Key Error");

    VerifyOrExit(msgInfo.payloadLen == 9, err = MATTER_ERROR_MESSAGE_INCOMPLETE);

    proto_tree_add_item(tree, hf_KeyError_SessionId, tvb, parsePoint, 2, ENC_LITTLE_ENDIAN);
    parsePoint += 2;

    proto_tree_add_item(tree, hf_KeyError_EncType, tvb, parsePoint, 1, ENC_LITTLE_ENDIAN);
    parsePoint += 1;

    proto_tree_add_item(tree, hf_KeyError_MsgCntr, tvb, parsePoint, 4, ENC_LITTLE_ENDIAN);
    parsePoint += 4;

    statusCode = tvb_get_letohs(tvb, parsePoint);
    statusReportStr = matter::StatusReportStr(kMatterProfile_Security, statusCode);
    proto_tree_add_uint_format_value(tree, hf_KeyError_StatusCode, tvb, parsePoint, 2, statusCode, "%s", statusReportStr);
    parsePoint += 2;

exit:
    (void)err;
    return msgInfo.payloadLen;
}

static int
DissectMatterSecurity(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    const MatterMessageInfo& msgInfo = *(const MatterMessageInfo *)data;

    AddMessageTypeToInfoColumn(pinfo, msgInfo);

    proto_item *top = proto_tree_add_item(tree, proto_matter_security, tvb, 0, -1, ENC_NA);
    proto_tree *security_tree = proto_item_add_subtree(top, ett_matter_security);

    switch (msgInfo.msgType) {
    case kMsgType_CASEBeginSessionRequest:
        return DissectCASEBeginSessionRequest(tvb, pinfo, security_tree, msgInfo);
    case kMsgType_CASEBeginSessionResponse:
        return DissectCASEBeginSessionResponse(tvb, pinfo, security_tree, msgInfo);
    case kMsgType_CASEInitiatorKeyConfirm:
        return DissectCASEInitiatorKeyConfirm(tvb, pinfo, security_tree, msgInfo);
    case kMsgType_CASEReconfigure:
        return DissectCASEReconfigure(tvb, pinfo, security_tree, msgInfo);
    case kMsgType_MsgCounterSyncResp:
        return DissectMessageCounterSyncResp(tvb, pinfo, security_tree, msgInfo);
    case kMsgType_KeyError:
        return DissectKeyError(tvb, pinfo, security_tree, msgInfo);
    default:
        return 0;
    }
}

void
proto_register_matter_security(void)
{
    static hf_register_info hf[] = {
        { &hf_CASEBeginSessionRequest_ControlHeader,
            { "Control Header", "matter.case.begin_session_request.control_header",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CASEBeginSessionRequest_EncType,
            { "Proposed Session Type", "matter.case.begin_session_request.enc_type",
            FT_UINT8, BASE_DEC, VALS(sessionTypeNames), 0x0F, NULL, HFILL }
        },
        { &hf_CASEBeginSessionRequest_PerformKeyConfirmFlag,
            { "Perform Key Confirmation", "matter.case.begin_session_request.perform_key_confirm",
            FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }
        },
        { &hf_CASEBeginSessionRequest_ProposedConfig,
            { "Proposed Config", "matter.case.begin_session_request.proposed_config",
            FT_UINT16, BASE_HEX, VALS(caseConfigNames), 0, NULL, HFILL }
        },
        { &hf_CASEBeginSessionRequest_ProposedCurve,
            { "Proposed ECDH Curve", "matter.case.begin_session_request.proposed_curve",
            FT_UINT16, BASE_HEX, VALS(matterCurveNames), 0, NULL, HFILL }
        },
        { &hf_CASEBeginSessionRequest_ProposedSessionId,
            { "Proposed Session Id", "matter.case.begin_session_request.proposed_key_id",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CASEBeginSessionRequest_AltConfigList,
            { "Alternate Config List", "matter.case.begin_session_request.alt_config_list",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CASEBeginSessionRequest_AltConfigListElem,
            { "Config", "matter.case.begin_session_request.alt_config_list.config",
            FT_UINT16, BASE_HEX, VALS(caseConfigNames), 0, NULL, HFILL }
        },
        { &hf_CASEBeginSessionRequest_AltCurveList,
            { "Alternate ECDH Curve List", "matter.case.begin_session_request.alt_curve_list",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CASEBeginSessionRequest_AltCurveListElem,
            { "Curve", "matter.case.begin_session_request.alt_curve_list.curve",
            FT_UINT16, BASE_HEX, VALS(matterCurveNames), 0, NULL, HFILL }
        },
        { &hf_CASEBeginSessionRequest_ECDHPublicKey,
            { "ECDH Public Key", "matter.case.begin_session_request.ecdh_public_key",
            FT_BYTES, SEP_SPACE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CASEBeginSessionRequest_CertInfo,
            { "Certificate Info", "matter.case.begin_session_request.cert_info",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CASEBeginSessionRequest_Payload,
            { "Payload", "matter.case.begin_session_request.payload",
            FT_BYTES, SEP_SPACE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CASEBeginSessionRequest_Signature,
            { "Signature", "matter.case.begin_session_request.signature",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        { &hf_ECDSASig_r,
            { "R", "matter.ecdsa_signature.r",
            FT_BYTES, SEP_SPACE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_ECDSASig_s,
            { "S", "matter.ecdsa_signature.s",
            FT_BYTES, SEP_SPACE, NULL, 0x0, NULL, HFILL }
        },

        { &hf_CertInfo_EntityCert,
            { "Entity Certificate", "matter.cert_info.entity_certificate",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CertInfo_EntityCertRef,
            { "Entity Certificate Reference", "matter.cert_info.entity_certificate_ref",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CertInfo_RelatedCertsList,
            { "Related Certificates", "matter.cert_info.related_certificates",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CertInfo_TrustAnchorsList,
            { "Trust Anchors", "matter.cert_info.trust_anchors",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        { &hf_Cert,
            { "Certificate", "matter.cert",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        { &hf_CertRef,
            { "Certificate Reference", "matter.cert_ref",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },


        { &hf_CASEBeginSessionResponse_ControlHeader,
            { "Control Header", "matter.case.begin_session_response.control_header",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CASEBeginSessionResponse_KeyConfirmHashLength,
            { "Key Confirmation Hash Length", "matter.case.begin_session_response.key_confirm_hash_len",
            FT_UINT8, BASE_DEC, NULL, 0xC0, NULL, HFILL }
        },
        { &hf_CASEBeginSessionResponse_ECDHPublicKey,
            { "ECDH Public Key", "matter.case.begin_session_response.ecdh_public_key",
            FT_BYTES, SEP_SPACE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CASEBeginSessionResponse_CertInfo,
            { "Certificate Info", "matter.case.begin_session_response.cert_info",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CASEBeginSessionResponse_Payload,
            { "Payload", "matter.case.begin_session_response.payload",
            FT_BYTES, SEP_SPACE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CASEBeginSessionResponse_KeyConfirmHash,
            { "Key Confirmation Hash", "matter.case.begin_session_response.key_confirm_hash",
            FT_BYTES, SEP_SPACE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_CASEBeginSessionResponse_Signature,
            { "Signature", "matter.case.begin_session_response.signature",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        { &hf_CASEInitiatorKeyConfirm_KeyConfirmHash,
            { "Key Confirmation Hash", "matter.case.initiator_key_confirm.key_confirm_hash",
            FT_BYTES, SEP_SPACE, NULL, 0x0, NULL, HFILL }
        },


        { &hf_CASEReconfigure_ProposedAltConfig,
            { "Proposed Alternate Config", "matter.case.reconfigure.proposed_alt_config",
            FT_UINT16, BASE_HEX, VALS(caseConfigNames), 0, NULL, HFILL }
        },
        { &hf_CASEReconfigure_ProposedAltCurve,
            { "Proposed Alternate ECDH Curve", "matter.case.begin_session_request.proposed_alt_curve",
            FT_UINT16, BASE_HEX, VALS(matterCurveNames), 0, NULL, HFILL }
        },

        { &hf_MessageCounterSyncResp_RequestMessageId,
            { "Request Message Counter", "matter.message_counter_sync_response.request_message_id",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },

        { &hf_KeyError_SessionId,
            { "Session Id", "matter.key_error.key_id",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_KeyError_EncType,
            { "Session Type", "matter.key_error.enc_type",
            FT_UINT8, BASE_DEC, VALS(sessionTypeNames), 0x0, NULL, HFILL }
        },
        { &hf_KeyError_MsgCntr,
            { "Message Counter", "matter.key_error.message_id",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_KeyError_StatusCode,
            { "Status Code", "matter.key_error.status_code",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_matter_security,
        &ett_CASEBeginSessionRequest_AltConfigList,
        &ett_CASEBeginSessionRequest_AltCurveList,
        &ett_CASEBeginSessionRequest_CertInfo,
        &ett_CASEBeginSessionRequest_Signature,
        &ett_CertInfo_RelatedCertsList,
        &ett_CertInfo_TrustAnchorsList,
        &ett_Cert,
        &ett_CertRef,
    };

    proto_matter_security = proto_register_protocol(
        "Matter Security",
        "Matter-Security",
        "matter-security"
    );

    proto_register_field_array(proto_matter_security, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_matter_security(void)
{
    static dissector_handle_t matter_security_handle;

    matter_security_handle = create_dissector_handle(DissectMatterSecurity, proto_matter_security);
    dissector_add_uint("matter.profile_id", kMatterProfile_Security, matter_security_handle);
}


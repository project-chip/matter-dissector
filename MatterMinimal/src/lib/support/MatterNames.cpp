/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

/**
 *    @file
 *      This file defines functions for converting various ids into human-readable strings.
 *
 */

#include <stdlib.h>

#include <Matter/Core/MatterCore.h>
#include <Matter/Protocols/MatterProfiles.h>
#include <Matter/Protocols/common/CommonProfile.h>
#include <Matter/Protocols/echo/MatterEcho.h>
#include <Matter/Protocols/network-provisioning/NetworkProvisioning.h>
#include <Matter/Protocols/security/MatterSecurity.h>
#include <Matter/Protocols/fabric-provisioning/FabricProvisioning.h>
#include <Matter/Protocols/device-control/DeviceControl.h>
#include <Matter/Protocols/time/MatterTime.h>
#include <Matter/Protocols/interaction-model/MessageDef.h>
#include <Matter/Protocols/software-update/SoftwareUpdateProfile.h>
#include <Matter/Protocols/bulk-data-transfer/BulkDataTransfer.h>
#include <Matter/Protocols/bulk-data-transfer/Development/BDXConstants.h>
#include <Matter/Protocols/device-description/DeviceDescription.h>
#include <Matter/Protocols/service-provisioning/ServiceProvisioning.h>

namespace matter {

using namespace matter::Profiles;

const char *GetVendorName(uint16_t vendorId)
{
    switch (vendorId) {
    case kMatterVendor_Common                                                : return "Common";
    case kMatterVendor_NestLabs                                              : return "Nest";
    }

    return NULL;
}

const char *GetProtocolName(uint32_t profileId)
{
    switch (profileId) {
    case kMatterProfile_Common                                               : return "Session";
    case kMatterProfile_InteractionModel                                     : return "Action";
    case kMatterProfile_BDX                                                  : return "BDX (Bulk Data Exchange)";
    case kMatterProfile_UDC                                                  : return "UDC (User Directed Commissioning)";
    case kMatterProfile_Echo                                                 : return "Echo";

    //case kMatterProfile_NetworkProvisioning                                  : return "NetworkProvisioning";
    case kMatterProfile_Security                                             : return "Security";
    case kMatterProfile_FabricProvisioning                                   : return "FabricProvisioning";
    case kMatterProfile_DeviceControl                                        : return "DeviceControl";
    case kMatterProfile_Time                                                 : return "Time";
    case kMatterProfile_IM                                                   : return "IM";
    case kMatterProfile_SWU                                                  : return "SWU";
    case kMatterProfile_DeviceDescription                                    : return "DeviceDescription";
    case kMatterProfile_ServiceProvisioning                                  : return "ServiceProvisioning";
    case kMatterProfile_Locale                                               : return "Locale";
    case kMatterProfile_DictionaryKey                                        : return "DictionaryKey";

    }

    return NULL;
}

const char *GetMessageName(uint32_t profileId, uint8_t msgType)
{
    switch (profileId) {
    case kMatterProfile_Common:
        switch (msgType) {
        case Common::kMsgType_StatusReport                                  : return "StatusReport";
        case Common::kMsgType_StandaloneAck                                 : return "StandaloneAck";

        case Common::kMsgType_MsgCounterSyncReq                             : return "MsgCounterSyncReq";
        case Common::kMsgType_MsgCounterSyncRsp                             : return "MsgCounterSyncRsp";

        case Common::kMsgType_PBKDFParamRequest                             : return "PBKDFParamRequest";
        case Common::kMsgType_PBKDFParamResponse                            : return "PBKDFParamResponse";
        case Common::kMsgType_PASE_Spake2p1                                 : return "PASE_Spake2p1";
        case Common::kMsgType_PASE_Spake2p2                                 : return "PASE_Spake2p2";
        case Common::kMsgType_PASE_Spake2p3                                 : return "PASE_Spake2p3";
        case Common::kMsgType_PASE_Spake2pError                             : return "PASE_Spake2pError";

        case Common::kMsgType_CASE_Sigma1                                   : return "CASE_Sigma1";
        case Common::kMsgType_CASE_Sigma2                                   : return "CASE_Sigma2";
        case Common::kMsgType_CASE_Sigma3                                   : return "CASE_Sigma3";
        case Common::kMsgType_CASE_Sigma2_Resume                            : return "CASE_Sigma2_Resume";
        }
        break;

    case kMatterProfile_InteractionModel:
        switch (msgType) {
        case InteractionModel::kMsgType_StatusResponse                      : return "StatusResponse";
        case InteractionModel::kMsgType_ReadRequest                         : return "ReadRequest";
        case InteractionModel::kMsgType_SubscribeRequest                    : return "SubscribeRequest";
        case InteractionModel::kMsgType_SubscribeResponse                   : return "SubscribeResponse";
        case InteractionModel::kMsgType_ReportData                          : return "ReportData";
        case InteractionModel::kMsgType_WriteRequest                        : return "WriteRequest";
        case InteractionModel::kMsgType_WriteResponse                       : return "WriteResponse";
        case InteractionModel::kMsgType_InvokeRequest                       : return "InvokeCommandRequest";
        case InteractionModel::kMsgType_InvokeResponse                      : return "InvokeCommandResponse";
        case InteractionModel::kMsgType_TimedRequest                        : return "TimedRequest";
        }
        break;

    case kMatterProfile_Echo:
        switch (msgType) {
        case kEchoMessageType_EchoRequest                                   : return "EchoRequest";
        case kEchoMessageType_EchoResponse                                  : return "EchoResponse";
        }
        break;



    case kMatterProfile_NetworkProvisioning:
        switch (msgType) {
        case NetworkProvisioning::kMsgType_ScanNetworks                     : return "ScanNetworks";
        case NetworkProvisioning::kMsgType_NetworkScanComplete              : return "NetworkScanComplete";
        case NetworkProvisioning::kMsgType_AddNetwork                       : return "AddNetwork";
        case NetworkProvisioning::kMsgType_AddNetworkComplete               : return "AddNetworkComplete";
        case NetworkProvisioning::kMsgType_UpdateNetwork                    : return "UpdateNetwork";
        case NetworkProvisioning::kMsgType_RemoveNetwork                    : return "RemoveNetwork";
        case NetworkProvisioning::kMsgType_EnableNetwork                    : return "EnableNetwork";
        case NetworkProvisioning::kMsgType_DisableNetwork                   : return "DisableNetwork";
        case NetworkProvisioning::kMsgType_TestConnectivity                 : return "TestConnectivity";
        case NetworkProvisioning::kMsgType_SetRendezvousMode                : return "SetRendezvousMode";
        case NetworkProvisioning::kMsgType_GetNetworks                      : return "GetNetworks";
        case NetworkProvisioning::kMsgType_GetNetworksComplete              : return "GetNetworksComplete";
        case NetworkProvisioning::kMsgType_GetLastResult                    : return "GetLastResult";
        }
        break;
    case kMatterProfile_Security:
        switch (msgType) {
        case Security::kMsgType_PASEInitiatorStep1                          : return "PASEInitiatorStep1";
        case Security::kMsgType_PASEResponderStep1                          : return "PASEResponderStep1";
        case Security::kMsgType_PASEResponderStep2                          : return "PASEResponderStep2";
        case Security::kMsgType_PASEInitiatorStep2                          : return "PASEInitiatorStep2";
        case Security::kMsgType_PASEResponderKeyConfirm                     : return "PASEResponderKeyConfirm";
        case Security::kMsgType_PASEResponderReconfigure                    : return "PASEReconfigure";
        case Security::kMsgType_CASEBeginSessionRequest                     : return "CASEBeginSessionRequest";
        case Security::kMsgType_CASEBeginSessionResponse                    : return "CASEBeginSessionResponse";
        case Security::kMsgType_CASEInitiatorKeyConfirm                     : return "CASEInitiatorKeyConfirm";
        case Security::kMsgType_CASEReconfigure                             : return "CASEReconfigure";
        case Security::kMsgType_EndSession                                  : return "EndSession";
        case Security::kMsgType_KeyError                                    : return "KeyError";
        case Security::kMsgType_MsgCounterSyncResp                          : return "MessageCounterSyncResponse";
        }
        break;
    case kMatterProfile_FabricProvisioning:
        switch (msgType) {
        case FabricProvisioning::kMsgType_CreateFabric                      : return "CreateFabric";
        case FabricProvisioning::kMsgType_LeaveFabric                       : return "LeaveFabric";
        case FabricProvisioning::kMsgType_GetFabricConfig                   : return "GetFabricConfig";
        case FabricProvisioning::kMsgType_GetFabricConfigComplete           : return "GetFabricConfigComplete";
        case FabricProvisioning::kMsgType_JoinExistingFabric                : return "JoinExistingFabric";
        }
        break;
    case kMatterProfile_DeviceControl:
        switch (msgType) {
        case DeviceControl::kMsgType_ResetConfig                            : return "ResetConfig";
        case DeviceControl::kMsgType_ArmFailSafe                            : return "ArmFailSafe";
        case DeviceControl::kMsgType_DisarmFailSafe                         : return "DisarmFailSafe";
        case DeviceControl::kMsgType_EnableConnectionMonitor                : return "EnableConnectionMonitor";
        case DeviceControl::kMsgType_DisableConnectionMonitor               : return "DisableConnectionMonitor";
        case DeviceControl::kMsgType_RemotePassiveRendezvous                : return "RemotePassiveRendezvous";
        case DeviceControl::kMsgType_RemoteConnectionComplete               : return "RemoteConnectionComplete";
        case DeviceControl::kMsgType_StartSystemTest                        : return "StartSystemTest";
        case DeviceControl::kMsgType_StopSystemTest                         : return "StopSystemTest";
        }
        break;
    case kMatterProfile_Time:
        switch (msgType) {
        case Time::kTimeMessageType_TimeSyncTimeChangeNotification          : return "TimeSyncTimeChangeNotification";
        case Time::kTimeMessageType_TimeSyncRequest                         : return "TimeSyncRequest";
        case Time::kTimeMessageType_TimeSyncResponse                        : return "TimeSyncResponse";
        }
        break;
    case kMatterProfile_SWU:
        switch (msgType) {
        case SoftwareUpdate::kMsgType_ImageAnnounce                         : return "ImageAnnounce";
        case SoftwareUpdate::kMsgType_ImageQuery                            : return "ImageQuery";
        case SoftwareUpdate::kMsgType_ImageQueryResponse                    : return "ImageQueryResponse";
        case SoftwareUpdate::kMsgType_DownloadNotify                        : return "DownloadNotify";
        case SoftwareUpdate::kMsgType_NotifyRepsponse                       : return "NotifyRepsponse";
        case SoftwareUpdate::kMsgType_UpdateNotify                          : return "UpdateNotify";
        case SoftwareUpdate::kMsgType_ImageQueryStatus                      : return "ImageQueryStatus";
        }
        break;
    case kMatterProfile_BDX:
        switch (msgType) {
        case BDX_Development::kMsgType_SendInit                             : return "SendInit";
        case BDX_Development::kMsgType_SendAccept                           : return "SendAccept";
        case BDX_Development::kMsgType_SendReject                           : return "SendReject";
        case BDX_Development::kMsgType_ReceiveInit                          : return "ReceiveInit";
        case BDX_Development::kMsgType_ReceiveAccept                        : return "ReceiveAccept";
        case BDX_Development::kMsgType_ReceiveReject                        : return "ReceiveReject";
        case BDX_Development::kMsgType_BlockQuery                           : return "BlockQuery";
        case BDX_Development::kMsgType_BlockSend                            : return "BlockSend";
        case BDX_Development::kMsgType_BlockEOF                             : return "BlockEOF";
        case BDX_Development::kMsgType_BlockAck                             : return "BlockAck";
        case BDX_Development::kMsgType_BlockEOFAck                          : return "BlockEOFAck";
        case BDX_Development::kMsgType_TransferError                        : return "TransferError";
        case BDX_Development::kMsgType_BlockQueryV1                         : return "BlockQueryV1";
        case BDX_Development::kMsgType_BlockSendV1                          : return "BlockSendV1";
        case BDX_Development::kMsgType_BlockEOFV1                           : return "BlockEOFV1";
        case BDX_Development::kMsgType_BlockAckV1                           : return "BlockAckV1";
        case BDX_Development::kMsgType_BlockEOFAckV1                        : return "BlockEOFAckV1";
        }
        break;
    case kMatterProfile_DeviceDescription:
        switch (msgType) {
        case DeviceDescription::kMessageType_IdentifyRequest                : return "IdentifyRequest";
        case DeviceDescription::kMessageType_IdentifyResponse               : return "IdentifyResponse";
        }
        break;
    case kMatterProfile_ServiceProvisioning:
        switch (msgType) {
        case ServiceProvisioning::kMsgType_RegisterServicePairAccount       : return "RegisterServicePairAccount";
        case ServiceProvisioning::kMsgType_UpdateService                    : return "UpdateService";
        case ServiceProvisioning::kMsgType_UnregisterService                : return "UnregisterService";
        case ServiceProvisioning::kMsgType_UnpairDeviceFromAccount          : return "UnpairDeviceFromAccount";
        case ServiceProvisioning::kMsgType_PairDeviceToAccount              : return "PairDeviceToAccount";
        }
        break;
    }

    return NULL;
}

} // namespace matter

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
 *      This file...
 *
 */

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <inttypes.h>
#include <stdio.h>

#include <Matter/Core/MatterCore.h>
#include <Matter/Protocols/MatterProfiles.h>
#include <Matter/Protocols/common/CommonProfile.h>
#include <Matter/Protocols/bulk-data-transfer/BulkDataTransfer.h>
#include <Matter/Protocols/interaction-model/MessageDef.h>
#include <Matter/Protocols/device-control/DeviceControl.h>
#include <Matter/Protocols/fabric-provisioning/FabricProvisioning.h>
#include <Matter/Protocols/network-provisioning/NetworkProvisioning.h>
#include <Matter/Protocols/security/MatterSecurity.h>
#include <Matter/Protocols/software-update/SoftwareUpdateProfile.h>
#include <Matter/Protocols/service-provisioning/ServiceProvisioning.h>

namespace matter {

using namespace matter::Profiles;

#if MATTER_CONFIG_SHORT_ERROR_STR

/**
 * static buffer to store the short version of error string for status report
 * "0x", 32-bit profile id in hex, ' ', "0x", 16-bit status code in hex, '\0'
 * An example would be "0xDEADBEEF,0xABCD"
 */
static char sErrorStr[2 + 8 + 1 + 2 + 4 + 1];

const char *StatusReportStr(uint32_t profileId, uint16_t statusCode)
{
    // note that snprintf in theory could return a negative number to indicate error, but in general matter doesn't check for very unlikely error conditions
    // snprintf could also return a number that is greater than (num_char_left - 1) to indicate the string has been truncated. refer to the previous line
    (void)snprintf(sErrorStr, sizeof(sErrorStr), "0x%" PRIx32 " 0x%" PRIx16, profileId, statusCode);
    return sErrorStr;
}

#else

static char sErrorStr[1024];

const char *StatusReportStr(uint32_t profileId, uint16_t statusCode)
{
    const char *fmt = NULL;

    switch (profileId)
    {
    case kMatterProfile_BDX:
        switch (statusCode)
        {
        case BulkDataTransfer::kStatus_Overflow                                         : fmt = "[ BDX(%08" PRIX32 "):%" PRIu16 " ] Overflow"; break;
        case BulkDataTransfer::kStatus_LengthTooShort                                   : fmt = "[ BDX(%08" PRIX32 "):%" PRIu16 " ] Length too short"; break;
        case BulkDataTransfer::kStatus_XferFailedUnknownErr                             : fmt = "[ BDX(%08" PRIX32 "):%" PRIu16 " ] Transfer failed for unknown reason"; break;
        case BulkDataTransfer::kStatus_XferMethodNotSupported                           : fmt = "[ BDX(%08" PRIX32 "):%" PRIu16 " ] Transfer method not supported"; break;
        case BulkDataTransfer::kStatus_UnknownFile                                      : fmt = "[ BDX(%08" PRIX32 "):%" PRIu16 " ] Unknown file"; break;
        case BulkDataTransfer::kStatus_StartOffsetNotSupported                          : fmt = "[ BDX(%08" PRIX32 "):%" PRIu16 " ] Start offset not support"; break;
        case BulkDataTransfer::kStatus_Unknown                                          : fmt = "[ BDX(%08" PRIX32 "):%" PRIu16 " ] Unknown error"; break;
        default                                                                         : fmt = "[ BDX(%08" PRIX32 "):%" PRIu16 " ]"; break;
        }
        break;

    case kMatterProfile_General:
        switch (statusCode)
        {
        case matter::Profiles::General::kStatus_SUCCESS             : fmt = "[ General:%2$" PRIu16 " ] Success"; break;
        case matter::Profiles::General::kStatus_FAILURE             : fmt = "[ General:%2$" PRIu16 " ] Failure"; break;
        case matter::Profiles::General::kStatus_BAD_PRECONDITION    : fmt = "[ General:%2$" PRIu16 " ] Bad Precondition"; break;
        case matter::Profiles::General::kStatus_OUT_OF_RANGE        : fmt = "[ General:%2$" PRIu16 " ] Out of Range"; break;
        case matter::Profiles::General::kStatus_BAD_REQUEST         : fmt = "[ General:%2$" PRIu16 " ] Bad Request"; break;
        case matter::Profiles::General::kStatus_UNSUPPORTED         : fmt = "[ General:%2$" PRIu16 " ] Unsupported"; break;
        case matter::Profiles::General::kStatus_UNEXPECTED          : fmt = "[ General:%2$" PRIu16 " ] Unexpected"; break;
        case matter::Profiles::General::kStatus_RESOURCE_EXHAUSTED  : fmt = "[ General:%2$" PRIu16 " ] Resource Exhausted"; break;
        case matter::Profiles::General::kStatus_BUSY                : fmt = "[ General:%2$" PRIu16 " ] Busy"; break;
        case matter::Profiles::General::kStatus_TIMEOUT             : fmt = "[ General:%2$" PRIu16 " ] Timeout"; break;
        case matter::Profiles::General::kStatus_CONTINUE            : fmt = "[ General:%2$" PRIu16 " ] Continue"; break;
        case matter::Profiles::General::kStatus_ABORTED             : fmt = "[ General:%2$" PRIu16 " ] Aborted"; break;
        case matter::Profiles::General::kStatus_INVALID_ARGUMENT    : fmt = "[ General:%2$" PRIu16 " ] Invalid Argument"; break;
        case matter::Profiles::General::kStatus_NOT_FOUND           : fmt = "[ General:%2$" PRIu16 " ] Not Found"; break;
        case matter::Profiles::General::kStatus_ALREADY_EXISTS      : fmt = "[ General:%2$" PRIu16 " ] Already Exists"; break;
        case matter::Profiles::General::kStatus_PERMISSION_DENIED   : fmt = "[ General:%2$" PRIu16 " ] Permission Denied"; break;
        case matter::Profiles::General::kStatus_DATA_LOSS           : fmt = "[ General:%2$" PRIu16 " ] Data Loss"; break;
        default                                                     : fmt = "[ General:%2$" PRIu16 " ]"; break;
        }
        break;

    case kMatterProfile_Common:
        switch (statusCode)
        {
        case matter::Profiles::Common::kStatus_SESSION_ESTABLISHMENT_SUCCESS  : fmt = "[ Session:%2$" PRIu16 " ] Session Establishment Success"; break;
        case matter::Profiles::Common::kStatus_NO_SHARED_TRUST_ROOTS          : fmt = "[ Session:%2$" PRIu16 " ] No Shared Trust Roots"; break;
        case matter::Profiles::Common::kStatus_INVALID_PARAMETER              : fmt = "[ Session:%2$" PRIu16 " ] Invalid Parameter"; break;
        case matter::Profiles::Common::kStatus_CLOSE_SESSION                  : fmt = "[ Session:%2$" PRIu16 " ] Close Session"; break;
        case matter::Profiles::Common::kStatus_BUSY                           : fmt = "[ Session:%2$" PRIu16 " ] Busy"; break;
        case matter::Profiles::Common::kStatus_SESSION_NOT_FOUND              : fmt = "[ Session:%2$" PRIu16 " ] Session Not Found"; break;
        default                                                               : fmt = "[ Session:%2$" PRIu16 " ]"; break;
        }
        break;

    case kMatterProfile_IM:
        switch (statusCode)
	    {
        case InteractionModel::kStatus_InvalidValueInNotification             : fmt = "[ IM(%08" PRIX32 "):%" PRIu16 " ] Invalid valid in notification"; break;
        case InteractionModel::kStatus_InvalidPath                            : fmt = "[ IM(%08" PRIX32 "):%" PRIu16 " ] Invalid path"; break;
        case InteractionModel::kStatus_ExpiryTimeNotSupported                 : fmt = "[ IM(%08" PRIX32 "):%" PRIu16 " ] Expiry time not supported"; break;
        case InteractionModel::kStatus_NotTimeSyncedYet                       : fmt = "[ IM(%08" PRIX32 "):%" PRIu16 " ] Time not synchronized"; break;
        case InteractionModel::kStatus_RequestExpiredInTime                   : fmt = "[ IM(%08" PRIX32 "):%" PRIu16 " ] Request expired"; break;
        case InteractionModel::kStatus_VersionMismatch                        : fmt = "[ IM(%08" PRIX32 "):%" PRIu16 " ] Version mismatch"; break;
        case InteractionModel::kStatus_GeneralProtocolError                   : fmt = "[ IM(%08" PRIX32 "):%" PRIu16 " ] General protocol error"; break;
        case InteractionModel::kStatus_SecurityError                          : fmt = "[ IM(%08" PRIX32 "):%" PRIu16 " ] Security error"; break;
        case InteractionModel::kStatus_InvalidSubscriptionID                  : fmt = "[ IM(%08" PRIX32 "):%" PRIu16 " ] Invalid subscription ID"; break;
        case InteractionModel::kStatus_GeneralSchemaViolation                 : fmt = "[ IM(%08" PRIX32 "):%" PRIu16 " ] General schema violation"; break;
        default                                                               : fmt = "[ IM(%08" PRIX32 "):%" PRIu16 " ]"; break;
        }
	break;

    case kMatterProfile_DeviceControl:
        switch (statusCode)
        {
        case DeviceControl::kStatusCode_FailSafeAlreadyActive                           : fmt = "[ DeviceControl(%08" PRIX32 "):%" PRIu16 " ] Fail-safe already active"; break;
        case DeviceControl::kStatusCode_NoFailSafeActive                                : fmt = "[ DeviceControl(%08" PRIX32 "):%" PRIu16 " ] No fail-safe active"; break;
        case DeviceControl::kStatusCode_NoMatchingFailSafeActive                        : fmt = "[ DeviceControl(%08" PRIX32 "):%" PRIu16 " ] No matching fail-safe active"; break;
        case DeviceControl::kStatusCode_UnsupportedFailSafeMode                         : fmt = "[ DeviceControl(%08" PRIX32 "):%" PRIu16 " ] Unsupported fail-safe mode"; break;
        default                                                                         : fmt = "[ DeviceControl(%08" PRIX32 "):%" PRIu16 " ]"; break;
        }
        break;

    case kMatterProfile_DeviceDescription:
        switch (statusCode)
        {
        default                                                                         : fmt = "[ DeviceDescription(%08" PRIX32 "):%" PRIu16 " ]"; break;
        }
        break;

    case kMatterProfile_Echo:
        switch (statusCode)
        {
        default                                                                         : fmt = "[ Echo(%08" PRIX32 "):%" PRIu16 " ]"; break;
        }
        break;

    case kMatterProfile_FabricProvisioning:
        switch (statusCode)
        {
        case FabricProvisioning::kStatusCode_AlreadyMemberOfFabric                      : fmt = "[ FabricProvisioning(%08" PRIX32 "):%" PRIu16 " ] Already member of fabric"; break;
        case FabricProvisioning::kStatusCode_NotMemberOfFabric                          : fmt = "[ FabricProvisioning(%08" PRIX32 "):%" PRIu16 " ] Not member of fabric"; break;
        case FabricProvisioning::kStatusCode_InvalidFabricConfig                        : fmt = "[ FabricProvisioning(%08" PRIX32 "):%" PRIu16 " ] Invalid fabric config"; break;
        default                                                                         : fmt = "[ FabricProvisioning(%08" PRIX32 "):%" PRIu16 " ]"; break;
        }
        break;

    case kMatterProfile_NetworkProvisioning:
        switch (statusCode)
        {
        case NetworkProvisioning::kStatusCode_UnknownNetwork                            : fmt = "[ NetworkProvisioning(%08" PRIX32 "):%" PRIu16 " ] Unknown network"; break;
        case NetworkProvisioning::kStatusCode_TooManyNetworks                           : fmt = "[ NetworkProvisioning(%08" PRIX32 "):%" PRIu16 " ] Too many networks"; break;
        case NetworkProvisioning::kStatusCode_InvalidNetworkConfiguration               : fmt = "[ NetworkProvisioning(%08" PRIX32 "):%" PRIu16 " ] Invalid network configuration"; break;
        case NetworkProvisioning::kStatusCode_UnsupportedNetworkType                    : fmt = "[ NetworkProvisioning(%08" PRIX32 "):%" PRIu16 " ] Unsupported network configuration"; break;
        case NetworkProvisioning::kStatusCode_UnsupportedWiFiMode                       : fmt = "[ NetworkProvisioning(%08" PRIX32 "):%" PRIu16 " ] Unsupported WiFi mode"; break;
        case NetworkProvisioning::kStatusCode_UnsupportedWiFiRole                       : fmt = "[ NetworkProvisioning(%08" PRIX32 "):%" PRIu16 " ] Unsupported WiFi role"; break;
        case NetworkProvisioning::kStatusCode_UnsupportedWiFiSecurityType               : fmt = "[ NetworkProvisioning(%08" PRIX32 "):%" PRIu16 " ] Unsupported WiFi security type"; break;
        case NetworkProvisioning::kStatusCode_InvalidState                              : fmt = "[ NetworkProvisioning(%08" PRIX32 "):%" PRIu16 " ] Invalid state"; break;
        case NetworkProvisioning::kStatusCode_TestNetworkFailed                         : fmt = "[ NetworkProvisioning(%08" PRIX32 "):%" PRIu16 " ] Test network failed"; break;
        default                                                                         : fmt = "[ NetworkProvisioning(%08" PRIX32 "):%" PRIu16 " ]"; break;
        }
        break;

    case kMatterProfile_Security:
        switch (statusCode)
        {
        case Security::kStatusCode_SessionAborted                                       : fmt = "[ Security(%08" PRIX32 "):%" PRIu16 " ] Session aborted"; break;
        case Security::kStatusCode_PASESupportsOnlyConfig1                              : fmt = "[ Security(%08" PRIX32 "):%" PRIu16 " ] PASE Engine only supports Config1"; break;
        case Security::kStatusCode_UnsupportedEncryptionType                            : fmt = "[ Security(%08" PRIX32 "):%" PRIu16 " ] Unsupported encryption type"; break;
        case Security::kStatusCode_InvalidSessionId                                         : fmt = "[ Security(%08" PRIX32 "):%" PRIu16 " ] Invalid key id"; break;
        case Security::kStatusCode_DuplicateSessionId                                       : fmt = "[ Security(%08" PRIX32 "):%" PRIu16 " ] Duplicate key id"; break;
        case Security::kStatusCode_KeyConfirmationFailed                                : fmt = "[ Security(%08" PRIX32 "):%" PRIu16 " ] Key confirmation failed"; break;
        case Security::kStatusCode_InternalError                                        : fmt = "[ Security(%08" PRIX32 "):%" PRIu16 " ] Internal error"; break;
        case Security::kStatusCode_AuthenticationFailed                                 : fmt = "[ Security(%08" PRIX32 "):%" PRIu16 " ] Authentication failed"; break;
        case Security::kStatusCode_UnsupportedCASEConfiguration                         : fmt = "[ Security(%08" PRIX32 "):%" PRIu16 " ] Unsupported CASE configuration"; break;
        case Security::kStatusCode_UnsupportedCertificate                               : fmt = "[ Security(%08" PRIX32 "):%" PRIu16 " ] Unsupported certificate"; break;
        case Security::kStatusCode_NoCommonPASEConfigurations                           : fmt = "[ Security(%08" PRIX32 "):%" PRIu16 " ] No supported PASE configurations in common"; break;
        case Security::kStatusCode_KeyNotFound                                          : fmt = "[ Security(%08" PRIX32 "):%" PRIu16 " ] Key not found"; break;
        case Security::kStatusCode_WrongEncryptionType                                  : fmt = "[ Security(%08" PRIX32 "):%" PRIu16 " ] Wrong encryption type"; break;
        case Security::kStatusCode_UnknownSessionType                                       : fmt = "[ Security(%08" PRIX32 "):%" PRIu16 " ] Unknown key type"; break;
        case Security::kStatusCode_InvalidUseOfSessionKey                               : fmt = "[ Security(%08" PRIX32 "):%" PRIu16 " ] Invalid use of session key"; break;
        case Security::kStatusCode_InternalKeyError                                     : fmt = "[ Security(%08" PRIX32 "):%" PRIu16 " ] Internal key error"; break;
        case Security::kStatusCode_NoCommonKeyExportConfiguration                       : fmt = "[ Security(%08" PRIX32 "):%" PRIu16 " ] No common key export configuration"; break;
        case Security::kStatusCode_UnathorizedKeyExportRequest                          : fmt = "[ Security(%08" PRIX32 "):%" PRIu16 " ] Unauthorized key export request"; break;
        default                                                                         : fmt = "[ Security(%08" PRIX32 "):%" PRIu16 " ]"; break;
        }
        break;
    case kMatterProfile_ServiceProvisioning:
        switch (statusCode)
        {
        case ServiceProvisioning::kStatusCode_TooManyServices                           : fmt = "[ ServiceProvisioning(%08" PRIX32 "):%" PRIu16 " ] Too many services"; break;
        case ServiceProvisioning::kStatusCode_ServiceAlreadyRegistered                  : fmt = "[ ServiceProvisioning(%08" PRIX32 "):%" PRIu16 " ] Service already registered"; break;
        case ServiceProvisioning::kStatusCode_InvalidServiceConfig                      : fmt = "[ ServiceProvisioning(%08" PRIX32 "):%" PRIu16 " ] Invalid service configuration"; break;
        case ServiceProvisioning::kStatusCode_NoSuchService                             : fmt = "[ ServiceProvisioning(%08" PRIX32 "):%" PRIu16 " ] No such service"; break;
        case ServiceProvisioning::kStatusCode_PairingServerError                        : fmt = "[ ServiceProvisioning(%08" PRIX32 "):%" PRIu16 " ] Error talking to pairing server"; break;
        case ServiceProvisioning::kStatusCode_InvalidPairingToken                       : fmt = "[ ServiceProvisioning(%08" PRIX32 "):%" PRIu16 " ] Invalid pairing token"; break;
        case ServiceProvisioning::kStatusCode_PairingTokenOld                           : fmt = "[ ServiceProvisioning(%08" PRIX32 "):%" PRIu16 " ] Pairing token no longer valid"; break;
        case ServiceProvisioning::kStatusCode_ServiceCommuncationError                  : fmt = "[ ServiceProvisioning(%08" PRIX32 "):%" PRIu16 " ] Service communication error"; break;
        case ServiceProvisioning::kStatusCode_ServiceConfigTooLarge                     : fmt = "[ ServiceProvisioning(%08" PRIX32 "):%" PRIu16 " ] Service configuration too large"; break;
        default                                                                         : fmt = "[ ServiceProvisioning(%08" PRIX32 "):%" PRIu16 " ]"; break;
        }
        break;

    case kMatterProfile_SWU:
        switch (statusCode)
        {
        case SoftwareUpdate::kStatus_NoUpdateAvailable                                  : fmt = "[ SWU(%08" PRIX32 "):%" PRIu16 " ] No software update available"; break;
        case SoftwareUpdate::kStatus_UpdateFailed                                       : fmt = "[ SWU(%08" PRIX32 "):%" PRIu16 " ] Software update failed"; break;
        case SoftwareUpdate::kStatus_InvalidInstructions                                : fmt = "[ SWU(%08" PRIX32 "):%" PRIu16 " ] Invalid software image download instructions"; break;
        case SoftwareUpdate::kStatus_DownloadFailed                                     : fmt = "[ SWU(%08" PRIX32 "):%" PRIu16 " ] Software image download failed"; break;
        case SoftwareUpdate::kStatus_IntegrityCheckFailed                               : fmt = "[ SWU(%08" PRIX32 "):%" PRIu16 " ] Software image integrity check failed"; break;
        case SoftwareUpdate::kStatus_Abort                                              : fmt = "[ SWU(%08" PRIX32 "):%" PRIu16 " ] Software image query aborted"; break;
        case SoftwareUpdate::kStatus_Retry                                              : fmt = "[ SWU(%08" PRIX32 "):%" PRIu16 " ] Retry software image query"; break;
        default                                                                         : fmt = "[ SWU(%08" PRIX32 "):%" PRIu16 " ]"; break;
        }
        break;
    }

    if (fmt == NULL)
        fmt = "[ %08" PRIX32 ":%" PRIu16 " ]";

    snprintf(sErrorStr, sizeof(sErrorStr) - 2, fmt, profileId, statusCode);
    sErrorStr[sizeof(sErrorStr) - 1] = 0;
    return sErrorStr;
}
#endif // #if MATTER_CONFIG_SHORT_ERROR_STR

} // namespace matter

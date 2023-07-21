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
 *      This file implements functions to translate error codes used
 *      throughout the Matter package into human-readable strings.
 *
 */

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <inttypes.h>
#include <stdio.h>

#include <Matter/Core/MatterCore.h>
#include <Matter/Support/CodeUtils.h>

namespace matter {

#if MATTER_CONFIG_SHORT_ERROR_STR

/**
 *  @def ERROR_STR_SIZE
 *
 *  @brief
 *    This defines the size of the buffer to store the formatted error string.
 *
 *    Static buffer to store the short version of error string, which includes
 *    subsystem name and 32-bit error code in hex
 *
 *    At max 22 bytes would be needed according to this calculation/formating:
 *    - 10 characters for subsystem name,
 *    - ':',
 *    - "0x", 8 characters for error code in hex,
 *    - '\0'
 *
 *        An example would be "Matter:0xDEAFBEEF"
 *        - The output string would be truncated if the subsystem name is longer
 *      than 10
 */
#define ERROR_STR_SIZE (10 + 3 + 8 + 1)

/**
 *  @def _SubsystemFormatError(name, err, desc)
 *
 *  @brief
 *    This defines a function that formats the specified error and string
 *    describing the subsystem into a platform- or system-specific manner.
 *
 */
#define _SubsystemFormatError(name, err, desc) SubsystemFormatError(name, err)

#else // #if MATTER_CONFIG_SHORT_ERROR_STR

/**
 *  @def ERROR_STR_SIZE
 *
 *  @brief
 *    This defines the size of the buffer to store the formatted error string.
 *
 *    Note that the size is arbitrary and probably doesn't have to be this big.
 *    On platforms where 1kB RAM matters, it is probably better to choose the
 *    short version, or don't call ErrorStr at all.
 *
 */
#define ERROR_STR_SIZE (1000)

/**
 *  @def _SubsystemFormatError(name, err, desc)
 *
 *  @brief
 *    This defines a function that formats the specified error and string
 *    describing the subsystem into a platform- or system-specific manner.
 *
 */
#define _SubsystemFormatError(name, err, desc) SubsystemFormatError(name, err, desc)

#endif // #if MATTER_CONFIG_SHORT_ERROR_STR


/**
 *  @var static char sErrorStr[ERROR_STR_SIZE]
 *
 *  @brief
 *    Static buffer to store the formated error string
 *
 */
static char sErrorStr[ERROR_STR_SIZE];

/**
 * This routine formats the specified error into a human-readable
 * NULL-terminated C string describing the provided error.
 *
 * @param[in] err    The error for formatting and description.
 *
 * @return A pointer to a NULL-terminated C string describing the
 *         provided error.
 */
static const char *FormatError(int32_t err)
{
#if MATTER_CONFIG_SHORT_ERROR_STR
    (void)snprintf(sErrorStr, sizeof(sErrorStr), "Error 0x%" PRIx32, err);
#else
    (void)snprintf(sErrorStr, sizeof(sErrorStr), "Error %" PRId32, err);
#endif
    return sErrorStr;
}

/**
 * This routine formats the specified error and string describing the
 * subsystem into the provided format string and returns a human-readable
 * NULL-terminated C string describing the provided error.
 *
 * @param[in] subsystem  A pointer to a NULL-terminated C string representing
 *                       the package subsystem to which the error corresponds.
 * @param[in] err        The error for formatting and description.
 *
 * @return A pointer to a NULL-terminated C string describing the
 *         provided error.
 */
static const char *SubsystemFormatError(const char *subsystem, int32_t err)
{
    // note that snprintf shall zero-terminate the string as long as sizeof(sErrorStr) > 0
    // note that the return value of snprintf is ignored for an error is very unlikely to happen and we do not care about truncation
#if MATTER_CONFIG_SHORT_ERROR_STR
    (void)snprintf(sErrorStr, sizeof(sErrorStr), "%s:0x%" PRIx32, subsystem, err);
#else
    (void)snprintf(sErrorStr, sizeof(sErrorStr), "%s Error %" PRId32, subsystem, err);
#endif
    return sErrorStr;
}

#if !(MATTER_CONFIG_SHORT_ERROR_STR)

/**
 * This routine formats the specified error and string describing the
 * subsystem into the provided format string and returns a human-readable
 * NULL-terminated C string describing the provided error.
 *
 * @param[in] subsystem    A pointer to a NULL-terminated C string representing
 *                         the package subsystem to which the error corresponds.
 * @param[in] err          The error for formatting and description.
 * @param[in] description  A pointer to a NULL-terminated C string describing
 *                         the error. Ignored when MATTER_CONFIG_SHORT_ERROR_STR is defined
 *
 * @return A pointer to a NULL-terminated C string describing the
 *         provided error.
 */
static const char *SubsystemFormatError(const char *subsystem, int32_t err, const char *description)
{
    (void)snprintf(sErrorStr, sizeof(sErrorStr), "%s Error %" PRId32 ": %s", subsystem, err, description);
    return sErrorStr;
}

#if CONFIG_NETWORK_LAYER_BLE
/**
 * This routine formats the specified error and string describing the
 * BLE layer into the provided format string and returns a human-readable
 * NULL-terminated C string describing the provided error.
 *
 * @param[in] err          The error for formatting and description.
 * @param[in] description  A pointer to a NULL-terminated C string describing
 *                         the error. Ignored when MATTER_CONFIG_SHORT_ERROR_STR is defined
 *
 * @return A pointer to a NULL-terminated C string describing the
 *         provided error.
 */
static const char *BleFormatError(int32_t err, const char *description)
{
    return SubsystemFormatError("Ble", err, description);
}
#endif // CONFIG_NETWORK_LAYER_BLE

/**
 * This routine formats the specified error and string describing Matter
 * into the provided format string and returns a human-readable NULL-terminated
 * C string describing the provided error.
 *
 * @param[in] err          The error for formatting and description.
 * @param[in] description  A pointer to a NULL-terminated C string describing
 *                         the error. Ignored when MATTER_CONFIG_SHORT_ERROR_STR is defined
 *
 * @return A pointer to a NULL-terminated C string describing the
 *         provided error.
 */
static const char *MatterFormatError(int32_t err, const char *description)
{
    return SubsystemFormatError("Matter", err, description);
}

#endif // #if !(MATTER_CONFIG_SHORT_ERROR_STR)

/**
 * This routine returns a human-readable NULL-terminated C string
 * describing the provided error.
 *
 * @param[in] err     The error for format and describe.
 *
 * @return A pointer to a NULL-terminated C string describing the
 *         provided error.
 */
const char *ErrorStr(int32_t err)
{
    switch (err)
    {
    case 0                                                      : return "No Error";

#if !MATTER_CONFIG_SHORT_ERROR_STR

    // ----- Matter Errors -----
    case MATTER_ERROR_TOO_MANY_CONNECTIONS                       : return MatterFormatError(err, "Too many connections");
    case MATTER_ERROR_SENDING_BLOCKED                            : return MatterFormatError(err, "Sending blocked");
    case MATTER_ERROR_CONNECTION_ABORTED                         : return MatterFormatError(err, "Connection aborted");
    case MATTER_ERROR_INCORRECT_STATE                            : return MatterFormatError(err, "Incorrect state");
    case MATTER_ERROR_MESSAGE_TOO_LONG                           : return MatterFormatError(err, "Message too long");
    case MATTER_ERROR_UNSUPPORTED_EXCHANGE_VERSION               : return MatterFormatError(err, "Unsupported exchange version");
    case MATTER_ERROR_TOO_MANY_UNSOLICITED_MESSAGE_HANDLERS      : return MatterFormatError(err, "Too many unsolicited message handlers");
    case MATTER_ERROR_NO_UNSOLICITED_MESSAGE_HANDLER             : return MatterFormatError(err, "No unsolicited message handler");
    case MATTER_ERROR_NO_CONNECTION_HANDLER                      : return MatterFormatError(err, "No connection handler");
    case MATTER_ERROR_TOO_MANY_PEER_NODES                        : return MatterFormatError(err, "Too many peer nodes");
    case MATTER_ERROR_NO_MEMORY                                  : return MatterFormatError(err, "No memory");
    case MATTER_ERROR_NO_MESSAGE_HANDLER                         : return MatterFormatError(err, "No message handler");
    case MATTER_ERROR_MESSAGE_INCOMPLETE                         : return MatterFormatError(err, "Message incomplete");
    case MATTER_ERROR_DATA_NOT_ALIGNED                           : return MatterFormatError(err, "Data not aligned");
    case MATTER_ERROR_UNKNOWN_KEY_TYPE                           : return MatterFormatError(err, "Unknown key type");
    case MATTER_ERROR_KEY_NOT_FOUND                              : return MatterFormatError(err, "Key not found");
    case MATTER_ERROR_WRONG_ENCRYPTION_TYPE                      : return MatterFormatError(err, "Wrong encryption type");
    case MATTER_ERROR_TOO_MANY_KEYS                              : return MatterFormatError(err, "Too many keys");
    case MATTER_ERROR_INTEGRITY_CHECK_FAILED                     : return MatterFormatError(err, "Integrity check failed");
    case MATTER_ERROR_INVALID_SIGNATURE                          : return MatterFormatError(err, "Invalid signature");
    case MATTER_ERROR_UNSUPPORTED_MESSAGE_VERSION                : return MatterFormatError(err, "Unsupported message version");
    case MATTER_ERROR_UNSUPPORTED_ENCRYPTION_TYPE                : return MatterFormatError(err, "Unsupported encryption type");
    case MATTER_ERROR_UNSUPPORTED_SIGNATURE_TYPE                 : return MatterFormatError(err, "Unsupported signature type");
    case MATTER_ERROR_INVALID_MESSAGE_LENGTH                     : return MatterFormatError(err, "Invalid message length");
    case MATTER_ERROR_BUFFER_TOO_SMALL                           : return MatterFormatError(err, "Buffer too small");
    case MATTER_ERROR_DUPLICATE_KEY_ID                           : return MatterFormatError(err, "Duplicate key id");
    case MATTER_ERROR_WRONG_KEY_TYPE                             : return MatterFormatError(err, "Wrong key type");
    case MATTER_ERROR_WELL_UNINITIALIZED                         : return MatterFormatError(err, "Well uninitialized");
    case MATTER_ERROR_WELL_EMPTY                                 : return MatterFormatError(err, "Well empty");
    case MATTER_ERROR_INVALID_STRING_LENGTH                      : return MatterFormatError(err, "Invalid string length");
    case MATTER_ERROR_INVALID_LIST_LENGTH                        : return MatterFormatError(err, "invalid list length");
    case MATTER_ERROR_INVALID_INTEGRITY_TYPE                     : return MatterFormatError(err, "Invalid integrity type");
    case MATTER_END_OF_TLV                                       : return MatterFormatError(err, "End of TLV");
    case MATTER_ERROR_TLV_UNDERRUN                               : return MatterFormatError(err, "TLV underrun");
    case MATTER_ERROR_INVALID_TLV_ELEMENT                        : return MatterFormatError(err, "Invalid TLV element");
    case MATTER_ERROR_INVALID_TLV_TAG                            : return MatterFormatError(err, "Invalid TLV tag");
    case MATTER_ERROR_UNKNOWN_IMPLICIT_TLV_TAG                   : return MatterFormatError(err, "Unknown implicit TLV tag");
    case MATTER_ERROR_WRONG_TLV_TYPE                             : return MatterFormatError(err, "Wrong TLV type");
    case MATTER_ERROR_TLV_CONTAINER_OPEN                         : return MatterFormatError(err, "TLV container open");
    case MATTER_ERROR_INVALID_TRANSFER_MODE                      : return MatterFormatError(err, "Invalid transfer mode");
    case MATTER_ERROR_INVALID_PROFILE_ID                         : return MatterFormatError(err, "Invalid profile id");
    case MATTER_ERROR_INVALID_MESSAGE_TYPE                       : return MatterFormatError(err, "Invalid message type");
    case MATTER_ERROR_UNEXPECTED_TLV_ELEMENT                     : return MatterFormatError(err, "Unexpected TLV element");
    case MATTER_ERROR_STATUS_REPORT_RECEIVED                     : return MatterFormatError(err, "Status Report received from peer");
    case MATTER_ERROR_NOT_IMPLEMENTED                            : return MatterFormatError(err, "Not Implemented");
    case MATTER_ERROR_INVALID_ADDRESS                            : return MatterFormatError(err, "Invalid address");
    case MATTER_ERROR_INVALID_ARGUMENT                           : return MatterFormatError(err, "Invalid argument");
    case MATTER_ERROR_TLV_TAG_NOT_FOUND                          : return MatterFormatError(err, "TLV tag not found");

    case MATTER_ERROR_INVALID_PATH_LIST                          : return MatterFormatError(err, "Invalid TLV path list");
    case MATTER_ERROR_INVALID_DATA_LIST                          : return MatterFormatError(err, "Invalid TLV data list");
    case MATTER_ERROR_TRANSACTION_CANCELED                       : return MatterFormatError(err, "Transaction canceled");
    case MATTER_ERROR_LISTENER_ALREADY_STARTED                   : return MatterFormatError(err, "Listener already started");
    case MATTER_ERROR_LISTENER_ALREADY_STOPPED                   : return MatterFormatError(err, "Listener already stopped");
    case MATTER_ERROR_UNKNOWN_TOPIC                              : return MatterFormatError(err, "Unknown Topic");

    case MATTER_ERROR_TIMEOUT                                    : return MatterFormatError(err, "Timeout");
    case MATTER_ERROR_INVALID_DEVICE_DESCRIPTOR                  : return MatterFormatError(err, "Invalid device descriptor");
    case MATTER_ERROR_UNSUPPORTED_DEVICE_DESCRIPTOR_VERSION      : return MatterFormatError(err, "Unsupported device descriptor version");
    case MATTER_END_OF_INPUT                                     : return MatterFormatError(err, "End of input");
    case MATTER_ERROR_RATE_LIMIT_EXCEEDED                        : return MatterFormatError(err, "Rate limit exceeded");
    case MATTER_ERROR_SECURITY_MANAGER_BUSY                      : return MatterFormatError(err, "Security manager busy");
    case MATTER_ERROR_INVALID_PASE_PARAMETER                     : return MatterFormatError(err, "Invalid PASE parameter");
    case MATTER_ERROR_PASE_SUPPORTS_ONLY_CONFIG1                 : return MatterFormatError(err, "PASE supports only Config1");
    case MATTER_ERROR_NO_COMMON_PASE_CONFIGURATIONS              : return MatterFormatError(err, "No supported PASE configurations in common");
    case MATTER_ERROR_INVALID_PASE_CONFIGURATION                 : return MatterFormatError(err, "Invalid PASE configuration");
    case MATTER_ERROR_KEY_CONFIRMATION_FAILED                    : return MatterFormatError(err, "Key confirmation failed");
    case MATTER_ERROR_INVALID_USE_OF_SESSION_KEY                 : return MatterFormatError(err, "Invalid use of session key");
    case MATTER_ERROR_CONNECTION_CLOSED_UNEXPECTEDLY             : return MatterFormatError(err, "Connection closed unexpectedly");
    case MATTER_ERROR_MISSING_TLV_ELEMENT                        : return MatterFormatError(err, "Missing TLV element");
    case MATTER_ERROR_RANDOM_DATA_UNAVAILABLE                    : return MatterFormatError(err, "Random data unavailable");
    case MATTER_ERROR_UNSUPPORTED_HOST_PORT_ELEMENT              : return MatterFormatError(err, "Unsupported type in host/port list");
    case MATTER_ERROR_INVALID_HOST_SUFFIX_INDEX                  : return MatterFormatError(err, "Invalid suffix index in host/port list");
    case MATTER_ERROR_HOST_PORT_LIST_EMPTY                       : return MatterFormatError(err, "Host/port empty");
    case MATTER_ERROR_UNSUPPORTED_AUTH_MODE                      : return MatterFormatError(err, "Unsupported authentication mode");

    case MATTER_ERROR_INVALID_SERVICE_EP                         : return MatterFormatError(err, "Invalid service endpoint");
    case MATTER_ERROR_INVALID_DIRECTORY_ENTRY_TYPE               : return MatterFormatError(err, "Invalid directory entry type");
    case MATTER_ERROR_FORCED_RESET                               : return MatterFormatError(err, "Service manager forced reset");
    case MATTER_ERROR_NO_ENDPOINT                                : return MatterFormatError(err, "No endpoint was available to send the message");
    case MATTER_ERROR_INVALID_DESTINATION_NODE_ID                : return MatterFormatError(err, "Invalid destination node id");
    case MATTER_ERROR_NOT_CONNECTED                              : return MatterFormatError(err, "Not connected");
    case MATTER_ERROR_NO_SW_UPDATE_AVAILABLE                     : return MatterFormatError(err, "No SW update available");

    case MATTER_ERROR_CA_CERT_NOT_FOUND                          : return MatterFormatError(err, "CA certificate not found");
    case MATTER_ERROR_CERT_PATH_LEN_CONSTRAINT_EXCEEDED          : return MatterFormatError(err, "Certificate path length constraint exceeded");
    case MATTER_ERROR_CERT_PATH_TOO_LONG                         : return MatterFormatError(err, "Certificate path too long");
    case MATTER_ERROR_CERT_USAGE_NOT_ALLOWED                     : return MatterFormatError(err, "Requested certificate usage is not allowed");
    case MATTER_ERROR_CERT_EXPIRED                               : return MatterFormatError(err, "Certificate expired");
    case MATTER_ERROR_CERT_NOT_VALID_YET                         : return MatterFormatError(err, "Certificate not yet valid");
    case MATTER_ERROR_UNSUPPORTED_CERT_FORMAT                    : return MatterFormatError(err, "Unsupported certificate format");
    case MATTER_ERROR_UNSUPPORTED_ELLIPTIC_CURVE                 : return MatterFormatError(err, "Unsupported elliptic curve");
    case MATTER_CERT_NOT_USED                                    : return MatterFormatError(err, "Certificate was not used in chain validation");
    case MATTER_ERROR_CERT_NOT_FOUND                             : return MatterFormatError(err, "Certificate not found");
    case MATTER_ERROR_INVALID_CASE_PARAMETER                     : return MatterFormatError(err, "Invalid CASE parameter");
    case MATTER_ERROR_UNSUPPORTED_CASE_CONFIGURATION             : return MatterFormatError(err, "Unsupported CASE configuration");
    case MATTER_ERROR_CERT_LOAD_FAIL                             : return MatterFormatError(err, "Unable to load certificate");
    case MATTER_ERROR_CERT_NOT_TRUSTED                           : return MatterFormatError(err, "Certificate not trusted");
    case MATTER_ERROR_INVALID_ACCESS_TOKEN                       : return MatterFormatError(err, "Invalid access token");
    case MATTER_ERROR_WRONG_CERT_SUBJECT                         : return MatterFormatError(err, "Wrong certificate subject");
    case MATTER_ERROR_WRONG_NODE_ID                              : return MatterFormatError(err, "Wrong node ID");
    case MATTER_ERROR_CONN_ACCEPTED_ON_WRONG_PORT                : return MatterFormatError(err, "Connection accepted on wrong port");
    case MATTER_ERROR_CALLBACK_REPLACED                          : return MatterFormatError(err, "Application callback replaced");
    case MATTER_ERROR_NO_CASE_AUTH_DELEGATE                      : return MatterFormatError(err, "No CASE auth delegate set");
    case MATTER_ERROR_DEVICE_LOCATE_TIMEOUT                      : return MatterFormatError(err, "Timeout attempting to locate device");
    case MATTER_ERROR_DEVICE_CONNECT_TIMEOUT                     : return MatterFormatError(err, "Timeout connecting to device");
    case MATTER_ERROR_DEVICE_AUTH_TIMEOUT                        : return MatterFormatError(err, "Timeout authenticating device");
    case MATTER_ERROR_MESSAGE_NOT_ACKNOWLEDGED                   : return MatterFormatError(err, "Message not acknowledged after max retries");
    case MATTER_ERROR_RETRANS_TABLE_FULL                         : return MatterFormatError(err, "Retransmit Table is already full");
    case MATTER_ERROR_INVALID_ACK_ID                             : return MatterFormatError(err, "Invalid Acknowledgment Id");
    case MATTER_ERROR_SEND_THROTTLED                             : return MatterFormatError(err, "Sending to peer is throttled on this Exchange");
    case MATTER_ERROR_WRONG_MSG_VERSION_FOR_EXCHANGE             : return MatterFormatError(err, "Message version not supported by current exchange context");
    case MATTER_ERROR_UNSUPPORTED_MATTER_FEATURE                  : return MatterFormatError(err, "Required feature not supported by this configuration");
    case MATTER_ERROR_UNSOLICITED_MSG_NO_ORIGINATOR              : return MatterFormatError(err, "Unsolicited msg with originator bit clear");
    case MATTER_ERROR_UNSUPPORTED_TUNNEL_VERSION                 : return MatterFormatError(err, "Unsupported Tunnel version");
    case MATTER_ERROR_INVALID_FABRIC_ID                          : return MatterFormatError(err, "Invalid Fabric Id");
    case MATTER_ERROR_TUNNEL_NEXTHOP_TABLE_FULL                  : return MatterFormatError(err, "Local tunnel nexthop table full");
    case MATTER_ERROR_TUNNEL_SERVICE_QUEUE_FULL                  : return MatterFormatError(err, "Service queue full");
    case MATTER_ERROR_TUNNEL_PEER_ENTRY_NOT_FOUND                : return MatterFormatError(err, "Shortcut Tunnel peer entry not found");
    case MATTER_ERROR_TUNNEL_FORCE_ABORT                         : return MatterFormatError(err, "Forced Tunnel Abort.");
    case MATTER_ERROR_DRBG_ENTROPY_SOURCE_FAILED                 : return MatterFormatError(err, "DRBG entropy source failed to generate entropy data");
    case MATTER_ERROR_NO_TAKE_AUTH_DELEGATE                      : return MatterFormatError(err, "No TAKE auth delegate set");
    case MATTER_ERROR_TAKE_RECONFIGURE_REQUIRED                  : return MatterFormatError(err, "TAKE requires a reconfigure");
    case MATTER_ERROR_TAKE_REAUTH_POSSIBLE                       : return MatterFormatError(err, "TAKE can do a reauthentication");
    case MATTER_ERROR_INVALID_TAKE_PARAMETER                     : return MatterFormatError(err, "TAKE received an invalid parameter");
    case MATTER_ERROR_UNSUPPORTED_TAKE_CONFIGURATION             : return MatterFormatError(err, "TAKE Unsupported configuration");
    case MATTER_ERROR_TAKE_TOKEN_IDENTIFICATION_FAILED           : return MatterFormatError(err, "TAKE token identification failed");
    case MATTER_ERROR_INVALID_TOKENPAIRINGBUNDLE                 : return MatterFormatError(err, "Invalid Token Pairing Bundle");
    case MATTER_ERROR_UNSUPPORTED_TOKENPAIRINGBUNDLE_VERSION     : return MatterFormatError(err, "Unsupported Token Pairing Bundle version");
    case MATTER_ERROR_KEY_NOT_FOUND_FROM_PEER                    : return MatterFormatError(err, "Key not found error code received from peer");
    case MATTER_ERROR_WRONG_ENCRYPTION_TYPE_FROM_PEER            : return MatterFormatError(err, "Wrong encryption type error code received from peer");
    case MATTER_ERROR_UNKNOWN_KEY_TYPE_FROM_PEER                 : return MatterFormatError(err, "Unknown key type error code received from peer");
    case MATTER_ERROR_INVALID_USE_OF_SESSION_KEY_FROM_PEER       : return MatterFormatError(err, "Invalid use of session key error code received from peer");
    case MATTER_ERROR_UNSUPPORTED_ENCRYPTION_TYPE_FROM_PEER      : return MatterFormatError(err, "Unsupported encryption type error code received from peer");
    case MATTER_ERROR_INTERNAL_KEY_ERROR_FROM_PEER               : return MatterFormatError(err, "Internal key error code received from peer");
    case MATTER_ERROR_INVALID_KEY_ID                             : return MatterFormatError(err, "Invalid key identifier");
    case MATTER_ERROR_INVALID_TIME                               : return MatterFormatError(err, "Valid time value is not available");
    case MATTER_ERROR_LOCKING_FAILURE                            : return MatterFormatError(err, "Failure to lock/unlock OS-provided lock");
    case MATTER_ERROR_UNSUPPORTED_PASSCODE_CONFIG                : return MatterFormatError(err, "Unsupported passcode encryption configuration.");
    case MATTER_ERROR_PASSCODE_AUTHENTICATION_FAILED             : return MatterFormatError(err, "Passcode authentication failed.");
    case MATTER_ERROR_PASSCODE_FINGERPRINT_FAILED                : return MatterFormatError(err, "Passcode fingerprint failed.");
    case MATTER_ERROR_SERIALIZATION_ELEMENT_NULL                 : return MatterFormatError(err, "Element requested is null.");
    case MATTER_ERROR_WRONG_CERT_SIGNATURE_ALGORITHM             : return MatterFormatError(err, "Certificate not signed with required signature algorithm");
    case MATTER_ERROR_WRONG_MATTER_SIGNATURE_ALGORITHM            : return MatterFormatError(err, "Matter signature not signed with required signature algorithm");
    case MATTER_ERROR_IM_SCHEMA_MISMATCH                        : return MatterFormatError(err, "Schema mismatch in IM.");
    case MATTER_ERROR_INVALID_INTEGER_VALUE                      : return MatterFormatError(err, "Invalid integer value.");
    case MATTER_ERROR_TOO_MANY_CASE_RECONFIGURATIONS             : return MatterFormatError(err, "Too many CASE reconfigurations were received.");
    case MATTER_ERROR_INVALID_MESSAGE_FLAG                       : return MatterFormatError(err, "Invalid message flag.");
    case MATTER_ERROR_NO_COMMON_KEY_EXPORT_CONFIGURATIONS        : return MatterFormatError(err, "No supported key export protocol configurations in common");
    case MATTER_ERROR_INVALID_KEY_EXPORT_CONFIGURATION           : return MatterFormatError(err, "Invalid key export protocol configuration");
    case MATTER_ERROR_NO_KEY_EXPORT_DELEGATE                     : return MatterFormatError(err, "No key export protocol delegate set");
    case MATTER_ERROR_UNAUTHORIZED_KEY_EXPORT_REQUEST            : return MatterFormatError(err, "Unauthorized key export request");
    case MATTER_ERROR_UNAUTHORIZED_KEY_EXPORT_RESPONSE           : return MatterFormatError(err, "Unauthorized key export response");
    case MATTER_ERROR_EXPORTED_KEY_AUTHENTICATION_FAILED         : return MatterFormatError(err, "Exported key authentication failed");
    case MATTER_ERROR_TOO_MANY_SHARED_SESSION_END_NODES          : return MatterFormatError(err, "Too many shared session end nodes");
    case MATTER_ERROR_IM_MALFORMED_DATA_ELEMENT                 : return MatterFormatError(err, "Malformed IM DataElement");
    case MATTER_ERROR_WRONG_CERT_TYPE                            : return MatterFormatError(err, "Wrong certificate type");

#endif // if !MATTER_CONFIG_SHORT_ERROR_STR

    }

#if MATTER_SYSTEM_CONFIG_USE_LWIP
    // Handle any Matter System Layer LwIP stack-specific errors.
    // description is ignored, and the actual printout is different when MATTER_CONFIG_SHORT_ERROR_STR is defined
    if (Matter::System::IsErrorLwIP(static_cast<Matter::System::Error>(err)))
        return _SubsystemFormatError("LwIP", err, Matter::System::DescribeErrorLwIP(static_cast<Matter::System::Error>(err)));
#endif // MATTER_SYSTEM_CONFIG_USE_LWIP

#if MATTER_SYSTEM_CONFIG_USE_SOCKETS
    // Handle any Matter System Layer POSIX stack-specific errors.
    // description is ignored, and the actual printout is different when MATTER_CONFIG_SHORT_ERROR_STR is defined
    if (Matter::System::IsErrorPOSIX(static_cast<Matter::System::Error>(err)))
        return _SubsystemFormatError("OS", err, Matter::System::DescribeErrorPOSIX(static_cast<Matter::System::Error>(err)));
#endif // MATTER_SYSTEM_CONFIG_USE_SOCKETS

    // Handle any default cases not explicitly handled in the switch
    // statement above.
    // Note this is the only case, and the actual printout is different when MATTER_CONFIG_SHORT_ERROR_STR is defined

    if (err >= MATTER_ERROR_MIN && err <= MATTER_ERROR_MAX)
        return SubsystemFormatError("Matter", (int)err);

    // note the actual printout is different when MATTER_CONFIG_SHORT_ERROR_STR is defined
    return FormatError((int)err);
}

} // namespace matter

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
 *      This file defines error constants for the Matter core subsystem.
 *
 *      Error types, ranges, and mappings overrides may be made by
 *      defining the appropriate MATTER_CONFIG_* or _MATTER_CONFIG_*
 *      macros.
 *
 *  NOTE WELL: On some platforms, this header is included by C-language programs.
 *
 */

#ifndef MATTER_ERROR_H
#define MATTER_ERROR_H

#include "MatterConfig.h"

/**
 *  @def MATTER_NO_ERROR
 *
 *  @brief
 *    This defines the Matter error code for success or no error.
 *    This value may be configured via #MATTER_CONFIG_NO_ERROR."
 *
 */
#define MATTER_NO_ERROR                                          MATTER_CONFIG_NO_ERROR

/**
 *  @def MATTER_ERROR_MIN
 *
 *  @brief
 *    This defines the bottom or minimum Matter error number range.
 *    This value may be configured via #MATTER_CONFIG_ERROR_MIN.
 *
 */
#define MATTER_ERROR_MIN                                         MATTER_CONFIG_ERROR_MIN

/**
 *  @def MATTER_ERROR_MAX
 *
 *  @brief
 *    This defines the top or maximum Matter error number range.
 *    This value may be configured via #MATTER_CONFIG_ERROR_MAX.
 *
 */
#define MATTER_ERROR_MAX                                         MATTER_CONFIG_ERROR_MAX

/**
 *  @def _MATTER_ERROR(e)
 *
 *  @brief
 *    This defines a mapping function for Matter errors that allows
 *    mapping such errors into a platform- or system-specific range.
 *    This function may be configured via #_MATTER_CONFIG_ERROR(e).
 *
 *  @param[in] e       The Matter error to map.
 *
 *  @return    The mapped Matter error.
 *
 *
 */
#define _MATTER_ERROR(e)                                         _MATTER_CONFIG_ERROR(e)

/**
 *  The basic type for all Matter errors.
 *
 *  @brief
 *    This is defined to a platform- or system-specific type.
 *
 */
typedef MATTER_CONFIG_ERROR_TYPE MATTER_ERROR;

/**
 *  @name Error Definitions
 *
 *  @{
 */

/**
 *  @def MATTER_ERROR_TOO_MANY_CONNECTIONS
 *
 *  @brief
 *    The attempt to allocate a connection object failed because too many
 *    connections exist.
 *
 */
#define MATTER_ERROR_TOO_MANY_CONNECTIONS                        _MATTER_ERROR(0)

/**
 *  @def MATTER_ERROR_SENDING_BLOCKED
 *
 *  @brief
 *    A message exceeds the sent limit.
 *
 */
#define MATTER_ERROR_SENDING_BLOCKED                             _MATTER_ERROR(1)

/**
 *  @def MATTER_ERROR_CONNECTION_ABORTED
 *
 *  @brief
 *    A connection has been aborted.
 *
 */
#define MATTER_ERROR_CONNECTION_ABORTED                          _MATTER_ERROR(2)

/**
 *  @def MATTER_ERROR_INCORRECT_STATE
 *
 *  @brief
 *    An unexpected state was encountered.
 *
 */
#define MATTER_ERROR_INCORRECT_STATE                             _MATTER_ERROR(3)

/**
 *  @def MATTER_ERROR_MESSAGE_TOO_LONG
 *
 *  @brief
 *    A message is too long.
 *
 */
#define MATTER_ERROR_MESSAGE_TOO_LONG                            _MATTER_ERROR(4)

/**
 *  @def MATTER_ERROR_UNSUPPORTED_EXCHANGE_VERSION
 *
 *  @brief
 *    An exchange version is not supported.
 *
 */
#define MATTER_ERROR_UNSUPPORTED_EXCHANGE_VERSION                _MATTER_ERROR(5)

/**
 *  @def MATTER_ERROR_TOO_MANY_UNSOLICITED_MESSAGE_HANDLERS
 *
 *  @brief
 *    The attempt to register an unsolicited message handler failed because the
 *    unsolicited message handler pool is full.
 *
 */
#define MATTER_ERROR_TOO_MANY_UNSOLICITED_MESSAGE_HANDLERS       _MATTER_ERROR(6)

/**
 *  @def MATTER_ERROR_NO_UNSOLICITED_MESSAGE_HANDLER
 *
 *  @brief
 *    The attempt to unregister an unsolicited message handler failed because
 *    the target handler was not found in the unsolicited message handler pool.
 *
 */
#define MATTER_ERROR_NO_UNSOLICITED_MESSAGE_HANDLER              _MATTER_ERROR(7)

/**
 *  @def MATTER_ERROR_NO_CONNECTION_HANDLER
 *
 *  @brief
 *    No callback has been registered for handling a connection.
 *
 */
#define MATTER_ERROR_NO_CONNECTION_HANDLER                       _MATTER_ERROR(8)

/**
 *  @def MATTER_ERROR_TOO_MANY_PEER_NODES
 *
 *  @brief
 *    The number of peer nodes exceeds the maximum limit of a local node.
 *
 */
#define MATTER_ERROR_TOO_MANY_PEER_NODES                         _MATTER_ERROR(9)

/**
 *  @def MATTER_ERROR_NO_MEMORY
 *
 *  @brief
 *    The attempt to allocate a buffer or object failed due to a lack of memory.
 *
 */
#define MATTER_ERROR_NO_MEMORY                                   _MATTER_ERROR(11)

/**
 *  @def MATTER_ERROR_NO_MESSAGE_HANDLER
 *
 *  @brief
 *    No callback has been registered for handling a message.
 *
 */
#define MATTER_ERROR_NO_MESSAGE_HANDLER                          _MATTER_ERROR(12)

/**
 *  @def MATTER_ERROR_MESSAGE_INCOMPLETE
 *
 *  @brief
 *    A message is incomplete.
 *
 */
#define MATTER_ERROR_MESSAGE_INCOMPLETE                          _MATTER_ERROR(13)

/**
 *  @def MATTER_ERROR_DATA_NOT_ALIGNED
 *
 *  @brief
 *    The data is not aligned.
 *
 */
#define MATTER_ERROR_DATA_NOT_ALIGNED                            _MATTER_ERROR(14)

/**
 *  @def MATTER_ERROR_UNKNOWN_KEY_TYPE
 *
 *  @brief
 *    The encryption key type is unknown.
 *
 */
#define MATTER_ERROR_UNKNOWN_KEY_TYPE                            _MATTER_ERROR(15)

/**
 *  @def MATTER_ERROR_KEY_NOT_FOUND
 *
 *  @brief
 *    The encryption key is not found.
 *
 */
#define MATTER_ERROR_KEY_NOT_FOUND                               _MATTER_ERROR(16)

/**
 *  @def MATTER_ERROR_WRONG_ENCRYPTION_TYPE
 *
 *  @brief
 *    The encryption type is incorrect for the specified key.
 *
 */
#define MATTER_ERROR_WRONG_ENCRYPTION_TYPE                       _MATTER_ERROR(17)

/**
 *  @def MATTER_ERROR_TOO_MANY_KEYS
 *
 *  @brief
 *    The attempt to allocate a key failed because the number of active keys
 *    exceeds the maximum limit.
 *
 */
#define MATTER_ERROR_TOO_MANY_KEYS                               _MATTER_ERROR(18)

/**
 *  @def MATTER_ERROR_INTEGRITY_CHECK_FAILED
 *
 *  @brief
 *    The integrity check in the message does not match the expected integrity
 *    check.
 *
 */
#define MATTER_ERROR_INTEGRITY_CHECK_FAILED                      _MATTER_ERROR(19)

/**
 *  @def MATTER_ERROR_INVALID_SIGNATURE
 *
 *  @brief
 *    Invalid signature.
 *
 */
#define MATTER_ERROR_INVALID_SIGNATURE                           _MATTER_ERROR(20)

/**
 *  @def MATTER_ERROR_UNSUPPORTED_MESSAGE_VERSION
 *
 *  @brief
 *    A message version is unsupported.
 *
 */
#define MATTER_ERROR_UNSUPPORTED_MESSAGE_VERSION                 _MATTER_ERROR(21)

/**
 *  @def MATTER_ERROR_UNSUPPORTED_ENCRYPTION_TYPE
 *
 *  @brief
 *    An encryption type is unsupported.
 *
 */
#define MATTER_ERROR_UNSUPPORTED_ENCRYPTION_TYPE                 _MATTER_ERROR(22)

/**
 *  @def MATTER_ERROR_UNSUPPORTED_SIGNATURE_TYPE
 *
 *  @brief
 *    A signature type is unsupported.
 *
 */
#define MATTER_ERROR_UNSUPPORTED_SIGNATURE_TYPE                  _MATTER_ERROR(23)

/**
 *  @def MATTER_ERROR_INVALID_MESSAGE_LENGTH
 *
 *  @brief
 *    A message length is invalid.
 *
 */
#define MATTER_ERROR_INVALID_MESSAGE_LENGTH                      _MATTER_ERROR(24)

/**
 *  @def MATTER_ERROR_BUFFER_TOO_SMALL
 *
 *  @brief
 *    A buffer is too small.
 *
 */
#define MATTER_ERROR_BUFFER_TOO_SMALL                            _MATTER_ERROR(25)

/**
 *  @def MATTER_ERROR_DUPLICATE_KEY_ID
 *
 *  @brief
 *    A key id is duplicate.
 *
 */
#define MATTER_ERROR_DUPLICATE_KEY_ID                            _MATTER_ERROR(26)

/**
 *  @def MATTER_ERROR_WRONG_KEY_TYPE
 *
 *  @brief
 *    A key type does not match the expected key type.
 *
 */
#define MATTER_ERROR_WRONG_KEY_TYPE                              _MATTER_ERROR(27)

/**
 *  @def MATTER_ERROR_WELL_UNINITIALIZED
 *
 *  @brief
 *    A requested object is uninitialized.
 *
 */
#define MATTER_ERROR_WELL_UNINITIALIZED                          _MATTER_ERROR(28)

/**
 *  @def MATTER_ERROR_WELL_EMPTY
 *
 *  @brief
 *    A requested object is empty.
 *
 */
#define MATTER_ERROR_WELL_EMPTY                                  _MATTER_ERROR(29)

/**
 *  @def MATTER_ERROR_INVALID_STRING_LENGTH
 *
 *  @brief
 *    A string length is invalid.
 *
 */
#define MATTER_ERROR_INVALID_STRING_LENGTH                       _MATTER_ERROR(30)

/**
 *  @def MATTER_ERROR_INVALID_LIST_LENGTH
 *
 *  @brief
 *    A list length is invalid.
 *
 */
#define MATTER_ERROR_INVALID_LIST_LENGTH                         _MATTER_ERROR(31)

/**
 *  @def MATTER_ERROR_INVALID_INTEGRITY_TYPE
 *
 *  @brief
 *    An integrity type is invalid.
 *
 */
#define MATTER_ERROR_INVALID_INTEGRITY_TYPE                      _MATTER_ERROR(32)

/**
 *  @def MATTER_END_OF_TLV
 *
 *  @brief
 *    The end of a TLV encoding,
 *    or the end of a TLV container element has been reached.
 *
 */
#define MATTER_END_OF_TLV                                        _MATTER_ERROR(33)

/**
 *  @def MATTER_ERROR_TLV_UNDERRUN
 *
 *  @brief
 *    The TLV encoding ended prematurely.
 *
 */
#define MATTER_ERROR_TLV_UNDERRUN                                _MATTER_ERROR(34)

/**
 *  @def MATTER_ERROR_INVALID_TLV_ELEMENT
 *
 *  @brief
 *    A TLV element is invalid.
 *
 */
#define MATTER_ERROR_INVALID_TLV_ELEMENT                         _MATTER_ERROR(35)

/**
 *  @def MATTER_ERROR_INVALID_TLV_TAG
 *
 *  @brief
 *    A TLV tag is invalid.
 *
 */
#define MATTER_ERROR_INVALID_TLV_TAG                             _MATTER_ERROR(36)

/**
 *  @def MATTER_ERROR_UNKNOWN_IMPLICIT_TLV_TAG
 *
 *  @brief
 *    An implicitly encoded TLV tag was encountered,
 *    but an implicit profile id has not been defined.
 *
 */
#define MATTER_ERROR_UNKNOWN_IMPLICIT_TLV_TAG                    _MATTER_ERROR(37)

/**
 *  @def MATTER_ERROR_WRONG_TLV_TYPE
 *
 *  @brief
 *    A TLV type is wrong.
 *
 */
#define MATTER_ERROR_WRONG_TLV_TYPE                              _MATTER_ERROR(38)

/**
 *  @def MATTER_ERROR_TLV_CONTAINER_OPEN
 *
 *  @brief
 *    A TLV container is unexpectedly open.
 *
 */
#define MATTER_ERROR_TLV_CONTAINER_OPEN                          _MATTER_ERROR(39)

/**
 *  @def MATTER_ERROR_INVALID_TRANSFER_MODE
 *
 *  @brief
 *    A transfer mode is invalid.
 *
 */
#define MATTER_ERROR_INVALID_TRANSFER_MODE                       _MATTER_ERROR(40)

/**
 *  @def MATTER_ERROR_INVALID_PROFILE_ID
 *
 *  @brief
 *    A profile id is invalid.
 *
 */
#define MATTER_ERROR_INVALID_PROFILE_ID                          _MATTER_ERROR(41)

/**
 *  @def MATTER_ERROR_INVALID_MESSAGE_TYPE
 *
 *  @brief
 *    A message type is invalid.
 *
 */
#define MATTER_ERROR_INVALID_MESSAGE_TYPE                        _MATTER_ERROR(42)

/**
 *  @def MATTER_ERROR_UNEXPECTED_TLV_ELEMENT
 *
 *  @brief
 *    An unexpected TLV element was encountered.
 *
 */
#define MATTER_ERROR_UNEXPECTED_TLV_ELEMENT                      _MATTER_ERROR(43)

/**
 *  @def MATTER_ERROR_STATUS_REPORT_RECEIVED
 *
 *  @brief
 *    A status report is received from a peer node.
 *
 */
#define MATTER_ERROR_STATUS_REPORT_RECEIVED                      _MATTER_ERROR(44)

/**
 *  @def MATTER_ERROR_NOT_IMPLEMENTED
 *
 *  @brief
 *    A requested function or feature is not implemented.
 *
 */
#define MATTER_ERROR_NOT_IMPLEMENTED                             _MATTER_ERROR(45)

/**
 *  @def MATTER_ERROR_INVALID_ADDRESS
 *
 *  @brief
 *    An address is invalid.
 *
 */
#define MATTER_ERROR_INVALID_ADDRESS                             _MATTER_ERROR(46)

/**
 *  @def MATTER_ERROR_INVALID_ARGUMENT
 *
 *  @brief
 *    An argument is invalid.
 *
 */
#define MATTER_ERROR_INVALID_ARGUMENT                            _MATTER_ERROR(47)

/**
 *  @def MATTER_ERROR_INVALID_PATH_LIST
 *
 *  @brief
 *    A TLV path list is invalid.
 *
 */
#define MATTER_ERROR_INVALID_PATH_LIST                           _MATTER_ERROR(48)

/**
 *  @def MATTER_ERROR_INVALID_DATA_LIST
 *
 *  @brief
 *    A TLV data list is invalid.
 *
 */
#define MATTER_ERROR_INVALID_DATA_LIST                           _MATTER_ERROR(49)

/**
 *  @def MATTER_ERROR_TIMEOUT
 *
 *  @brief
 *    A request timed out.
 *
 */
#define MATTER_ERROR_TIMEOUT                                     _MATTER_ERROR(50)

/**
 *  @def MATTER_ERROR_INVALID_DEVICE_DESCRIPTOR
 *
 *  @brief
 *    A device descriptor is invalid.
 *
 */
#define MATTER_ERROR_INVALID_DEVICE_DESCRIPTOR                   _MATTER_ERROR(51)

/**
 *  @def MATTER_ERROR_UNSUPPORTED_DEVICE_DESCRIPTOR_VERSION
 *
 *  @brief
 *    A device descriptor version is unsupported.
 *
 */
#define MATTER_ERROR_UNSUPPORTED_DEVICE_DESCRIPTOR_VERSION       _MATTER_ERROR(52)

/**
 *  @def MATTER_END_OF_INPUT
 *
 *  @brief
 *    An input ended.
 *
 */
#define MATTER_END_OF_INPUT                                      _MATTER_ERROR(53)

/**
 *  @def MATTER_ERROR_RATE_LIMIT_EXCEEDED
 *
 *  @brief
 *    A rate limit is exceeded.
 *
 */
#define MATTER_ERROR_RATE_LIMIT_EXCEEDED                         _MATTER_ERROR(54)

/**
 *  @def MATTER_ERROR_SECURITY_MANAGER_BUSY
 *
 *  @brief
 *    A security manager is busy.
 *
 */
#define MATTER_ERROR_SECURITY_MANAGER_BUSY                       _MATTER_ERROR(55)

/**
 *  @def MATTER_ERROR_INVALID_PASE_PARAMETER
 *
 *  @brief
 *    A PASE parameter is invalid.
 *
 */
#define MATTER_ERROR_INVALID_PASE_PARAMETER                      _MATTER_ERROR(56)

/**
 *  @def MATTER_ERROR_PASE_SUPPORTS_ONLY_CONFIG1
 *
 *  @brief
 *    PASE supports only config1.
 *
 */
#define MATTER_ERROR_PASE_SUPPORTS_ONLY_CONFIG1                  _MATTER_ERROR(57)

/**
 *  @def MATTER_ERROR_KEY_CONFIRMATION_FAILED
 *
 *  @brief
 *    A key confirmation failed.
 *
 */
#define MATTER_ERROR_KEY_CONFIRMATION_FAILED                     _MATTER_ERROR(58)

/**
 *  @def MATTER_ERROR_INVALID_USE_OF_SESSION_KEY
 *
 *  @brief
 *    A use of session key is invalid.
 *
 */
#define MATTER_ERROR_INVALID_USE_OF_SESSION_KEY                  _MATTER_ERROR(59)

/**
 *  @def MATTER_ERROR_CONNECTION_CLOSED_UNEXPECTEDLY
 *
 *  @brief
 *    A connection is closed unexpectedly.
 *
 */
#define MATTER_ERROR_CONNECTION_CLOSED_UNEXPECTEDLY              _MATTER_ERROR(60)

/**
 *  @def MATTER_ERROR_MISSING_TLV_ELEMENT
 *
 *  @brief
 *    A TLV element is missing.
 *
 */
#define MATTER_ERROR_MISSING_TLV_ELEMENT                         _MATTER_ERROR(61)

/**
 *  @def MATTER_ERROR_RANDOM_DATA_UNAVAILABLE
 *
 *  @brief
 *    Secure random data is not available.
 *
 */
#define MATTER_ERROR_RANDOM_DATA_UNAVAILABLE                     _MATTER_ERROR(62)

/**
 *  @def MATTER_ERROR_UNSUPPORTED_HOST_PORT_ELEMENT
 *
 *  @brief
 *    A type in host/port list is unsupported.
 *
 */
#define MATTER_ERROR_UNSUPPORTED_HOST_PORT_ELEMENT               _MATTER_ERROR(63)

/**
 *  @def MATTER_ERROR_INVALID_HOST_SUFFIX_INDEX
 *
 *  @brief
 *    A suffix index in host/port list is invalid.
 *
 */
#define MATTER_ERROR_INVALID_HOST_SUFFIX_INDEX                   _MATTER_ERROR(64)

/**
 *  @def MATTER_ERROR_HOST_PORT_LIST_EMPTY
 *
 *  @brief
 *    A host/port list is empty.
 *
 */
#define MATTER_ERROR_HOST_PORT_LIST_EMPTY                        _MATTER_ERROR(65)

/**
 *  @def MATTER_ERROR_UNSUPPORTED_AUTH_MODE
 *
 *  @brief
 *    An authentication mode is unsupported.
 *
 */
#define MATTER_ERROR_UNSUPPORTED_AUTH_MODE                       _MATTER_ERROR(66)

/**
 *  @def MATTER_ERROR_INVALID_SERVICE_EP
 *
 *  @brief
 *    A service endpoint is invalid.
 *
 */
#define MATTER_ERROR_INVALID_SERVICE_EP                          _MATTER_ERROR(67)

/**
 *  @def MATTER_ERROR_INVALID_DIRECTORY_ENTRY_TYPE
 *
 *  @brief
 *    A directory entry type is unknown.
 *
 */
#define MATTER_ERROR_INVALID_DIRECTORY_ENTRY_TYPE                _MATTER_ERROR(68)

/**
 *  @def MATTER_ERROR_FORCED_RESET
 *
 *  @brief
 *    A service manager is forced to reset.
 *
 */
#define MATTER_ERROR_FORCED_RESET                                _MATTER_ERROR(69)

/**
 *  @def MATTER_ERROR_NO_ENDPOINT
 *
 *  @brief
 *    No endpoint is available.
 *
 */
#define MATTER_ERROR_NO_ENDPOINT                                 _MATTER_ERROR(70)

/**
 *  @def MATTER_ERROR_INVALID_DESTINATION_NODE_ID
 *
 *  @brief
 *    A destination node id is invalid.
 *
 */
#define MATTER_ERROR_INVALID_DESTINATION_NODE_ID                 _MATTER_ERROR(71)

/**
 *  @def MATTER_ERROR_NOT_CONNECTED
 *
 *  @brief
 *    The operation cannot be performed because the underlying object is not
 *    connected.
 *
 */
#define MATTER_ERROR_NOT_CONNECTED                               _MATTER_ERROR(72)

/**
 *  @def MATTER_ERROR_NO_SW_UPDATE_AVAILABLE
 *
 *  @brief
 *    No software update is available.
 *
 */
#define MATTER_ERROR_NO_SW_UPDATE_AVAILABLE                      _MATTER_ERROR(73)

/**
 *  @def MATTER_ERROR_CA_CERT_NOT_FOUND
 *
 *  @brief
 *    CA certificate is not found.
 *
 */
#define MATTER_ERROR_CA_CERT_NOT_FOUND                           _MATTER_ERROR(74)

/**
 *  @def MATTER_ERROR_CERT_PATH_LEN_CONSTRAINT_EXCEEDED
 *
 *  @brief
 *    A certificate path length exceeds the constraint.
 *
 */
#define MATTER_ERROR_CERT_PATH_LEN_CONSTRAINT_EXCEEDED           _MATTER_ERROR(75)

/**
 *  @def MATTER_ERROR_CERT_PATH_TOO_LONG
 *
 *  @brief
 *    A certificate path is too long.
 *
 */
#define MATTER_ERROR_CERT_PATH_TOO_LONG                          _MATTER_ERROR(76)

/**
 *  @def MATTER_ERROR_CERT_USAGE_NOT_ALLOWED
 *
 *  @brief
 *    A requested certificate usage is not allowed.
 *
 */
#define MATTER_ERROR_CERT_USAGE_NOT_ALLOWED                      _MATTER_ERROR(77)

/**
 *  @def MATTER_ERROR_CERT_EXPIRED
 *
 *  @brief
 *    A certificate expired.
 *
 */
#define MATTER_ERROR_CERT_EXPIRED                                _MATTER_ERROR(78)

/**
 *  @def MATTER_ERROR_CERT_NOT_VALID_YET
 *
 *  @brief
 *    A certificate is not valid yet.
 *
 */
#define MATTER_ERROR_CERT_NOT_VALID_YET                          _MATTER_ERROR(79)

/**
 *  @def MATTER_ERROR_UNSUPPORTED_CERT_FORMAT
 *
 *  @brief
 *    A certificate format is unsupported.
 *
 */
#define MATTER_ERROR_UNSUPPORTED_CERT_FORMAT                     _MATTER_ERROR(80)

/**
 *  @def MATTER_ERROR_UNSUPPORTED_ELLIPTIC_CURVE
 *
 *  @brief
 *    An elliptic curve is unsupported.
 *
 */
#define MATTER_ERROR_UNSUPPORTED_ELLIPTIC_CURVE                  _MATTER_ERROR(81)

/**
 *  @def MATTER_CERT_NOT_USED
 *
 *  @brief
 *    A certificate was not used during the chain validation.
 *
 */
#define MATTER_CERT_NOT_USED                                     _MATTER_ERROR(82)

/**
 *  @def MATTER_ERROR_CERT_NOT_FOUND
 *
 *  @brief
 *    A certificate is not found.
 *
 */
#define MATTER_ERROR_CERT_NOT_FOUND                              _MATTER_ERROR(83)

/**
 *  @def MATTER_ERROR_INVALID_CASE_PARAMETER
 *
 *  @brief
 *    A CASE parameter is invalid.
 *
 */
#define MATTER_ERROR_INVALID_CASE_PARAMETER                      _MATTER_ERROR(84)

/**
 *  @def MATTER_ERROR_UNSUPPORTED_CASE_CONFIGURATION
 *
 *  @brief
 *    A CASE configuration is unsupported.
 *
 */
#define MATTER_ERROR_UNSUPPORTED_CASE_CONFIGURATION              _MATTER_ERROR(85)

/**
 *  @def MATTER_ERROR_CERT_LOAD_FAIL
 *
 *  @brief
 *    A certificate load failed.
 *
 */
#define MATTER_ERROR_CERT_LOAD_FAIL                              _MATTER_ERROR(86)

/**
 *  @def MATTER_ERROR_CERT_NOT_TRUSTED
 *
 *  @brief
 *    A certificate is not trusted.
 *
 */
#define MATTER_ERROR_CERT_NOT_TRUSTED                            _MATTER_ERROR(87)

/**
 *  @def MATTER_ERROR_INVALID_ACCESS_TOKEN
 *
 *  @brief
 *    An access token is invalid.
 *
 */
#define MATTER_ERROR_INVALID_ACCESS_TOKEN                        _MATTER_ERROR(88)

/**
 *  @def MATTER_ERROR_WRONG_CERT_SUBJECT
 *
 *  @brief
 *    A certificate subject is wrong.
 *
 */
#define MATTER_ERROR_WRONG_CERT_SUBJECT                          _MATTER_ERROR(89)

// deprecated alias
#define MATTER_ERROR_WRONG_CERTIFICATE_SUBJECT MATTER_ERROR_WRONG_CERT_SUBJECT

/**
 *  @def MATTER_ERROR_INVALID_PROVISIONING_BUNDLE
 *
 *  @brief
 *    A provisioning bundle is invalid.
 *
 */
#define MATTER_ERROR_INVALID_PROVISIONING_BUNDLE                 _MATTER_ERROR(90)

/**
 *  @def MATTER_ERROR_PROVISIONING_BUNDLE_DECRYPTION_ERROR
 *
 *  @brief
 *    A provision bundle encountered a decryption error.
 *
 */
#define MATTER_ERROR_PROVISIONING_BUNDLE_DECRYPTION_ERROR        _MATTER_ERROR(91)

/**
 *  @def MATTER_ERROR_WRONG_NODE_ID
 *
 *  @brief
 *    A node id is wrong.
 *
 */
#define MATTER_ERROR_WRONG_NODE_ID                               _MATTER_ERROR(92)

/**
 *  @def MATTER_ERROR_CONN_ACCEPTED_ON_WRONG_PORT
 *
 *  @brief
 *    A connection is accepted on a wrong port.
 *
 */
#define MATTER_ERROR_CONN_ACCEPTED_ON_WRONG_PORT                 _MATTER_ERROR(93)

/**
 *  @def MATTER_ERROR_CALLBACK_REPLACED
 *
 *  @brief
 *    An application callback has been replaced.
 *
 */
#define MATTER_ERROR_CALLBACK_REPLACED                           _MATTER_ERROR(94)

/**
 *  @def MATTER_ERROR_NO_CASE_AUTH_DELEGATE
 *
 *  @brief
 *    No CASE authentication delegate is set.
 *
 */
#define MATTER_ERROR_NO_CASE_AUTH_DELEGATE                       _MATTER_ERROR(95)

/**
 *  @def MATTER_ERROR_DEVICE_LOCATE_TIMEOUT
 *
 *  @brief
 *    The attempt to locate device timed out.
 *
 */
#define MATTER_ERROR_DEVICE_LOCATE_TIMEOUT                       _MATTER_ERROR(96)

/**
 *  @def MATTER_ERROR_DEVICE_CONNECT_TIMEOUT
 *
 *  @brief
 *    The attempt to connect device timed out.
 *
 */
#define MATTER_ERROR_DEVICE_CONNECT_TIMEOUT                      _MATTER_ERROR(97)

/**
 *  @def MATTER_ERROR_DEVICE_AUTH_TIMEOUT
 *
 *  @brief
 *    The attempt to authenticate device timed out.
 *
 */
#define MATTER_ERROR_DEVICE_AUTH_TIMEOUT                         _MATTER_ERROR(98)

/**
 *  @def MATTER_ERROR_MESSAGE_NOT_ACKNOWLEDGED
 *
 *  @brief
 *    A message is not acknowledged after max retries.
 *
 */
#define MATTER_ERROR_MESSAGE_NOT_ACKNOWLEDGED                    _MATTER_ERROR(99)

/**
 *  @def MATTER_ERROR_RETRANS_TABLE_FULL
 *
 *  @brief
 *    A retransmission table is already full.
 *
 */
#define MATTER_ERROR_RETRANS_TABLE_FULL                          _MATTER_ERROR(100)

/**
 *  @def MATTER_ERROR_INVALID_ACK_ID
 *
 *  @brief
 *    An acknowledgment id is invalid.
 *
 */
#define MATTER_ERROR_INVALID_ACK_ID                              _MATTER_ERROR(101)

/**
 *  @def MATTER_ERROR_SEND_THROTTLED
 *
 *  @brief
 *    A send is throttled.
 *
 */
#define MATTER_ERROR_SEND_THROTTLED                              _MATTER_ERROR(102)

/**
 *  @def MATTER_ERROR_WRONG_MSG_VERSION_FOR_EXCHANGE
 *
 *  @brief
 *    A message version is not supported by the current exchange context.
 *
 */
#define MATTER_ERROR_WRONG_MSG_VERSION_FOR_EXCHANGE              _MATTER_ERROR(103)

/**
 *  @def MATTER_ERROR_TRANSACTION_CANCELED
 *
 *  @brief
 *    A transaction is cancelled.
 *
 */
#define MATTER_ERROR_TRANSACTION_CANCELED                        _MATTER_ERROR(104)

/**
 *  @def MATTER_ERROR_LISTENER_ALREADY_STARTED
 *
 *  @brief
 *    A listener has already started.
 *
 */
#define MATTER_ERROR_LISTENER_ALREADY_STARTED                    _MATTER_ERROR(105)

/**
 *  @def MATTER_ERROR_LISTENER_ALREADY_STOPPED
 *
 *  @brief
 *    A listener has already stopped.
 *
 */
#define MATTER_ERROR_LISTENER_ALREADY_STOPPED                    _MATTER_ERROR(106)

/**
 *  @def MATTER_ERROR_UNKNOWN_TOPIC
 *
 *  @brief
 *    A topic ID was unknown to the recipient.
 *
 */
#define MATTER_ERROR_UNKNOWN_TOPIC                               _MATTER_ERROR(107)

/**
 *  @def MATTER_ERROR_UNSUPPORTED_MATTER_FEATURE
 *
 *  @brief
 *    A Matter feature is unsupported.
 *
 */
#define MATTER_ERROR_UNSUPPORTED_MATTER_FEATURE                   _MATTER_ERROR(108)

/**
 *  @def MATTER_ERROR_PASE_RECONFIGURE_REQUIRED
 *
 *  @brief
 *    PASE is required to reconfigure.
 *
 */
#define MATTER_ERROR_PASE_RECONFIGURE_REQUIRED                   _MATTER_ERROR(109)

/**
 *  @def MATTER_ERROR_INVALID_PASE_CONFIGURATION
 *
 *  @brief
 *    A PASE configuration is invalid.
 *
 */
#define MATTER_ERROR_INVALID_PASE_CONFIGURATION                  _MATTER_ERROR(110)

/**
 *  @def MATTER_ERROR_NO_COMMON_PASE_CONFIGURATIONS
 *
 *  @brief
 *    No PASE configuration is in common.
 *
 */
#define MATTER_ERROR_NO_COMMON_PASE_CONFIGURATIONS               _MATTER_ERROR(111)

/**
 *  @def MATTER_ERROR_UNSOLICITED_MSG_NO_ORIGINATOR
 *
 *  @brief
 *    An unsolicited message with the originator bit clear.
 *
 */
#define MATTER_ERROR_UNSOLICITED_MSG_NO_ORIGINATOR               _MATTER_ERROR(112)

/**
 *  @def MATTER_ERROR_INVALID_FABRIC_ID
 *
 *  @brief
 *    A fabric id is invalid.
 *
 */
#define MATTER_ERROR_INVALID_FABRIC_ID                           _MATTER_ERROR(113)

/**
 *  @def MATTER_ERROR_UNSUPPORTED_TUNNEL_VERSION
 *
 *  @brief
 *    A tunnel version is unsupported.
 *
 */
#define MATTER_ERROR_UNSUPPORTED_TUNNEL_VERSION                  _MATTER_ERROR(114)

/**
 *  @def MATTER_ERROR_TUNNEL_NEXTHOP_TABLE_FULL
 *
 *  @brief
 *    A tunnel nexthop table is full.
 *
 */
#define MATTER_ERROR_TUNNEL_NEXTHOP_TABLE_FULL                   _MATTER_ERROR(115)

/**
 *  @def MATTER_ERROR_TUNNEL_SERVICE_QUEUE_FULL
 *
 *  @brief
 *    A tunnel service queue is full.
 *
 */
#define MATTER_ERROR_TUNNEL_SERVICE_QUEUE_FULL                   _MATTER_ERROR(116)

/**
 *  @def MATTER_ERROR_DRBG_ENTROPY_SOURCE_FAILED
 *
 *  @brief
 *    DRBG entropy source failed to generate entropy data.
 *
 */
#define MATTER_ERROR_DRBG_ENTROPY_SOURCE_FAILED                  _MATTER_ERROR(117)

/**
 *  @def MATTER_ERROR_TLV_TAG_NOT_FOUND
 *
 *  @brief
 *    A specified TLV tag was not found.
 *
 */
#define MATTER_ERROR_TLV_TAG_NOT_FOUND                           _MATTER_ERROR(118)

/**
 *  @def MATTER_ERROR_INVALID_TOKENPAIRINGBUNDLE
 *
 *  @brief
 *    A token pairing bundle is invalid.
 *
 */
#define MATTER_ERROR_INVALID_TOKENPAIRINGBUNDLE                  _MATTER_ERROR(119)

/**
 *  @def MATTER_ERROR_UNSUPPORTED_TOKENPAIRINGBUNDLE_VERSION
 *
 *  @brief
 *    A token pairing bundle is invalid.
 *
 */
#define MATTER_ERROR_UNSUPPORTED_TOKENPAIRINGBUNDLE_VERSION      _MATTER_ERROR(120)

/**
 *  @def MATTER_ERROR_NO_TAKE_AUTH_DELEGATE
 *
 *  @brief
 *    No TAKE authentication delegate is set.
 *
 */
#define MATTER_ERROR_NO_TAKE_AUTH_DELEGATE                       _MATTER_ERROR(121)

/**
 *  @def MATTER_ERROR_TAKE_RECONFIGURE_REQUIRED
 *
 *  @brief
 *    TAKE requires a reconfigure.
 *
 */
#define MATTER_ERROR_TAKE_RECONFIGURE_REQUIRED                   _MATTER_ERROR(122)

/**
 *  @def MATTER_ERROR_TAKE_REAUTH_POSSIBLE
 *
 *  @brief
 *    TAKE can do a reauthentication.
 *
 */
#define MATTER_ERROR_TAKE_REAUTH_POSSIBLE                        _MATTER_ERROR(123)

/**
 *  @def MATTER_ERROR_INVALID_TAKE_PARAMETER
 *
 *  @brief
 *    Received an invalid TAKE paramter.
 *
 */
#define MATTER_ERROR_INVALID_TAKE_PARAMETER                      _MATTER_ERROR(124)

/**
 *  @def MATTER_ERROR_UNSUPPORTED_TAKE_CONFIGURATION
 *
 *  @brief
 *    This configuration is not supported by TAKE.
 *
 */
#define MATTER_ERROR_UNSUPPORTED_TAKE_CONFIGURATION              _MATTER_ERROR(125)

/**
 *  @def MATTER_ERROR_TAKE_TOKEN_IDENTIFICATION_FAILED
 *
 *  @brief
 *    The TAKE Token Identification failed.
 *
 */
#define MATTER_ERROR_TAKE_TOKEN_IDENTIFICATION_FAILED            _MATTER_ERROR(126)

/**
 *  @def MATTER_ERROR_KEY_NOT_FOUND_FROM_PEER
 *
 *  @brief
 *    The encryption key is not found error received from a peer node.
 *
 */
#define MATTER_ERROR_KEY_NOT_FOUND_FROM_PEER                     _MATTER_ERROR(127)

/**
 *  @def MATTER_ERROR_WRONG_ENCRYPTION_TYPE_FROM_PEER
 *
 *  @brief
 *    The wrong encryption type error received from a peer node.
 *
 */
#define MATTER_ERROR_WRONG_ENCRYPTION_TYPE_FROM_PEER             _MATTER_ERROR(128)

/**
 *  @def MATTER_ERROR_UNKNOWN_KEY_TYPE_FROM_PEER
 *
 *  @brief
 *    The unknown key type error received from a peer node.
 *
 */
#define MATTER_ERROR_UNKNOWN_KEY_TYPE_FROM_PEER                  _MATTER_ERROR(129)

/**
 *  @def MATTER_ERROR_INVALID_USE_OF_SESSION_KEY_FROM_PEER
 *
 *  @brief
 *    The invalid use of session key error received from a peer node.
 *
 */
#define MATTER_ERROR_INVALID_USE_OF_SESSION_KEY_FROM_PEER        _MATTER_ERROR(130)

/**
 *  @def MATTER_ERROR_UNSUPPORTED_ENCRYPTION_TYPE_FROM_PEER
 *
 *  @brief
 *    An unsupported encryption type error received from a peer node.
 *
 */
#define MATTER_ERROR_UNSUPPORTED_ENCRYPTION_TYPE_FROM_PEER       _MATTER_ERROR(131)

/**
 *  @def MATTER_ERROR_INTERNAL_KEY_ERROR_FROM_PEER
 *
 *  @brief
 *    The internal key error received from a peer node.
 *
 */
#define MATTER_ERROR_INTERNAL_KEY_ERROR_FROM_PEER                _MATTER_ERROR(132)

/**
 *  @def MATTER_ERROR_INVALID_KEY_ID
 *
 *  @brief
 *    A key id is invalid.
 *
 */
#define MATTER_ERROR_INVALID_KEY_ID                              _MATTER_ERROR(133)

/**
 *  @def MATTER_ERROR_INVALID_TIME
 *
 *  @brief
 *    Time has invalid value.
 *
 */
#define MATTER_ERROR_INVALID_TIME                                _MATTER_ERROR(134)

/**
 *  @def MATTER_ERROR_TUNNEL_PEER_ENTRY_NOT_FOUND
 *
 *  @brief
 *    A tunnel shortcut peer entry not found in the cache.
 *
 */
#define MATTER_ERROR_TUNNEL_PEER_ENTRY_NOT_FOUND                 _MATTER_ERROR(135)

/**
 *  @def MATTER_ERROR_LOCKING_FAILURE
 *
 *  @brief
 *    Failure to acquire or release an OS provided mutex.
 *
 */
#define MATTER_ERROR_LOCKING_FAILURE                             _MATTER_ERROR(136)

/**
 *  @def MATTER_ERROR_UNSUPPORTED_PASSCODE_CONFIG
 *
 *  @brief
 *    A passcode encryption configuration is unsupported.
 *
 */
#define MATTER_ERROR_UNSUPPORTED_PASSCODE_CONFIG                 _MATTER_ERROR(137)

/**
 *  @def MATTER_ERROR_PASSCODE_AUTHENTICATION_FAILED
 *
 *  @brief
 *    The Matter passcode authentication failed.
 *
 */
#define MATTER_ERROR_PASSCODE_AUTHENTICATION_FAILED              _MATTER_ERROR(138)

/**
 *  @def MATTER_ERROR_PASSCODE_FINGERPRINT_FAILED
 *
 *  @brief
 *    The Matter passcode fingerprint failed.
 *
 */
#define MATTER_ERROR_PASSCODE_FINGERPRINT_FAILED                 _MATTER_ERROR(139)

/**
 *  @def MATTER_ERROR_TUNNEL_FORCE_ABORT
 *
 *  @brief
 *    The Matter error code to be used with the API for stopping
 *    the tunnel to enforce it to abort its TCP connection and return
 *    synchronously to the caller.
 *
 */
#define MATTER_ERROR_TUNNEL_FORCE_ABORT                          _MATTER_ERROR(140)

/**
 *  @def MATTER_ERROR_SERIALIZATION_ELEMENT_NULL
 *
 *  @brief
 *      The element of the struct is null.
 *
 */
#define MATTER_ERROR_SERIALIZATION_ELEMENT_NULL                  _MATTER_ERROR(141)

/**
 *  @def MATTER_ERROR_WRONG_CERT_SIGNATURE_ALGORITHM
 *
 *  @brief
 *    The certificate was not signed using the required signature algorithm.
 *
 */
#define MATTER_ERROR_WRONG_CERT_SIGNATURE_ALGORITHM              _MATTER_ERROR(142)

/**
 *  @def MATTER_ERROR_WRONG_MATTER_SIGNATURE_ALGORITHM
 *
 *  @brief
 *    The Matter signature was not signed using the required signature algorithm.
 *
 */
#define MATTER_ERROR_WRONG_MATTER_SIGNATURE_ALGORITHM             _MATTER_ERROR(143)

/**
 *  @def MATTER_ERROR_IM_SCHEMA_MISMATCH
 *
 *  @brief
 *    A mismatch in schema was encountered.
 *
 */
#define MATTER_ERROR_IM_SCHEMA_MISMATCH                         _MATTER_ERROR(144)

/**
 *  @def MATTER_ERROR_INVALID_INTEGER_VALUE
 *
 *  @brief
 *    An integer does not have the kind of value we expect.
 *
 */
#define MATTER_ERROR_INVALID_INTEGER_VALUE                       _MATTER_ERROR(145)

/**
 *  @def MATTER_ERROR_CASE_RECONFIG_REQUIRED
 *
 *  @brief
 *    CASE is required to reconfigure.
 *
 */
#define MATTER_ERROR_CASE_RECONFIG_REQUIRED                      _MATTER_ERROR(146)

/**
 *  @def MATTER_ERROR_TOO_MANY_CASE_RECONFIGURATIONS
 *
 *  @brief
 *    Too many CASE reconfigurations were received.
 *
 */
#define MATTER_ERROR_TOO_MANY_CASE_RECONFIGURATIONS              _MATTER_ERROR(147)

/**
 *  @def MATTER_ERROR_BAD_REQUEST
 *
 *  @brief
 *    The request cannot be processed or fulfilled
 *
 */
#define MATTER_ERROR_BAD_REQUEST                                 _MATTER_ERROR(148)

/**
 *  @def MATTER_ERROR_INVALID_MESSAGE_FLAG
 *
 *  @brief
 *    One or more message flags have invalid value.
 *
 */
#define MATTER_ERROR_INVALID_MESSAGE_FLAG                        _MATTER_ERROR(149)

/**
 *  @def MATTER_ERROR_KEY_EXPORT_RECONFIGURE_REQUIRED
 *
 *  @brief
 *    Key export protocol required to reconfigure.
 *
 */
#define MATTER_ERROR_KEY_EXPORT_RECONFIGURE_REQUIRED             _MATTER_ERROR(150)

/**
 *  @def MATTER_ERROR_INVALID_KEY_EXPORT_CONFIGURATION
 *
 *  @brief
 *    A key export protocol configuration is invalid.
 *
 */
#define MATTER_ERROR_INVALID_KEY_EXPORT_CONFIGURATION            _MATTER_ERROR(151)

/**
 *  @def MATTER_ERROR_NO_COMMON_KEY_EXPORT_CONFIGURATIONS
 *
 *  @brief
 *    No key export protocol configuration is in common.
 *
 */
#define MATTER_ERROR_NO_COMMON_KEY_EXPORT_CONFIGURATIONS         _MATTER_ERROR(152)

/**
 *  @def MATTER_ERROR_NO_KEY_EXPORT_DELEGATE
 *
 *  @brief
 *    No key export delegate is set.
 *
 */
#define MATTER_ERROR_NO_KEY_EXPORT_DELEGATE                      _MATTER_ERROR(153)

/**
 *  @def MATTER_ERROR_UNAUTHORIZED_KEY_EXPORT_REQUEST
 *
 *  @brief
 *    Unauthorized key export request.
 *
 */
#define MATTER_ERROR_UNAUTHORIZED_KEY_EXPORT_REQUEST             _MATTER_ERROR(154)

/**
 *  @def MATTER_ERROR_UNAUTHORIZED_KEY_EXPORT_RESPONSE
 *
 *  @brief
 *    Unauthorized key export response.
 *
 */
#define MATTER_ERROR_UNAUTHORIZED_KEY_EXPORT_RESPONSE            _MATTER_ERROR(155)

/**
 *  @def MATTER_ERROR_EXPORTED_KEY_AUTHENTICATION_FAILED
 *
 *  @brief
 *    The Matter exported encrypted key authentication failed.
 *
 */
#define MATTER_ERROR_EXPORTED_KEY_AUTHENTICATION_FAILED          _MATTER_ERROR(156)

/**
 *  @def MATTER_ERROR_TOO_MANY_SHARED_SESSION_END_NODES
 *
 *  @brief
 *    The number of shared secure sessions end nodes exceeds
 *    the maximum limit.
 *
 */
#define MATTER_ERROR_TOO_MANY_SHARED_SESSION_END_NODES           _MATTER_ERROR(157)

/**
 * @def MATTER_ERROR_IM_MALFORMED_DATA_ELEMENT
 *
 * @brief
 *   The IM DataElement is malformed: it either does not contain
 *   the required elements, or it contais both the MergeData element
 *   and DeletedDictionaryKeyList.
 */
#define MATTER_ERROR_IM_MALFORMED_DATA_ELEMENT                  _MATTER_ERROR(158)

/**
 * @def MATTER_ERROR_WRONG_CERT_TYPE
 *
 * @brief
 *   The presented certificate was of the wrong type.
 */
#define MATTER_ERROR_WRONG_CERT_TYPE                             _MATTER_ERROR(159)

/**
 * @def MATTER_ERROR_INTERNAL
 *
 * @brief
 *   Internal error
 */
#define MATTER_ERROR_INTERNAL                                    _MATTER_ERROR(172)

/**
 *  @}
 */

// !!!!! IMPORTANT !!!!!  If you add new Matter errors, please update the translation
// of error codes to strings in support/ErrorStr.cpp, and add them to unittest
// in test-apps/TestErrorStr.cpp

#endif // MATTER_ERROR_H

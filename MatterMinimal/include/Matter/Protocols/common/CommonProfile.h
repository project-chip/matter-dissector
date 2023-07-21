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
 *      The defines constants for the Matter Common Profile, present in
 *      every Matter device.
 *
 */

#ifndef _COMMON_PROFILE_H
#define _COMMON_PROFILE_H

/**
 *   @namespace matter::Profiles::Common
 *
 *   @brief
 *     This namespace includes all interfaces within Matter for the
 *     Matter Common profile.
 *
 *     The interfaces define message types and status codes.
 */

namespace matter {
namespace Profiles {

namespace General {
// General Profile Status Codes (kMatterProfile_General)

enum
{
    kStatus_SUCCESS             = 0, // Operation completed successfully.
    kStatus_FAILURE             = 1, // Generic failure, additional details may be included in the protocol specific status.
    kStatus_BAD_PRECONDITION    = 2, // Operation was rejected by the system because the system is in an invalid state.
    kStatus_OUT_OF_RANGE        = 3, // A value was out of a required range
    kStatus_BAD_REQUEST         = 4, // A request was unrecognized or malformed
    kStatus_UNSUPPORTED         = 5, // An unrecognized or unsupported request was received
    kStatus_UNEXPECTED          = 6, // A request was not expected at this time
    kStatus_RESOURCE_EXHAUSTED  = 7, // Insufficient resources to process the given request
    kStatus_BUSY                = 8, // Device is busy and cannot handle this request at this time
    kStatus_TIMEOUT             = 9, // A timeout occurred
    kStatus_CONTINUE            = 10, // Context-specific signal to proceed
    kStatus_ABORTED             = 11, // Failure, may be due to a concurrency error.
    kStatus_INVALID_ARGUMENT    = 12, // An invalid/unsupported argument was provided
    kStatus_NOT_FOUND           = 13, // Some requested entity was not found
    kStatus_ALREADY_EXISTS      = 14,  // The sender attempted to create something that already exists
    kStatus_PERMISSION_DENIED   = 15,  // The sender does not have sufficient permissions to execute the requested operations.
    kStatus_DATA_LOSS           = 16,  // Unrecoverable data loss or corruption has occurred.
};

} // namespace General

namespace Common {

// Common Profile Message Types
//
enum
{
    // Message Counter Synchronization Protocol Message Types
    kMsgType_MsgCounterSyncReq = 0x00,
    kMsgType_MsgCounterSyncRsp = 0x01,

    // Reliable Messaging Protocol Message Types
    kMsgType_StandaloneAck = 0x10,

    // Password-based session establishment Message Types
    kMsgType_PBKDFParamRequest  = 0x20,
    kMsgType_PBKDFParamResponse = 0x21,
    kMsgType_PASE_Spake2p1      = 0x22,
    kMsgType_PASE_Spake2p2      = 0x23,
    kMsgType_PASE_Spake2p3      = 0x24,
    kMsgType_PASE_Spake2pError  = 0x2F,

    // Certificate-based session establishment Message Types
    kMsgType_CASE_Sigma1        = 0x30,
    kMsgType_CASE_Sigma2        = 0x31,
    kMsgType_CASE_Sigma3        = 0x32,
    kMsgType_CASE_Sigma2_Resume = 0x33,

    // Common control messages such as status
    kMsgType_StatusReport  = 0x40,

    // ==== DEPRECATED BELOW THIS LINE =====

    //Reliable Messaging Protocol Message Types
    kMsgType_WRMP_Delayed_Delivery    = 3,
    kMsgType_WRMP_Throttle_Flow       = 4
};

// Common Profile Status Codes (kMatterProfile_Common)

enum
{
    kStatus_SESSION_ESTABLISHMENT_SUCCESS   = 0, // Indication that the last session establishment message was successfully processed.
    kStatus_NO_SHARED_TRUST_ROOTS           = 1, // Failure to find a common set of shared roots.
    kStatus_INVALID_PARAMETER               = 2, // Generic failure during session establishment.
    kStatus_CLOSE_SESSION                   = 3, // Indication that the sender will close the current session. See Section 4.9.1.7, “CloseSession” for more details.
    kStatus_BUSY                            = 4, // Indication that the sender cannot currently fulfill the request. See Section 4.9.1.8, “Busy” for more details.
    kStatus_SESSION_NOT_FOUND               = 5, // Indication that the sender does not hold a session matching the enclosed session ID. See Section 4.9.1.9, “Session Not Found” for more details.
};


// Common Profile Data Tags
//
//                                      Value       Tag Category      Element Type      Constraints  Description
//                                      ------------------------------------------------------------------------

enum
{
    kTag_SystemErrorCode              = 0x0001,  // Profile-specific  Unsigned Integer  -            System-specific error
    kTag_SchemaVersion                = 0x0002,  // Profile-specific  Unsigned Integer  0-255        Schema revision
};

} // namespace Common
} // namespace Profiles
} // namespace matter

#endif // _COMMON_PROFILE_H

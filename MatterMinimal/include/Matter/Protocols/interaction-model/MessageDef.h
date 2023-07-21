/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

namespace matter {
namespace Profiles {
namespace InteractionModel {

/**
 * Interaction Model Opcodes
 * See 10.2.1. Protocol OpCodes
 */
enum
{
    kMsgType_StatusResponse             = 0x01,
    kMsgType_ReadRequest                = 0x02,
    kMsgType_SubscribeRequest           = 0x03,
    kMsgType_SubscribeResponse          = 0x04,
    kMsgType_ReportData                 = 0x05,
    kMsgType_WriteRequest               = 0x06,
    kMsgType_WriteResponse              = 0x07,
    kMsgType_InvokeRequest              = 0x08,
    kMsgType_InvokeResponse             = 0x09,
    kMsgType_TimedRequest               = 0x0A,
};

enum
{
    kStatus_InvalidValueInNotification  = 0x20,
    kStatus_InvalidPath                 = 0x21,
    kStatus_ExpiryTimeNotSupported      = 0x22,
    kStatus_NotTimeSyncedYet            = 0x23,
    kStatus_RequestExpiredInTime        = 0x24,
    kStatus_VersionMismatch             = 0x25,
    kStatus_GeneralProtocolError        = 0x26,
    kStatus_SecurityError               = 0x27,
    kStatus_InvalidSubscriptionID       = 0x28,
    kStatus_GeneralSchemaViolation      = 0x29,
};


namespace CommonActionInfo
{
    enum {
        kTag_InteractionModelRevision  = 0xFF,
    };
};

namespace Path
{
    enum
    {
        kTag_InstanceLocator          = 1,

        kTag_ResourceID               = 1,
        kTag_TraitProfileID           = 2,
        kTag_TraitInstanceID          = 3,
    };
};

namespace CommandPathIB
{
    enum
    {
        kTag_Endpoint                 = 0,
        kTag_Cluster                  = 1,
        kTag_Command                  = 2,
    };
};


namespace DataElement
{
    enum
    {
        kTag_Path                     = 0,   // 0
        kTag_Data                     = 1,   //10,

        kTag_Version                  = 2,
        kTag_IsPartialChange          = 3,
    };
};

namespace Event
{
    enum
    {
        kTag_Source                   = 1,
        kTag_Importance               = 2,
        kTag_Id                       = 3,
        kTag_RelatedImportance        = 10,
        kTag_RelatedId                = 11,
        kTag_UTCTimestamp             = 12,
        kTag_SystemTimestamp          = 13,
        kTag_ResourceId               = 14,
        kTag_TraitProfileId           = 15,
        kTag_TraitInstanceId          = 16,
        kTag_Type                     = 17,
        kTag_DeltaUTCTime             = 30,
        kTag_DeltaSystemTime          = 31,
        kTag_Data                     = 50,
    };
};

namespace StatusResponse
{
    enum
    {
        kTag_Status                   = 0,    // uint32
    };
};

namespace ReadRequest
{
    enum
    {
        kTag_AttributeRequests         = 0,    // array[AttributePathIB]
        kTag_EventRequests             = 1,    // array[EventPathIB]
        kTag_EventFilters              = 2,    // array[EventFilterIB]
        kTag_IsFabricFiltered          = 3,    // boolean
        kTag_DataVersionFilters        = 4,    // array[DataVersionFilterIB]
    };
};

namespace ReportData
{
    enum
    {
        kTag_SubscriptionID           = 0,    // uint32
        kTag_AttributeReports         = 1,    // array[AttributeReportIB]
        kTag_EventReports             = 2,    // array[EventReportIB]
        kTag_MoreChunkedMessages      = 3,    // boolean
        kTag_SuppressResponse         = 4,    // boolean
    };
};

namespace SubscribeRequest
{
    enum
    {
        kTag_KeepSubscriptions        = 0,    // boolean
        kTag_MinIntervalFloor         = 1,    // uint16
        kTag_MaxIntervalCeiling       = 2,    // uint16
        kTag_AttributeRequests        = 3,    // array[AttributePathIB]
        kTag_EventRequests            = 4,    // array[EventPathIB]
        kTag_EventFilters             = 5,    // array[EventFilterIB]
        kTag_IsFabricFiltered         = 7,    // boolean
        kTag_DataVersionFilters       = 8,    // array[DataVersionFilterIB]
    };
};

namespace SubscribeResponse
{
    enum
    {
        kTag_SubscriptionID           = 0,    // uint32
        kTag_MaxInterval              = 2,    // uint16
    };
};

namespace WriteRequest
{
    enum
    {
        kTag_SuppressResponse         = 0,    // boolean
        kTag_TimedRequest             = 1,    // boolean
        kTag_WriteRequests            = 2,    // array[AttributeDataIB]
        kTag_MoreChunkedMessages      = 3,    // boolean
    };
};

namespace WriteResponse
{
    enum
    {
        kTag_WriteResponses           = 0,    // array[AttributeStatusIB]
    };
};

namespace InvokeCommandRequest
{
    enum
    {
        kTag_SuppressResponse         = 0,   // boolean
        kTag_TimedRequest             = 1,   // boolean
        kTag_CommandList              = 2,   // array[CommandDataIB]
    };
};

namespace InvokeCommandResponse
{
    enum
    {
        kTag_SuppressResponse         = 0,    // boolean
        kTag_InvokeResponses          = 1,    // array[InvokeResponseIB]
    };
};

/// 10.5.12. CommandDataIB
namespace CommandDataIB
{
    enum
    {
        kTag_Path                     = 0,   // CommandPathIB
        kTag_Data                     = 1,   // variable
    };
};

/// 10.5.13. InvokeResponseIB
namespace InvokeResponseIB
{
    enum
    {
        kTag_Command                  = 0,   // CommandDataIB
        kTag_Status                   = 1,   // CommandStatusIB
    };
};

/// 10.5.14. CommandStatusIB
namespace CommandStatusIB
{
    enum
    {
        kTag_Path                     = 0,   // CommandPathIB
        kTag_Status                   = 1,   // StatusIB
    };
};

/// 10.5.17. StatusIB
namespace StatusIB
{
    enum
    {
        kTag_Status                     = 0,   // uint16_t
        kTag_ClusterStatus              = 1,   // uint16_t
    };
};

}; // InteractionModel
}; // Profiles
}; // matter

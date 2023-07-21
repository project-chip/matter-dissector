/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _BULK_DATA_TRANSFER_CONSTANTS_H
#define _BULK_DATA_TRANSFER_CONSTANTS_H

namespace matter {
namespace Profiles {
namespace BDX_Development {

enum
{
    kMsgType_SendInit =                     0x01,
    kMsgType_SendAccept =                   0x02,
    kMsgType_SendReject =                   0x03,
    kMsgType_ReceiveInit =                  0x04,
    kMsgType_ReceiveAccept =                0x05,
    kMsgType_ReceiveReject =                0x06,
    kMsgType_BlockQuery =                   0x07,
    kMsgType_BlockSend =                    0x08,
    kMsgType_BlockEOF =                     0x09,
    kMsgType_BlockAck =                     0x0A,
    kMsgType_BlockEOFAck =                  0x0B,
    kMsgType_TransferError =                0x0F,
    kMsgType_BlockQueryV1 =                 0x10,
    kMsgType_BlockSendV1 =                  0x11,
    kMsgType_BlockEOFV1 =                   0x12,
    kMsgType_BlockAckV1 =                   0x13,
    kMsgType_BlockEOFAckV1 =                0x14,
};

enum
{
    kMode_SenderDrive =                     0x10,
    kMode_ReceiverDrive =                   0x20,
    kMode_Asynchronous =                    0x40,
};

enum
{
    kRangeCtl_DefiniteLength =              0x01,
    kRangeCtl_StartOffsetPresent =          0x02,
    kRangeCtl_WideRange =                   0x10,
};

enum
{
    kStatus_NoError =                       0x0000,
    kStatus_Overflow =                      0x0011,
    kStatus_LengthTooLarge =                0x0012,
    kStatus_LengthTooShort =                0x0013,
    kStatus_LengthMismatch =                0x0014,
    kStatus_LengthRequired =                0x0015,
    kStatus_BadMessageContents =            0x0016,
    kStatus_BadBlockCounter =               0x0017,
    kStatus_XferFailedUnknownErr =          0x001F,
    kStatus_ServerBadState =                0x0020,
    kStatus_FailureToSend =                 0x0021,
    kStatus_XferMethodNotSupported =        0x0050,
    kStatus_UnknownFile =                   0x0051,
    kStatus_StartOffsetNotSupported =       0x0052,
    kStatus_VersionNotSupported =           0x0053,
    kStatus_Unknown =                       0x005F,
};

} // namespace BDX_Development
} // namespace Profiles
} // namespace matter

#endif // _BULK_DATA_TRANSFER_CONSTANTS_H

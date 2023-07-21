/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _BULK_DATA_TRANSFER_PROFILE_H
#define _BULK_DATA_TRANSFER_PROFILE_H

/**
 *   @namespace matter::Profiles::BulkDataTransfer
 *
 *   @brief
 *     This namespace includes all interfaces within Matter for the
 *     Matter Bulk Data Transfer (BDX) profile.
 */

namespace matter {
namespace Profiles {
namespace BulkDataTransfer {
  // the message type values
  enum {
    kMsgType_SendInit               = 0x01,
    kMsgType_SendAccept             = 0x02,
    kMsgType_SendReject             = 0x03,
    kMsgType_ReceiveInit            = 0x04,
    kMsgType_ReceiveAccept          = 0x05,
    kMsgType_ReceiveReject          = 0x06,
    kMsgType_BlockQuery             = 0x07,
    kMsgType_BlockSend              = 0x08,
    kMsgType_BlockAck               = 0x0A,
    kMsgType_BlockEOF               = 0x09,
    kMsgType_BlockEOFAck            = 0x0B,
    kMsgType_TransferError          = 0x0F,
  };
  /*
   * as described above there are 3 mutually exclusive transfer modes:
   * - sender drive
   * - receiver drive
   * - asynchronous
   * these are set up as bit values so they can be ORed together to
   * reflect device capabilities.
   */
  enum {
    kMode_SenderDrive               = 0x10,
    kMode_ReceiverDrive             = 0x20,
    kMode_Asynchronous              = 0x40,
  };
  /*
   * with respect to range control, there are several options:
   * - definite length, if set then the transfer has definite length
   * - start offset present, if set then the date to be transferred has
   * an initial offset.
   * - wide range, if set then the offset values during the file transfer will
   * be 8 bytes in length. otherwise they will be 4 bytes in length.
   * again, these are defined so as to be interpreted as bit fields.
   */
  enum {
    kRangeCtl_DefiniteLength        = 0x01,
    kRangeCtl_StartOffsetPresent    = 0x02,
    kRangeCtl_WideRange             = 0x10,
  };
  /*
   * status/error codes for BDX
   */
  enum {
    kStatus_Overflow                = 0x0011,
    kStatus_LengthTooShort          = 0x0013,
    kStatus_XferFailedUnknownErr    = 0x001F,
    kStatus_XferMethodNotSupported  = 0x0050,
    kStatus_UnknownFile             = 0x0051,
    kStatus_StartOffsetNotSupported = 0x0052,
    kStatus_Unknown                 = 0x005F,
  };
} // namespace BulkDataTransfer
} // namespace Profiles
} // namespace matter

#endif // _BULK_DATA_TRANSFER_PROFILE_H

/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MATTER_EXCHANGE_MGR_H
#define MATTER_EXCHANGE_MGR_H

namespace matter {

typedef enum MatterExchangeFlags
{
    kMatterExchangeFlag_Initiator           = 0x01,
    kMatterExchangeFlag_AckId               = 0x02,
    kMatterExchangeFlag_NeedsAck            = 0x04,
    kMatterExchangeFlag_SecureExtensions    = 0x08,
    kMatterExchangeFlag_VendorProtocol      = 0x10,
} MatterExchangeFlags;

} // namespace matter

#endif // MATTER_EXCHANGE_MGR_H

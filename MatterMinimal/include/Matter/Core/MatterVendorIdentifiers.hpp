/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MATTER_VENDOR_IDENTIFIERS_HPP
#define MATTER_VENDOR_IDENTIFIERS_HPP

namespace matter {

enum MatterVendorId
{
    kMatterVendor_Common                         = 0x0000,
    kMatterVendor_NestLabs                       = 0x235A,

    kMatterVendor_NotSpecified                   = 0xFFFF
};

}; // namespace matter

#endif // MATTER_VENDOR_IDENTIFIERS_HPP

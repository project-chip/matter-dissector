/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MATTERPROFILES_H_
#define MATTERPROFILES_H_

#include <Matter/Core/MatterVendorIdentifiers.hpp>

namespace matter {
namespace Profiles {

//
// Matter Profile Ids (32-bits max)
//

enum MatterProfileId
{
    kMatterProfile_General                       = (kMatterVendor_Common << 16) | 0xFFFF,
    kMatterProfile_Common                        = (kMatterVendor_Common << 16) | 0x0000,
    kMatterProfile_InteractionModel              = (kMatterVendor_Common << 16) | 0x0001,
    kMatterProfile_BDX                           = (kMatterVendor_Common << 16) | 0x0002, // Buld Data Exchange
    kMatterProfile_UDC                           = (kMatterVendor_Common << 16) | 0x0003, // User Directed Commissioning
    kMatterProfile_Echo                          = (kMatterVendor_Common << 16) | 0x0004,

    kMatterProfile_NetworkProvisioning           = (kMatterVendor_Common << 16) | 0x0003,
    kMatterProfile_Security                      = (kMatterVendor_Common << 16) | 0x1004, // 0x0004
    kMatterProfile_FabricProvisioning            = (kMatterVendor_Common << 16) | 0x0005,
    kMatterProfile_DeviceControl                 = (kMatterVendor_Common << 16) | 0x0006,
    kMatterProfile_Time                          = (kMatterVendor_Common << 16) | 0x0007,
    kMatterProfile_IM                            = (kMatterVendor_Common << 16) | 0x000B,
    kMatterProfile_SWU                           = (kMatterVendor_Common << 16) | 0x000C,
    kMatterProfile_DeviceDescription             = (kMatterVendor_Common << 16) | 0x000E,
    kMatterProfile_ServiceProvisioning           = (kMatterVendor_Common << 16) | 0x000F,
    kMatterProfile_Locale                        = (kMatterVendor_Common << 16) | 0x0011,
    kMatterProfile_ApplicationKeys               = (kMatterVendor_Common << 16) | 0x001D,
    kMatterProfile_DictionaryKey                 = (kMatterVendor_Common << 16) | 0x0021,

    kMatterProfile_NotSpecified                  = (kMatterVendor_NotSpecified << 16) | 0xFFFF,
};

} // namespace Profiles
} // namespace matter


#endif /* MATTERPROFILES_H_ */

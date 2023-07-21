/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MATTER_FABRIC_STATE_H
#define MATTER_FABRIC_STATE_H

#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif

#include <inttypes.h>

namespace matter {

enum
{
    kNodeIdNotSpecified                                 = 0ULL,
    kAnyNodeId                                          = 0xFFFFFFFFFFFFFFFFULL
};

enum
{
    kFabricIdNotSpecified                               = 0ULL,
    kFabricIdDefaultForTest                             = 1ULL,
    kReservedFabricIdStart                              = 0xFFFFFFFFFFFFFF00ULL,
    kMaxFabricId                                        = 0xFFFFFFFFFFFFFFFFULL
};

enum
{
    kPasswordSource_NotSpecified                        = 0x0,
    kPasswordSource_PairingCode                         = 0x1,
    kPasswordSource_Max                                 = 0xF,
};

} // namespace matter

#endif // MATTER_FABRIC_STATE_H

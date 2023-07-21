/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MATTER_TIME_H_
#define MATTER_TIME_H_

// __STDC_CONSTANT_MACROS must be defined for UINT64_C and INT64_C to be defined for pre-C++11 clib
#ifndef __STDC_CONSTANT_MACROS
#define __STDC_CONSTANT_MACROS
#endif // __STDC_CONSTANT_MACROS
#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif // __STDC_LIMIT_MACROS
#include <stdint.h>


namespace matter {
namespace Profiles {
namespace Time {

/// type of a message, used with Matter Exchange
enum
{
    kTimeMessageType_TimeSyncTimeChangeNotification = 0,
    kTimeMessageType_TimeSyncRequest = 1,
    kTimeMessageType_TimeSyncResponse = 2,
};

/// Profile-specific tags used in IM queries for timezone information
enum
{
    kWdmTagTime_Zone_Name = 0x00,      ///< The IANA Timezone name in UTF8-String format
    kWdmTagTime_Zone_POSIX_TZ = 0x01,  ///< The POSIX TZ environment variable in UTF8-String format
    kWdmTagTime_Zone_UTC_Offset = 0x02 ///< The UTC offsets for this timezone, in packed binary format
};

/// Roles a protocol engine can play.
/// for example, a TimeSyncServer could be playing a Server or part of a Coordinator.
/// likewise, a TimeSyncClient could be playing a Client or just part of a Coordinator.
enum TimeSyncRole
{
    kTimeSyncRole_Unknown = 0,
    kTimeSyncRole_Server = 1,
    kTimeSyncRole_Coordinator = 2,
    kTimeSyncRole_Client = 3,
};

} // namespace Time
} // namespace Platform
} // namespace matter

#endif // MATTER_TIME_H_

/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef DEVICECONTROL_H_
#define DEVICECONTROL_H_

namespace matter {
namespace Profiles {
namespace DeviceControl {

enum
{
    kStatusCode_FailSafeAlreadyActive           = 1,
    kStatusCode_NoFailSafeActive                = 2,
    kStatusCode_NoMatchingFailSafeActive        = 3,
    kStatusCode_UnsupportedFailSafeMode         = 4,
    kStatusCode_RemotePassiveRendezvousTimedOut = 5,

    kStatusCode_UnsecuredListenPreempted        = 6,

    kStatusCode_ResetSuccessCloseCon            = 7,
    kStatusCode_ResetNotAllowed                 = 8,
    kStatusCode_NoSystemTestDelegate            = 9
};

enum
{
    kMsgType_ResetConfig                     = 1,
    kMsgType_ArmFailSafe                     = 2,
    kMsgType_DisarmFailSafe                  = 3,
    kMsgType_EnableConnectionMonitor         = 4,
    kMsgType_DisableConnectionMonitor        = 5,
    kMsgType_RemotePassiveRendezvous         = 6,
    kMsgType_RemoteConnectionComplete        = 7,

    kMsgType_StartSystemTest                 = 8,
    kMsgType_StopSystemTest                  = 9
};

enum
{
    kArmMode_New                                = 1,
    kArmMode_Reset                              = 2,
    kArmMode_ResumeExisting                     = 3

};

enum
{
    kResetConfigFlag_All                        = 0x00FF,
    kResetConfigFlag_NetworkConfig              = 0x0001,
    kResetConfigFlag_FabricConfig               = 0x0002,
    kResetConfigFlag_ServiceConfig              = 0x0004,
    kResetConfigFlag_FactoryDefaults            = 0x8000
};

enum
{
    kMessageLength_ResetConfig              = 2,
    kMessageLength_ArmFailsafe              = 5,
    kMessageLength_DisarmFailsafe           = 0,
    kMessageLength_EnableConnectionMonitor  = 4,
    kMessageLength_DisableConnectionMonitor = 0,
    kMessageLength_RemotePassiveRendezvous  = 20,
    kMessageLength_StartSystemTest          = 8,
    kMessageLength_StopSystemTest           = 0,
};

} // namespace DeviceControl
} // namespace Profiles
} // namespace matter

#endif /* DEVICECONTROL_H_ */

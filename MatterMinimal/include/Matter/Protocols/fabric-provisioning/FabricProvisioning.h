/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef FABRICPROVISIONING_H_
#define FABRICPROVISIONING_H_

namespace matter {
namespace Profiles {
namespace FabricProvisioning {

enum
{
    kStatusCode_AlreadyMemberOfFabric           = 1,    /**< The recipient is already a member of a fabric. */
    kStatusCode_NotMemberOfFabric               = 2,    /**< The recipient is not a member of a fabric. */
    kStatusCode_InvalidFabricConfig             = 3     /**< The specified fabric configuration was invalid. */
};

enum
{
    kMsgType_CreateFabric                       = 1,
    kMsgType_LeaveFabric                        = 2,
    kMsgType_GetFabricConfig                    = 3,
    kMsgType_GetFabricConfigComplete            = 4,
    kMsgType_JoinExistingFabric                 = 5
};

enum
{
    // ---- Top-level Data Elements ----
    kTag_FabricConfig                           = 1,    /**< [ structure ] Contains provisioning information for an existing fabric.
                                                               IMPORTANT NOTE: As a convenience to readers, all elements in a FabricConfig
                                                               must be encoded in numeric tag order, at all levels. */

    // ---- Context-specific Tags for FabricConfig Structure ----
    kTag_FabricId                               = 1,    /**< [ uint ] Fabric ID. */
    kTag_FabricKeys                             = 2,    /**< [ array ] List of FabricKey structures. */

    // ---- Context-specific Tags for FabricKey Structure ----
    kTag_FabricSessionId                            = 1,    /**< [ uint ] Matter key ID for fabric key. */
    kTag_EncryptionType                         = 2,    /**< [ uint ] Matter encryption type supported by the key. */
    kTag_DataKey                                = 3,    /**< [ byte-string ] Data encryption key. */
    kTag_IntegrityKey                           = 4,    /**< [ byte-string ] Data integrity key. */
    kTag_KeyScope                               = 5,    /**< [ uint ] Enumerated value identifying the category of devices that can possess
                                                                      the fabric key. */
    kTag_RotationScheme                         = 6,    /**< [ uint ] Enumerated value identifying the rotation scheme for the key. */
    kTag_RemainingLifeTime                      = 7,    /**< [ uint ] Remaining time (in seconds) until key expiration. Absent if lifetime
                                                                      is indefinite or doesn't apply. */
    kTag_RemainingReservedTime                  = 8     /**< [ uint ] Remaining time (in seconds) until key is eligible for use. Absent if
                                                                      key can be used right away. */
};


} // namespace FabricProvisioning
} // namespace Profiles
} // namespace matter

#endif /* FABRICPROVISIONING_H_ */

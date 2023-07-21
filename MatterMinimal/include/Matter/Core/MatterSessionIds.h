/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

/**
 *    @file
 *      This file defines constant enumerations for all Matter key types,
 *      key flags, key Id fields and helper API functions.
 */

#ifndef MATTERKEYS_H_
#define MATTERKEYS_H_

namespace matter {

/**
 *  @class MatterSessionId
 *
 *  @brief
 *    The definition of the Matter Key identifier. This class contains
 *    key types, key flags, key Id fields definition and API functions.
 *
 */
class MatterSessionId
{
private:
    /**
     * @brief
     *   Private Matter key id fields, flags and types.
     */
    enum
    {
        kMask_KeyNumber                                     = 0x00000FFF,  /**< Matter key number field mask. */
        kMask_RootKeyNumber                                 = 0x00000C00,  /**< Application group root key number field mask. */
        kMask_EpochKeyNumber                                = 0x00000380,  /**< Application group epoch key number field mask. */
        kMask_GroupLocalNumber                              = 0x0000007F,  /**< Application group local number field mask. */

        kShift_RootKeyNumber                                = 10,          /**< Application group root key number field shift. */
        kShift_EpochKeyNumber                               = 7,           /**< Application group epoch key number field shift. */
        kShift_GroupLocalNumber                             = 0,           /**< Application group local number field shift. */

        kFlag_UseCurrentEpochKey                            = 0x80000000,  /**< Used to indicate that the key is of logical current type. */

        kTypeModifier_IncorporatesEpochKey                  = 0x00001000,  /**< Used to indicate that the key incorporates group epoch key. */
    };


public:
    /**
     * @brief
     *   Public Matter key id fields, flags and types.
     */
    enum
    {
        /**
         * @brief  Matter key types used for Matter message encryption.
         *
         * @note  16 (out of 32) most significant bits of the message encryption key
         *        type should be zero because only 16 least significant bits of the Id
         *        are encoded in the Matter message.
         *  @{
         */
        kMask_SessionType                                   = 0x0F,        /**< Matter session type field mask. */

        kSessionType_Unicast                                = 0,
        kSessionType_Group                                  = 1,

        kType_None                                          = 0x00000000,  /**< Matter message is unencrypted. */
        kType_General                                       = 0x00001000,  /**< General key type. */
        kType_Session                                       = 0x00002000,  /**< Session key type. */
        kType_AppStaticKey                                  = 0x00004000,  /**< Application static key type. */
        /** Application rotating key type. */
        kType_AppRotatingKey                                = kType_AppStaticKey | kTypeModifier_IncorporatesEpochKey,
        /** @} */

        /**
         * @brief  Matter key types (other than Matter message encryption types).
         *
         * @note  16 (out of 32) most significant bits of these types cannot be all zeros,
         *        because these values are reserved for the Matter message encryption keys only.
         *  @{
         */

        /**
         * @brief  Constituent group key types.
         *  @{
         */
        /** Application group root key type. */
        kType_AppRootKey                                    = 0x00010000,
        /** Application group epoch key type. */
        kType_AppEpochKey                                   = 0x00020000 | kTypeModifier_IncorporatesEpochKey,
        /** Application group master key type. */
        kType_AppGroupMasterKey                             = 0x00030000,
        /** Application group intermediate key type. */
        kType_AppIntermediateKey                            = kType_AppRootKey | kTypeModifier_IncorporatesEpochKey,
        /** @} */

        /**
         * @brief  Matter global key ids.
         *  @{
         */
        /** Unspecified Matter key Id. */
        kNone                                               = kType_None | 0x0000,
        /** Matter fabric secret Id. */
        kFabricSecret                                       = kType_General | 0x0001,
        /** Fabric root key Id. */
        kFabricRootKey                                      = kType_AppRootKey | (0 << kShift_RootKeyNumber),
        /** Client root key Id. */
        kClientRootKey                                      = kType_AppRootKey | (1 << kShift_RootKeyNumber),
        /** Service root key Id. */
        kServiceRootKey                                     = kType_AppRootKey | (2 << kShift_RootKeyNumber),
        /** @} */


        /**
         * @brief  Maximum values for key id subfields.
         *  @{
         */
        kKeyNumber_Max                                      = kMask_KeyNumber,
        kRootKeyNumber_Max                                  = (kMask_RootKeyNumber >> kShift_RootKeyNumber),
        kEpochKeyNumber_Max                                 = (kMask_EpochKeyNumber >> kShift_EpochKeyNumber),
        kGroupLocalNumber_Max                               = (kMask_GroupLocalNumber >> kShift_GroupLocalNumber),
        /** @} */
    };

    /**
     *  Get Matter key type of the specified key Id.
     *
     *  @param[in]   keyId     Matter key identifier.
     *  @return                type of the key Id.
     *
     */
    static uint32_t GetType(uint32_t keyId)
    {
        return keyId & kMask_SessionType;
    }

    /**
     *  Determine whether the specified key Id is of a general type.
     *
     *  @param[in]   keyId     Matter key identifier.
     *  @return      true      if the keyId has General type.
     *
     */
    static bool IsGeneralKey(uint32_t keyId)
    {
        return GetType(keyId) == kType_General;
    }

    /**
     *  Determine whether the specified key Id is of a session type.
     *
     *  @param[in]   keyId     Matter key identifier.
     *  @return      true      if the keyId of a session type.
     *
     */
    static bool IsSessionKey(uint32_t keyId)
    {
        return GetType(keyId) == kType_Session;
    }

    /**
     *  Determine whether the specified key Id is of an application static type.
     *
     *  @param[in]   keyId     Matter key identifier.
     *  @return      true      if the keyId of an application static type.
     *
     */
    static bool IsAppStaticKey(uint32_t keyId)
    {
        return GetType(keyId) == kType_AppStaticKey;
    }

    /**
     *  Determine whether the specified key Id is of an application rotating type.
     *
     *  @param[in]   keyId     Matter key identifier.
     *  @return      true      if the keyId of an application rotating type.
     *
     */
    static bool IsAppRotatingKey(uint32_t keyId)
    {
        return GetType(keyId) == kType_AppRotatingKey;
    }

    static bool IsAppGroupKey(uint32_t keyId);

    /**
     *  Determine whether the specified key Id is of an application root key type.
     *
     *  @param[in]   keyId     Matter key identifier.
     *  @return      true      if the keyId of an application root key type.
     *
     */
    static bool IsAppRootKey(uint32_t keyId)
    {
        return GetType(keyId) == kType_AppRootKey;
    }

    /**
     *  Determine whether the specified key Id is of an application epoch key type.
     *
     *  @param[in]   keyId     Matter key identifier.
     *  @return      true      if the keyId of an application epoch key type.
     *
     */
    static bool IsAppEpochKey(uint32_t keyId)
    {
        return GetType(keyId) == kType_AppEpochKey;
    }

    /**
     *  Determine whether the specified key Id is of an application group master key type.
     *
     *  @param[in]       keyId     Matter key identifier.
     *  @return  true      if the keyId of an application group master key type.
     *
     */
    static bool IsAppGroupMasterKey(uint32_t keyId)
    {
        return GetType(keyId) == kType_AppGroupMasterKey;
    }

    /**
     *  Construct fabric key Id given fabric key number.
     *
     *  @param[in]   fabricKeyNumber       Fabric key number.
     *  @return      fabric key Id.
     *
     */
    static uint16_t MakeGeneralSessionId(uint16_t generalKeyNumber)
    {
        return kType_General | (generalKeyNumber & kMask_KeyNumber);
    }

    /**
     *  Get application group root key Id that was used to derive specified application key.
     *
     *  @param[in]   keyId     Matter application group key identifier.
     *  @return      root key Id.
     *
     */
    static uint32_t GetRootSessionId(uint32_t keyId)
    {
        return kType_AppRootKey | (keyId & kMask_RootKeyNumber);
    }

    /**
     *  Get application group epoch key Id that was used to derive specified application key.
     *
     *  @param[in]   keyId     Matter application group key identifier.
     *  @return      epoch key Id.
     *
     */
    static uint32_t GetEpochSessionId(uint32_t keyId)
    {
        return kType_AppEpochKey | (keyId & kMask_EpochKeyNumber);
    }

    /**
     *  Get application group master key Id that was used to derive specified application key.
     *
     *  @param[in]   keyId     Matter application group key identifier.
     *  @return      application group master key Id.
     *
     */
    static uint32_t GetAppGroupMasterSessionId(uint32_t keyId)
    {
        return kType_AppGroupMasterKey | (keyId & kMask_GroupLocalNumber);
    }

    /**
     *  Get application group root key number that was used to derive specified application key.
     *
     *  @param[in]   keyId     Matter application group key identifier.
     *  @return      root key number.
     *
     */
    static uint8_t GetRootKeyNumber(uint32_t keyId)
    {
        return (keyId & kMask_RootKeyNumber) >> kShift_RootKeyNumber;
    }

    /**
     *  Get application group epoch key number that was used to derive specified application key.
     *
     *  @param[in]   keyId     Matter application group key identifier.
     *  @return      epoch key number.
     *
     */
    static uint8_t GetEpochKeyNumber(uint32_t keyId)
    {
        return (keyId & kMask_EpochKeyNumber) >> kShift_EpochKeyNumber;
    }

    /**
     *  Get application group local number that was used to derive specified application key.
     *
     *  @param[in]   keyId     Matter application group key identifier.
     *  @return      application group local number.
     *
     */
    static uint8_t GetAppGroupLocalNumber(uint32_t keyId)
    {
        return (keyId & kMask_GroupLocalNumber) >> kShift_GroupLocalNumber;
    }

    /**
     *  Construct application group root key Id given root key number.
     *
     *  @param[in]   rootKeyNumber         Root key number.
     *  @return      root key Id.
     *
     */
    static uint32_t MakeRootSessionId(uint8_t rootKeyNumber)
    {
        return kType_AppRootKey | (rootKeyNumber << kShift_RootKeyNumber);
    }

    /**
     *  Construct application group root key Id given epoch key number.
     *
     *  @param[in]   epochKeyNumber        Epoch key number.
     *  @return      epoch key Id.
     *
     */
    static uint32_t MakeEpochSessionId(uint8_t epochKeyNumber)
    {
        return kType_AppEpochKey | (epochKeyNumber << kShift_EpochKeyNumber);
    }

    /**
     *  Construct application group master key Id given application group local number.
     *
     *  @param[in]   appGroupLocalNumber   Application group local number.
     *  @return      application group master key Id.
     *
     */
    static uint32_t MakeAppGroupMasterSessionId(uint8_t appGroupLocalNumber)
    {
        return kType_AppGroupMasterKey | (appGroupLocalNumber << kShift_GroupLocalNumber);
    }

    /**
     *  Convert application group key Id to application current key Id.
     *
     *  @param[in]   keyId                 Application key Id.
     *  @return      application current key Id.
     *
     */
    static uint32_t ConvertToCurrentAppSessionId(uint32_t keyId)
    {
        return (keyId & ~kMask_EpochKeyNumber) | kFlag_UseCurrentEpochKey;
    }

    /**
     *  Determine whether the specified application group key Id incorporates epoch key.
     *
     *  @param[in]   keyId     Matter application group key identifier.
     *  @return      true      if the keyId incorporates epoch key.
     *
     */
    static bool IncorporatesEpochKey(uint32_t keyId)
    {
        return (keyId & kTypeModifier_IncorporatesEpochKey) != 0;
    }

    static bool UsesCurrentEpochKey(uint32_t keyId);
    static bool IncorporatesRootKey(uint32_t keyId);
    static bool IncorporatesAppGroupMasterKey(uint32_t keyId);

    static uint32_t MakeAppSessionId(uint32_t keyType, uint32_t rootSessionId, uint32_t epochSessionId,
                                 uint32_t appGroupMasterSessionId, bool useCurrentEpochKey);
    static uint32_t MakeAppIntermediateSessionId(uint32_t rootSessionId, uint32_t epochSessionId, bool useCurrentEpochKey);
    static uint32_t MakeAppRotatingSessionId(uint32_t rootSessionId, uint32_t epochSessionId,
                                         uint32_t appGroupMasterSessionId, bool useCurrentEpochKey);
    static uint32_t MakeAppStaticSessionId(uint32_t rootSessionId, uint32_t appGroupMasterSessionId);
    static uint32_t ConvertToStaticAppSessionId(uint32_t keyId);
    static uint32_t UpdateEpochSessionId(uint32_t keyId, uint32_t epochSessionId);

    static bool IsValidSessionId(uint32_t keyId);
    static const char *DescribeKey(uint32_t keyId);
};

} // namespace matter

#endif /* MATTERKEYS_H_ */

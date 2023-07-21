/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef DEVICEDESCRIPTION_H_
#define DEVICEDESCRIPTION_H_


namespace matter {
namespace Profiles {
namespace DeviceDescription {

/**
 * Message Types for the Device Description Profile.
 */
enum
{
    kMessageType_IdentifyRequest                = 1,
    kMessageType_IdentifyResponse               = 2
};


/**
 * Data Element Tags for the Device Description Profile.
 */
enum
{
    /**
     * Top-level Tags
     */
    kTag_MatterDeviceDescriptor                  = 1,    /**< Structure containing information describing a Matter device. */

    /**
     * Context-specific Tags for MatterDeviceDescriptor Structure
     */
    kTag_VendorId                               = 0,    /**< Code identifying product vendor. [ uint, range 1-65535 ] */
    kTag_ProductId                              = 1,    /**< Code identifying product. [ uint, range 1-65535 ] */
    kTag_ProductRevision                        = 2,    /**< Code identifying product revision. [ uint, range 1-65535 ] */
    kTag_ManufacturingDate                      = 3,    /**< Calendar date of manufacture in encoded form. [ uint, range 1-65535 ] */
    kTag_SerialNumber                           = 4,    /**< Device serial number. [ UTF-8 string, len 1-32 ] */
    kTag_Primary802154MACAddress                = 5,    /**< MAC address for device's primary 802.15.4 interface. [ byte string, len = 8 ] */
    kTag_PrimaryWiFiMACAddress                  = 6,    /**< MAC address for device's primary WiFi interface. [ byte string, len = 6 ] */
    kTag_RendezvousWiFiESSID                    = 7,    /**< ESSID for device's WiFi rendezvous network. [ UTF-8 string, len 1-32 ] */
    kTag_PairingCode                            = 8,    /**< The pairing code for the device. [ UTF-8 string, len 1-16 ] */
                                                        /**<     @note @b IMPORTANT: For security reasons, the PairingCode field should *never*
                                                         *       be sent over the network. It is present in a MatterDeviceDescriptor structure so
                                                         *       that is can encoded in a data label (e.g. QR-code) that is physically associated
                                                         *       with the device. */
    kTag_SoftwareVersion                        = 9,    /**< Version of software on the device. [ UTF-8 string, len 1-32 ] */
    kTag_DeviceId                               = 10,   /**< Matter device ID. [ uint, 2^64 max ] */
    kTag_FabricId                               = 11,   /**< Id of Matter fabric to which the device belongs. [ uint, 2^64 max ] */
    kTag_PairingCompatibilityVersionMajor       = 12,   /**< Pairing software compatibility major version. [ uint, range 1-65535 ] */
    kTag_PairingCompatibilityVersionMinor       = 13,   /**< Pairing software compatibility minor version. [ uint, range 1-65535 ] */
};

/**
 * Special target fabric IDs.
 */
enum TargetFabricIds
{
    kTargetFabricId_NotInFabric = kFabricIdNotSpecified,        /**< Specifies that only devices that are __not__ a member of a fabric should respond. */
    kTargetFabricId_AnyFabric   = kReservedFabricIdStart,       /**< Specifies that only devices that __are_ a member of a fabric should respond. */
    kTargetFabricId_Any         = kMaxFabricId,                 /**< Specifies that all devices should respond regardless of fabric membership. */
};

/**
 * Bit field (32-bits max) identifying which devices should respond
 * to a LocateRequest Message based on their current mode.
 *
 * Note that the modes defined here are intended to be general such that they can be
 * applied to a variety of device types.
 */
enum TargetDeviceModes
{
    kTargetDeviceMode_Any               = 0x00000000,           /**< Locate all devices regardless of mode. */

    kTargetDeviceMode_UserSelectedMode  = 0x00000001            /**< Locate all devices in 'user-selected' mode -- that is, where the device has
                                                                     been directly identified by a user by pressing a button (or equivalent). */
};

} // namespace DeviceDescription
} // namespace Profiles
} // namespace matter

#endif // DEVICEDESCRIPTION_H_

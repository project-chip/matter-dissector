/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef NETWORKPROVISIONING_H_
#define NETWORKPROVISIONING_H_

namespace matter {
namespace Profiles {
namespace NetworkProvisioning {

/**
 *  Network Provisioning Status Codes.
 */
enum
{
    kStatusCode_UnknownNetwork                  = 1,            /**< A provisioned network with the specified network ID was not found. */
    kStatusCode_TooManyNetworks                 = 2,            /**< The maximum number of provisioned networks has been reached. */
    kStatusCode_InvalidNetworkConfiguration     = 3,            /**< The specified network configuration is invalid. */
    kStatusCode_UnsupportedNetworkType          = 4,            /**< The specified network type is unknown or unsupported. */
    kStatusCode_UnsupportedWiFiMode             = 5,            /**< The specified WiFi mode is unsupported. */
    kStatusCode_UnsupportedWiFiRole             = 6,            /**< The specified WiFi role is unsupported. */
    kStatusCode_UnsupportedWiFiSecurityType     = 7,            /**< The specified WiFi security type is unsupported. */
    kStatusCode_InvalidState                    = 8,            /**< The network provisioning operation could not be performed in the current state. */
    kStatusCode_TestNetworkFailed               = 9,            /**< The connectivity test of the specified network failed. */
                                                                // XXX Placeholder for more detailed errors to come
    kStatusCode_NetworkConnectFailed            = 10            /**< An attempt to connect to the specified network failed. */
};

/**
 * Network Provisioning Message Types.
 */
enum
{
    kMsgType_ScanNetworks                       = 1,
    kMsgType_NetworkScanComplete                = 2,
    kMsgType_AddNetwork                         = 3,
    kMsgType_AddNetworkComplete                 = 4,
    kMsgType_UpdateNetwork                      = 5,
    kMsgType_RemoveNetwork                      = 6,
    kMsgType_EnableNetwork                      = 7,
    kMsgType_DisableNetwork                     = 8,
    kMsgType_TestConnectivity                   = 9,
    kMsgType_SetRendezvousMode                  = 10,
    kMsgType_GetNetworks                        = 11,
    kMsgType_GetNetworksComplete                = 12,
    kMsgType_GetLastResult                      = 13
};

/**
 * @anchor NetworkProvisioningDataElementTags
 * Network Provisioning Data Element Tags.
 */
enum
{
    /**
     * Top-level Data Elements (profile-specific).
     */
    kTag_Networks                               = 1,	/**< An array of NetworkConfiguration structures. [ array ] */
    kTag_EnabledNetworks                        = 2,	/**< An array of NetworkIds identifying the networks currently enabled on the device. [ array ] */
    kTag_RendezvousMode                         = 3,	/**< A bit field indicating the currently active rendezvous mode. [ uint ] */

    /**
     * General-Purpose Data Elements (profile-specific).
     */
    kTag_NetworkInformation                     = 32,	/**< A structure containing information for a network. [ struct ] */
    kTag_NetworkId                              = 33,	/**< An integer uniquely identifying a provisioned network. [ uint, 32-bit max ] */
    kTag_NetworkType                            = 34,	/**< An unsigned integer value identifying the type of a network. [ uint, 8-bit max ] */
    kTag_WirelessSignalStrength                 = 35,   /**< An signed integer value giving the signal strength of a wireless network in dBm. [ int, 16-bit max ] */

    /**
     * WiFi Data Elements (Profile-specific).
     */
    kTag_WiFiSSID                               = 64,	/**< A string containing a WiFi SSID. [ UTF-8 string ] */
    kTag_WiFiMode                               = 65,	/**< An integer identify the mode of operation of the WiFi network. [ uint, 8-bit max ] */
    kTag_WiFiRole                               = 66,	/**< An integer identify the role the device plays in the WiFi network. [ uint, 8-bit max ] */
    kTag_WiFiSecurityType                       = 67,	/**< An integer value identifying the type of security used by a WiFi network. [ uint, 8-bit max ] */
    kTag_WiFiPreSharedKey                       = 68,	/**< A byte string containing the WiFi password/pre-shared key. */

    /**
     * Thread Data Elements (profile-specific).
     */
    kTag_ThreadExtendedPANId                    = 80,   /**< The Thread extended PAN ID. [ byte string ] */
    kTag_ThreadNetworkName                      = 81,   /**< A UTF-8 string containing the name of the Thread network. [ UTF-8 string ] */
    kTag_ThreadNetworkKey                       = 82,   /**< The Thread master network key. [ bytes string ] */
    kTag_ThreadMeshPrefix                       = 83    /**< Thread mesh IPv6 /64 prefix (optional). [ bytes string, exactly 8 bytes ] */
};

/**
 * Network Types.
 */
enum NetworkType
{
    kNetworkType_NotSpecified                   = -1,

    kNetworkType_WiFi                           = 1,
    kNetworkType_Thread                         = 2
};

/**
 * WiFi Security Modes.
 */
enum WiFiSecurityType
{
    kWiFiSecurityType_NotSpecified              = -1,

    kWiFiSecurityType_None                      = 1,
    kWiFiSecurityType_WEP                       = 2,
    kWiFiSecurityType_WPAPersonal               = 3,
    kWiFiSecurityType_WPA2Personal              = 4,
    kWiFiSecurityType_WPA2MixedPersonal         = 5,
    kWiFiSecurityType_WPAEnterprise             = 6,
    kWiFiSecurityType_WPA2Enterprise            = 7,
    kWiFiSecurityType_WPA2MixedEnterprise       = 8
};

/**
 * WiFi Operating Modes.
 */
enum WiFiMode
{
    kWiFiMode_NotSpecified                      = -1,

    kWiFiMode_AdHoc                             = 1,
    kWiFiMode_Managed                           = 2
};

/**
 * Device WiFi Role.
 */
enum WiFiRole
{
    kWiFiRole_NotSpecified                      = -1,

    kWiFiRole_Station                           = 1,
    kWiFiRole_AccessPoint                       = 2
};

/**
 * Rendezvous Mode Flags.
 */
enum RendezvousModeFlags
{
    kRendezvousMode_EnableWiFiRendezvousNetwork = 0x0001,
    kRendezvousMode_EnableThreadRendezvous      = 0x0002
};

/**
 * Get Network Flags.
 */
enum GetNetworkFlags
{
    kGetNetwork_IncludeCredentials              = 0x01
};

} // namespace NetworkProvisioning
} // namespace Profiles
} // namespace matter

#endif /* NETWORKPROVISIONING_H_ */

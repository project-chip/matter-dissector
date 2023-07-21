/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SERVICEPROVISIONING_H_
#define SERVICEPROVISIONING_H_

namespace matter {
namespace Profiles {
namespace ServiceProvisioning {

// Service Provisioning Status Codes
//
enum
{
    kStatusCode_TooManyServices                 = 1,    // There are too many service's registered on the device.
    kStatusCode_ServiceAlreadyRegistered        = 2,    // The specified service is already registered on the device.
    kStatusCode_InvalidServiceConfig            = 3,    // The specified service configuration is invalid.
    kStatusCode_NoSuchService                   = 4,    // The specified id does not match a service registered on the device.
    kStatusCode_PairingServerError              = 5,    // The device could not complete service pairing because it failed to talk to the pairing server.
    kStatusCode_InvalidPairingToken             = 6,    // The device could not complete service pairing because it passed an invalid pairing token.
    kStatusCode_PairingTokenOld                 = 7,    // The device could not complete service pairing because the pairing token it passed has expired.
    kStatusCode_ServiceCommuncationError        = 8,    // The device could not complete service pairing because it encountered an error when communicating with the service.
    kStatusCode_ServiceConfigTooLarge           = 9,     // The specified service configuration is too large.
    kStatusCode_WrongFabric                     = 10,   // Device paired with a different fabric
    kStatusCode_TooManyFabrics                  = 11    // Too many fabrics in the structure

    // !!!!! IMPORTANT !!!!!  If you add new Service Provisioning status codes, you must coordinate this with the service team.
    // The service runs a separate implementation of the Matter protocol, so it does not automatically pick up undocumented or
    // uncommunicated changes to status codes in the devices' Matter stack.
};

// Service Provisioning Message Types
//
enum
{
    // Application/Device Messages
    kMsgType_RegisterServicePairAccount         = 1,
    kMsgType_UpdateService                      = 2,
    kMsgType_UnregisterService                  = 3,

    // Device/Service Messages
    kMsgType_UnpairDeviceFromAccount            = 101,
    kMsgType_PairDeviceToAccount                = 102
};

// Service Provisioning Data Element Tags
//
enum
{
    // ---- Top-level Data Elements ----
    kTag_ServiceConfig                          = 1,    // [ structure ] Describes a Matter Service.
    kTag_ServiceEndPoint                        = 2,    // [ structure ] Describes a Matter Service EndPoint.

    // ---- Context-specific Tags for ServiceConfig Structure ----
    kTag_ServiceConfig_CACerts                  = 1,    // [ array, length >= 1 ] List of trusted CA certificates for service.
                                                        //      Each element is a MatterCertificate, as defined in the Security Profile.
    kTag_ServiceConfig_DirectoryEndPoint        = 2,    // [ structure ] Contains contact information for the service's primary directory end point.
                                                        //      Contents are as defined below for ServiceEndPoint structure.

    // ---- Context-specific Tags for ServiceEndPoint Structure ----
    kTag_ServiceEndPoint_Id                     = 1,    // [ uint, 8-64 bits ] Service end point id (an EUI-64) assigned to the service end point.
    kTag_ServiceEndPoint_Addresses              = 2,    // [ array, length >= 1 ] List of addresses for the service end point.
                                                        //      Each element is a ServiceEndPointAddress structure, as defined below.
    kTag_ServiceEndPoint_NodeId                 = 3,    // [ uint, 8-64 bits ] Matter node id of the node providing the service.
                                                        //      Mutually exclusive with Addresses list.

    // ---- Context-specific Tags for ServiceEndPointAddress Structure ----
    kTag_ServiceEndPointAddress_HostName        = 1,    // [ utf-8 string ] Host name or literal IP address.
    kTag_ServiceEndPointAddress_Port            = 2     // [ uint, 1-63353 ] IP port number. Optional
};

} // namespace ServiceProvisioning
} // namespace Profiles
} // namespace matter

#endif /* SERVICEPROVISIONING_H_ */

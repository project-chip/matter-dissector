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
 *      Definitions for the Matter CASE protocol.
 *
 */

#ifndef MATTERCASE_H_
#define MATTERCASE_H_

#include <Matter/Core/MatterCore.h>
#include <Matter/Core/MatterVendorIdentifiers.hpp>
#include <Matter/Protocols/security/MatterSecurity.h>

/**
 *   @namespace matter::Profiles::Security::CASE
 *
 *   @brief
 *     This namespace includes all interfaces within Matter for the
 *     Certificate Authenticated Session Establishment (CASE)
 *     protocol within the Matter security profile.
 */

namespace matter {
namespace Profiles {
namespace Security {
namespace CASE {

namespace Sigma1
{
    enum
    {
        kTag_InitiatorRandom          = 1,
        kTag_InitiatorSessionId       = 2,
        kTag_DestinationId            = 3,
        kTag_InitiatorEphPubKey       = 4,
        kTag_InitiatorSleepyParams    = 5,
        kTag_ResumptionId             = 6,
        kTag_InitiatorResumeMic       = 7,
    };
};

namespace Sigma2
{
    enum
    {
        kTag_ResponderRandom          = 1,
        kTag_ResponderSessionId       = 2,
        kTag_ResponderEphPubKey       = 3,
        kTag_Encrypted2               = 4,
        kTag_ResponderSleepyParams    = 5,
    };
};
namespace Sigma3
{
    enum
    {
        kTag_Encrypted3               = 1,
    };
};

namespace Sigma2_Resume
{
    enum
    {
        kTag_ResumptionId             = 1,
        kTag_ResumeMic                = 2,
        kTag_ResponderSessionId       = 3,
        kTag_ResponderSleepyParams    = 4,
    };
};

// CASE Protocol Configuration Values
enum
{
    kCASEConfig_NotSpecified                    = 0,
    kCASEConfig_Config1                         = (kMatterVendor_NestLabs << 16) | 1,
    kCASEConfig_Config2                         = (kMatterVendor_NestLabs << 16) | 2,
};

// Bit-field representing a set of allowed CASE protocol configurations
enum
{
    kCASEAllowedConfig_Config1                  = 0x01,
    kCASEAllowedConfig_Config2                  = 0x02,

    kCASEAllowedConfig_Mask                     = 0x03, // NOTE: If you expand this mask, you must reconfigure
                                                        // the mFlags field in MatterCASEEngine.
};

enum
{
    kCASEKeyConfirmHashLength_0Bytes            = 0x00,
    kCASEKeyConfirmHashLength_32Bytes           = 0x40,
    kCASEKeyConfirmHashLength_20Bytes           = 0x80,
    kCASEKeyConfirmHashLength_Reserved          = 0xC0,
};

// CASE Header Field Definitions
enum
{
    // Control Header Fields
    kCASEHeader_EncryptionTypeMask              = 0x0F,
    kCASEHeader_PerformKeyConfirmFlag           = 0x80,
    kCASEHeader_ControlHeaderUnusedBits         = ~(kCASEHeader_EncryptionTypeMask |
                                                    kCASEHeader_PerformKeyConfirmFlag),

    // Size Header Fields
    kCASEHeader_DHPublicKeyLengthMask           = 0x000000FF,
    kCASEHeader_DHPublicKeyLengthShift          = 0,
    kCASEHeader_SignatureLengthMask             = 0x0000FF00,
    kCASEHeader_SignatureLengthShift            = 8,
    kCASEHeader_AlternateConfigCountMask        = 0x00FF0000,
    kCASEHeader_AlternateConfigCountShift       = 16,
    kCASEHeader_AlternateCurveCountMask         = 0xFF000000,
    kCASEHeader_AlternateCurveCountShift        = 24,

    // Mask for Key Confirm Hash Length field in CASEBeginSessionResponse
    kCASEHeader_KeyConfirmHashLengthMask        = 0xC0
};

} // namespace CASE
} // namespace Security
} // namespace Profiles
} // namespace matter

#endif /* MATTERCASE_H_ */

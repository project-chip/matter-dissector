/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MATTERTLVTAGS_H_
#define MATTERTLVTAGS_H_

namespace matter {
namespace TLV {

enum TLVCommonProfiles
{
    kProfileIdNotSpecified                      = 0xFFFFFFFF,
    kCommonProfileId                            = 0
};

enum TLVTagFields
{
    kProfileIdMask                              = 0xFFFFFFFF00000000ULL,
    kProfileIdShift                             = 32,
    kVendorIdShift                              = 48,
    kProfileNumShift                            = 32,
    kTagNumMask                                 = 0x00000000FFFFFFFFULL,
    kSpecialTagMarker                           = 0xFFFFFFFF00000000ULL,
    kContextTagMaxNum                           = 256
};

enum TLVTagControl
{
    kTLVTagControl_Anonymous                    = 0x00,
    kTLVTagControl_ContextSpecific              = 0x20,
    kTLVTagControl_CommonProfile_2Bytes         = 0x40,
    kTLVTagControl_CommonProfile_4Bytes         = 0x60,
    kTLVTagControl_ImplicitProfile_2Bytes       = 0x80,
    kTLVTagControl_ImplicitProfile_4Bytes       = 0xA0,
    kTLVTagControl_FullyQualified_6Bytes        = 0xC0,
    kTLVTagControl_FullyQualified_8Bytes        = 0xE0
};

enum
{
    kTLVTagControlMask                          = 0xE0,
    kTLVTagControlShift                         = 5
};


inline uint64_t ProfileTag(uint32_t profileId, uint32_t tagNum) { return (((uint64_t)profileId) << kProfileIdShift) | tagNum; }

inline uint64_t ProfileTag(uint16_t vendorId, uint16_t profileNum, uint32_t tagNum) { return (((uint64_t)vendorId) << kVendorIdShift) | (((uint64_t)profileNum) << kProfileNumShift) | tagNum; }

inline uint64_t ContextTag(uint8_t tagNum) { return kSpecialTagMarker | tagNum; }

inline uint64_t CommonTag(uint32_t tagNum) { return ProfileTag(kCommonProfileId, tagNum); }

enum
{
    AnonymousTag = kSpecialTagMarker | 0x00000000FFFFFFFFULL,

    UnknownImplicitTag = kSpecialTagMarker | 0x00000000FFFFFFFEULL
};

inline uint32_t ProfileIdFromTag(uint64_t tag) { return (uint32_t)((tag & kProfileIdMask) >> kProfileIdShift); }

inline uint16_t ProfileNumFromTag(uint64_t tag) { return (uint16_t) ((tag & kProfileIdMask) >> kProfileIdShift); }

inline uint32_t TagNumFromTag(uint64_t tag) { return (uint32_t)(tag & kTagNumMask); }

inline uint16_t VendorIdFromTag(uint64_t tag) { return (uint16_t)((tag & kProfileIdMask) >> kVendorIdShift); }

inline bool IsProfileTag(uint64_t tag) { return (tag & kProfileIdMask) != kSpecialTagMarker; }

inline bool IsContextTag(uint64_t tag) { return (tag & kProfileIdMask) == kSpecialTagMarker && TagNumFromTag(tag) < kContextTagMaxNum; }

inline bool IsSpecialTag(uint64_t tag) { return (tag & kProfileIdMask) == kSpecialTagMarker; }

} // namespace TLV
} // namespace matter

#endif /* MATTERTLVTAGS_H_ */

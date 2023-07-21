/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MATTERTLVTYPES_H_
#define MATTERTLVTYPES_H_

namespace matter {
namespace TLV {

enum TLVType
{
    kTLVType_NotSpecified                       = -1,
    kTLVType_UnknownContainer                   = -2,
    kTLVType_SignedInteger                      = 0x00,
    kTLVType_UnsignedInteger                    = 0x04,
    kTLVType_Boolean                            = 0x08,
    kTLVType_FloatingPointNumber                = 0x0A,
    kTLVType_UTF8String                         = 0x0C,
    kTLVType_ByteString                         = 0x10,
    kTLVType_Null                               = 0x14,
    kTLVType_Structure                          = 0x15,
    kTLVType_Array                              = 0x16,
    kTLVType_Path                               = 0x17
};

enum TLVElementType
{
    kTLVElementType_NotSpecified                = -1,
    kTLVElementType_Int8                        = 0x00,
    kTLVElementType_Int16                       = 0x01,
    kTLVElementType_Int32                       = 0x02,
    kTLVElementType_Int64                       = 0x03,
    kTLVElementType_UInt8                       = 0x04,
    kTLVElementType_UInt16                      = 0x05,
    kTLVElementType_UInt32                      = 0x06,
    kTLVElementType_UInt64                      = 0x07,
    kTLVElementType_BooleanFalse                = 0x08,
    kTLVElementType_BooleanTrue                 = 0x09,
    kTLVElementType_FloatingPointNumber32       = 0x0A,
    kTLVElementType_FloatingPointNumber64       = 0x0B,
    kTLVElementType_UTF8String_1ByteLength      = 0x0C,
    kTLVElementType_UTF8String_2ByteLength      = 0x0D,
    kTLVElementType_UTF8String_4ByteLength      = 0x0E,
    kTLVElementType_UTF8String_8ByteLength      = 0x0F,
    kTLVElementType_ByteString_1ByteLength      = 0x10,
    kTLVElementType_ByteString_2ByteLength      = 0x11,
    kTLVElementType_ByteString_4ByteLength      = 0x12,
    kTLVElementType_ByteString_8ByteLength      = 0x13,
    kTLVElementType_Null                        = 0x14,
    kTLVElementType_Structure                   = 0x15,
    kTLVElementType_Array                       = 0x16,
    kTLVElementType_Path                        = 0x17,
    kTLVElementType_EndOfContainer              = 0x18
};

enum TLVFieldSize
{
    kTLVFieldSize_0Byte                         = -1,
    kTLVFieldSize_1Byte                         = 0,
    kTLVFieldSize_2Byte                         = 1,
    kTLVFieldSize_4Byte                         = 2,
    kTLVFieldSize_8Byte                         = 3
};

enum
{
    kTLVTypeMask                                = 0x1F,
    kTLVTypeSizeMask                            = 0x03
};

inline bool IsValidTLVType(uint8_t type)
{
    return type <= kTLVElementType_EndOfContainer;
}

inline bool TLVTypeHasValue(uint8_t type)
{
    return (type <= kTLVElementType_UInt64 ||
            (type >= kTLVElementType_FloatingPointNumber32 && type <= kTLVElementType_ByteString_8ByteLength));
}

inline bool TLVTypeHasLength(uint8_t type)
{
    return type >= kTLVElementType_UTF8String_1ByteLength && type <= kTLVElementType_ByteString_8ByteLength;
}

inline bool TLVTypeIsContainer(uint8_t type)
{
    return type >= kTLVElementType_Structure && type <= kTLVElementType_Path;
}

inline bool TLVTypeIsString(uint8_t type)
{
    return type >= kTLVElementType_UTF8String_1ByteLength && type <= kTLVElementType_ByteString_8ByteLength;
}

inline TLVFieldSize GetTLVFieldSize(uint8_t type)
{
    if (TLVTypeHasValue(type))
        return (TLVFieldSize)(type & kTLVTypeSizeMask);
    else
        return kTLVFieldSize_0Byte;
}

inline uint8_t TLVFieldSizeToBytes(TLVFieldSize fieldSize)
{
    return (fieldSize != kTLVFieldSize_0Byte) ? (1 << fieldSize) : 0;
}

} // namespace TLV
} // namespace matter



#endif /* MATTERTLVTYPES_H_ */

/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _MATTERENCODING_H
#define _MATTERENCODING_H

#include <stdint.h>

namespace matter {
namespace Encoding {

inline uint8_t  Get8(const uint8_t *p)          { return *p; }
inline void     Put8(uint8_t *p, uint8_t v)     { *p = v; }
inline uint8_t  Read8(uint8_t *& p)             { return *p++; }
inline uint8_t  Read8(const uint8_t *& p)       { return *p++; }
inline void     Write8(uint8_t *& p, uint8_t v) { *p++ = v; }

namespace LittleEndian {

inline uint16_t Read16(const uint8_t *& p)
{
    uint16_t res;
    res  = ((uint16_t)(*p++)) << (8 * 0);
    res |= ((uint16_t)(*p++)) << (8 * 1);
    return res;
}

inline uint32_t Read32(const uint8_t *& p)
{
    uint32_t res;
    res  = ((uint32_t)(*p++)) << (8 * 0);
    res |= ((uint32_t)(*p++)) << (8 * 1);
    res |= ((uint32_t)(*p++)) << (8 * 2);
    res |= ((uint32_t)(*p++)) << (8 * 3);
    return res;
}

inline uint64_t Read64(const uint8_t *& p)
{
    uint64_t res;
    res  = ((uint64_t)(*p++)) << (8 * 0);
    res |= ((uint64_t)(*p++)) << (8 * 1);
    res |= ((uint64_t)(*p++)) << (8 * 2);
    res |= ((uint64_t)(*p++)) << (8 * 3);
    res |= ((uint64_t)(*p++)) << (8 * 4);
    res |= ((uint64_t)(*p++)) << (8 * 5);
    res |= ((uint64_t)(*p++)) << (8 * 6);
    res |= ((uint64_t)(*p++)) << (8 * 7);
    return res;
}

inline uint16_t Get16(const uint8_t *p)         { return Read16(p); }

inline uint32_t Get32(const uint8_t *p)         { return Read32(p); }

inline uint64_t Get64(const uint8_t *p)         { return Read64(p); }

inline void     Write16(uint8_t *& p, uint16_t v)
{
    *p++ = (uint8_t)(v >> (8 * 0));
    *p++ = (uint8_t)(v >> (8 * 1));
}

inline void     Write32(uint8_t *& p, uint32_t v)
{
    *p++ = (uint8_t)(v >> (8 * 0));
    *p++ = (uint8_t)(v >> (8 * 1));
    *p++ = (uint8_t)(v >> (8 * 2));
    *p++ = (uint8_t)(v >> (8 * 3));
}

inline void     Write64(uint8_t *& p, uint64_t v)
{
    *p++ = (uint8_t)(v >> (8 * 0));
    *p++ = (uint8_t)(v >> (8 * 1));
    *p++ = (uint8_t)(v >> (8 * 2));
    *p++ = (uint8_t)(v >> (8 * 3));
    *p++ = (uint8_t)(v >> (8 * 4));
    *p++ = (uint8_t)(v >> (8 * 5));
    *p++ = (uint8_t)(v >> (8 * 6));
    *p++ = (uint8_t)(v >> (8 * 7));
}

inline void     Put16(uint8_t *p, uint16_t v)   { Write16(p, v); }

inline void     Put32(uint8_t *p, uint32_t v)   { Write32(p, v); }

inline void     Put64(uint8_t *p, uint64_t v)   { Write64(p, v); }

} // LittleEndian

namespace BigEndian {

inline uint16_t Read16(const uint8_t *& p)
{
    uint16_t res;
    res  = ((uint16_t)(*p++)) << (8 * 1);
    res |= ((uint16_t)(*p++)) << (8 * 0);
    return res;
}

inline uint32_t Read32(const uint8_t *& p)
{
    uint32_t res;
    res  = ((uint32_t)(*p++)) << (8 * 3);
    res |= ((uint32_t)(*p++)) << (8 * 2);
    res |= ((uint32_t)(*p++)) << (8 * 1);
    res |= ((uint32_t)(*p++)) << (8 * 0);
    return res;
}

inline uint64_t Read64(const uint8_t *& p)
{
    uint64_t res;
    res  = ((uint64_t)(*p++)) << (8 * 7);
    res |= ((uint64_t)(*p++)) << (8 * 6);
    res |= ((uint64_t)(*p++)) << (8 * 5);
    res |= ((uint64_t)(*p++)) << (8 * 4);
    res |= ((uint64_t)(*p++)) << (8 * 3);
    res |= ((uint64_t)(*p++)) << (8 * 2);
    res |= ((uint64_t)(*p++)) << (8 * 1);
    res |= ((uint64_t)(*p++)) << (8 * 0);
    return res;
}

inline uint16_t Get16(const uint8_t *p)         { return Read16(p); }

inline uint32_t Get32(const uint8_t *p)         { return Read32(p); }

inline uint64_t Get64(const uint8_t *p)         { return Read64(p); }

inline void     Write16(uint8_t *& p, uint16_t v)
{
    *p++ = (uint8_t)(v >> (8 * 1));
    *p++ = (uint8_t)(v >> (8 * 0));
}

inline void     Write32(uint8_t *& p, uint32_t v)
{
    *p++ = (uint8_t)(v >> (8 * 3));
    *p++ = (uint8_t)(v >> (8 * 2));
    *p++ = (uint8_t)(v >> (8 * 1));
    *p++ = (uint8_t)(v >> (8 * 0));
}

inline void     Write64(uint8_t *& p, uint64_t v)
{
    *p++ = (uint8_t)(v >> (8 * 7));
    *p++ = (uint8_t)(v >> (8 * 6));
    *p++ = (uint8_t)(v >> (8 * 5));
    *p++ = (uint8_t)(v >> (8 * 4));
    *p++ = (uint8_t)(v >> (8 * 3));
    *p++ = (uint8_t)(v >> (8 * 2));
    *p++ = (uint8_t)(v >> (8 * 1));
    *p++ = (uint8_t)(v >> (8 * 0));
}

inline void     Put16(uint8_t *p, uint16_t v)   { Write16(p, v); }

inline void     Put32(uint8_t *p, uint32_t v)   { Write32(p, v); }

inline void     Put64(uint8_t *p, uint64_t v)   { Write64(p, v); }

} // BigEndian


} // namespace Encoding
} // namespace matter

#endif // _MATTERENCODING_H

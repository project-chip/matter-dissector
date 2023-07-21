/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MATTERTLV_H_
#define MATTERTLV_H_

#include <stdlib.h>
#include <stdarg.h>

#include <Matter/Core/MatterError.h>
#include "MatterTLVTags.h"
#include "MatterTLVTypes.h"

namespace matter {
namespace TLV {

enum {
    kTLVControlByte_NotSpecified = 0xFFFF
};

class TLVReader
{
friend class TLVWriter;
friend class TLVUpdater;

public:
    void Init(const TLVReader &aReader);
    void Init(const uint8_t *data, uint32_t dataLen);

    MATTER_ERROR Next(void);
    MATTER_ERROR Next(TLVType expectedType, uint64_t expectedTag);

    TLVType GetType(void) const;
    uint64_t GetTag(void) const;
    uint32_t GetLength(void) const;
    uint16_t GetControlByte(void) const;

    MATTER_ERROR Get(bool& v);
    MATTER_ERROR Get(int8_t& v);
    MATTER_ERROR Get(int16_t& v);
    MATTER_ERROR Get(int32_t& v);
    MATTER_ERROR Get(int64_t& v);
    MATTER_ERROR Get(uint8_t& v);
    MATTER_ERROR Get(uint16_t& v);
    MATTER_ERROR Get(uint32_t& v);
    MATTER_ERROR Get(uint64_t& v);
    MATTER_ERROR Get(float& v);
    MATTER_ERROR Get(double& v);
    MATTER_ERROR GetBytes(uint8_t *buf, uint32_t bufSize);
    MATTER_ERROR DupBytes(uint8_t *& buf, uint32_t& dataLen);
    MATTER_ERROR GetString(char *buf, uint32_t bufSize);
    MATTER_ERROR DupString(char *& buf);
    MATTER_ERROR GetDataPtr(const uint8_t *& data);

    MATTER_ERROR EnterContainer(TLVType& outerContainerType);
    MATTER_ERROR ExitContainer(TLVType outerContainerType);
    MATTER_ERROR OpenContainer(TLVReader& containerReader);
    MATTER_ERROR CloseContainer(TLVReader& containerReader);
    TLVType GetContainerType(void) const;
    MATTER_ERROR VerifyEndOfContainer(void);

    uint32_t GetLengthRead(void) const { return mLenRead; }
    uint32_t GetRemainingLength(void) const { return mMaxLen - mLenRead; }

    const uint8_t *GetReadPoint(void) const { return mReadPoint; }

    MATTER_ERROR Skip(void);

    uint32_t ImplicitProfileId;
    void *AppData;

    typedef MATTER_ERROR (*GetNextBufferFunct)(TLVReader& reader, uintptr_t& bufHandle, const uint8_t *& bufStart,
            uint32_t& bufLen);
    GetNextBufferFunct GetNextBuffer;

protected:
    uint64_t mElemTag;
    uint64_t mElemLenOrVal;
    uintptr_t mBufHandle;
    const uint8_t *mReadPoint;
    const uint8_t *mBufEnd;
    uint32_t mLenRead;
    uint32_t mMaxLen;
    TLVType mContainerType;
    uint16_t mControlByte;

private:
    bool mContainerOpen;

protected:
    bool IsContainerOpen(void) const { return mContainerOpen; }
    void SetContainerOpen(bool aContainerOpen) { mContainerOpen = aContainerOpen; }

    MATTER_ERROR ReadElement(void);
    void ClearElementState(void);
    MATTER_ERROR SkipData(void);
    MATTER_ERROR SkipToEndOfContainer(void);
    MATTER_ERROR VerifyElement(void);
    uint64_t ReadTag(TLVTagControl tagControl, const uint8_t *& p);
    MATTER_ERROR EnsureData(MATTER_ERROR noDataErr);
    MATTER_ERROR ReadData(uint8_t *buf, uint32_t len);
    MATTER_ERROR GetElementHeadLength(uint8_t& elemHeadBytes) const;
    TLVElementType ElementType(void) const;

    static MATTER_ERROR GetNextPacketBuffer(TLVReader& reader, uintptr_t& bufHandle, const uint8_t *& bufStart,
            uint32_t& bufLen);
    static MATTER_ERROR FailGetNextBuffer(TLVReader& reader, uintptr_t& bufHandle, const uint8_t *& bufStart,
            uint32_t& bufLen);
};

} // namespace TLV
} // namespace matter

#endif /* MATTERTLV_H_ */

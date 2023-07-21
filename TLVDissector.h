/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __TLVDISSECTOR_H__
#define __TLVDISSECTOR_H__

#include <glib.h>
#include "config.h"

#include <epan/packet.h>

#include <Matter/Core/MatterCore.h>
#include <Matter/Core/MatterTLV.h>

class TLVDissector : private matter::TLV::TLVReader
{
public:
    TLVDissector();
    ~TLVDissector();

    void Init(const uint8_t *data, uint32_t dataLen, uint32_t sourceBufBaseOffset = 0);

    MATTER_ERROR Next(void);
    MATTER_ERROR Next(matter::TLV::TLVType expectedType, uint64_t expectedTag);

    using matter::TLV::TLVReader::GetType;
    using matter::TLV::TLVReader::GetTag;
    using matter::TLV::TLVReader::GetLength;
    using matter::TLV::TLVReader::Get;
    using matter::TLV::TLVReader::GetDataPtr;
    using matter::TLV::TLVReader::DupString;
    using matter::TLV::TLVReader::ImplicitProfileId;

    MATTER_ERROR EnterContainer();
    MATTER_ERROR ExitContainer();

    MATTER_ERROR AddTypedItem(proto_tree *tree, int hfindex, tvbuff_t *tvb);

    MATTER_ERROR AddGenericTLVItem(proto_tree *tree, int hfindex, tvbuff_t *tvb, bool suppressTag);

    MATTER_ERROR AddIMPathItem(proto_tree *tree, int hfindex, tvbuff_t* tvb, const char *header = NULL);

    MATTER_ERROR AddStringItemF(proto_tree *tree, int hfindex, tvbuff_t *tvb, const char *format, ...);
    MATTER_ERROR AddStringItemWithHeaderF(proto_tree *tree, int hfindex, tvbuff_t *tvb, const char *format, ...);

    MATTER_ERROR AddSubTreeItem(proto_tree *tree, int hfindex, int ett, tvbuff_t *tvb, proto_tree *& subTree);
    MATTER_ERROR AddSubTreeItemF(proto_tree *tree, int hfindex, int ett, tvbuff_t *tvb, proto_tree *& subTree, const char *format, ...);

    typedef MATTER_ERROR (*ListElemHandler)(TLVDissector& tlvDissector, proto_tree *tree, tvbuff_t* tvb);

    MATTER_ERROR AddListItem(proto_tree *tree, int hfindex, int ett, tvbuff_t *tvb, ListElemHandler elemHandler);

    proto_item *LastItem() const { return mLastItem; }

    uint32_t ElemStart() const { return mElemStart; }
    uint32_t ElemLength() const { return mElemLen; }

private:
    struct ContainerContext
    {
        matter::TLV::TLVType ContainerType;
        proto_item *ContainerItem;
        uint32_t ElemStart;
        uint32_t ElemLen;
    };

    uint32_t mSourceBufBaseOffset;
    uint32_t mElemStart;
    uint32_t mElemLen;
    proto_item *mLastItem;
    ContainerContext *mContainerStack;
    uint32_t mContainerStackSize;
    uint32_t mContainerDepth;

    MATTER_ERROR MarkElemStart();
    MATTER_ERROR MarkElemLength();

    MATTER_ERROR PushContainer(matter::TLV::TLVType containerType);
    matter::TLV::TLVType PopContainer();

    MATTER_ERROR AddGenericTLVItem(proto_tree *tree, int hfindex, tvbuff_t *tvb, bool suppressTag, bool suppressHeader, int indentLeve);

    const matter::TLV::TLVReader& Reader() const { return *this; }

};



#endif // __TLVDISSECTOR_H__

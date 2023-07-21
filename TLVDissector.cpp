/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * TLVDissector.cpp
 */

#include <stdio.h>

#include <glib.h>
#include "config.h"

#include <epan/packet.h>
#include <epan/strutil.h>

#include <Matter/Protocols/interaction-model/MessageDef.h>
#include <Matter/Support/CodeUtils.h>

#include "TLVDissector.h"

#define FEATURE_SHOW_TAGS 0

using namespace matter::TLV;
using namespace matter::Profiles::InteractionModel;

TLVDissector::TLVDissector()
{
    mElemStart = mElemLen = 0;
    mLastItem = NULL;
    mContainerStack = NULL;
    mContainerStackSize = 0;
    mContainerDepth = 0;
    mSourceBufBaseOffset = 0;
}

TLVDissector::~TLVDissector()
{
    if (mContainerStack != NULL)
        free(mContainerStack);
}

void TLVDissector::Init(const uint8_t* data, uint32_t dataLen, uint32_t sourceBufBaseOffset)
{
    ((TLVReader *)this)->Init(data, dataLen);
    mSourceBufBaseOffset = sourceBufBaseOffset;
    mElemStart = mElemLen = 0;
    mLastItem = NULL;
    mContainerDepth = 0;
}

MATTER_ERROR TLVDissector::Next(void)
{
    MATTER_ERROR err;

    mLastItem = NULL;

    err = Skip();
    SuccessOrExit(err);

    err = MarkElemStart();
    SuccessOrExit(err);

    err = ((TLVReader *)this)->Next();
    SuccessOrExit(err);

    err = MarkElemLength();
    SuccessOrExit(err);

exit:
    return err;
}

MATTER_ERROR TLVDissector::Next(matter::TLV::TLVType expectedType, uint64_t expectedTag)
{
    MATTER_ERROR err;

    mLastItem = NULL;

    err = Skip();
    SuccessOrExit(err);

    err = MarkElemStart();
    SuccessOrExit(err);

    err = ((TLVReader *)this)->Next(expectedType, expectedTag);
    SuccessOrExit(err);

    err = MarkElemLength();
    SuccessOrExit(err);

exit:
    return err;
}

MATTER_ERROR TLVDissector::EnterContainer()
{
    MATTER_ERROR err;
    TLVType containerType;

    err = ((TLVReader *)this)->EnterContainer(containerType);
    SuccessOrExit(err);

    err = PushContainer(containerType);
    SuccessOrExit(err);

exit:
    return err;
}

MATTER_ERROR TLVDissector::ExitContainer()
{
    MATTER_ERROR err;
    TLVType containerType;

    containerType = PopContainer();

    err = ((TLVReader *)this)->ExitContainer(containerType);
    SuccessOrExit(err);

exit:
    return err;
}

MATTER_ERROR TLVDissector::AddTypedItem(proto_tree* tree, int hfindex, tvbuff_t* tvb)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    TLVType elemType;
    uint32_t tag;
    proto_item *listItem;

    elemType = GetType();

    switch (elemType) {
    case kTLVType_SignedInteger:
    {
        int64_t val;

        err = Get(val);
        SuccessOrExit(err);

        ftenum fieldType = proto_registrar_get_ftype(hfindex);
        if (fieldType == FT_INT8 || fieldType == FT_INT16 || fieldType == FT_INT24 || fieldType == FT_INT32)
            mLastItem = proto_tree_add_int(tree, hfindex, tvb, mElemStart + mSourceBufBaseOffset, mElemLen, (int32_t)val);
        else if (fieldType == FT_INT40 || fieldType == FT_INT48 || fieldType == FT_INT56 || fieldType == FT_INT64)
            mLastItem = proto_tree_add_int64(tree, hfindex, tvb, mElemStart + mSourceBufBaseOffset, mElemLen, val);
        else
            ExitNow(err = MATTER_ERROR_INVALID_ARGUMENT);

        break;
    }
    case kTLVType_UnsignedInteger:
    {
        uint64_t val;

        err = Get(val);
        SuccessOrExit(err);

        ftenum fieldType = proto_registrar_get_ftype(hfindex);
        if (fieldType == FT_UINT8 || fieldType == FT_UINT16 || fieldType == FT_UINT24 || fieldType == FT_UINT32)
            mLastItem = proto_tree_add_uint(tree, hfindex, tvb, mElemStart + mSourceBufBaseOffset, mElemLen, (uint32_t)val);
        else if (fieldType == FT_UINT40 || fieldType == FT_UINT48 || fieldType == FT_UINT56 || fieldType == FT_UINT64)
            mLastItem = proto_tree_add_uint64(tree, hfindex, tvb, mElemStart + mSourceBufBaseOffset, mElemLen, val);
        else
            ExitNow(err = MATTER_ERROR_INVALID_ARGUMENT);

        break;
    }
    case kTLVType_Boolean:
    {
        bool val;
        err = Get(val);
        SuccessOrExit(err);
        mLastItem = proto_tree_add_boolean(tree, hfindex, tvb, mElemStart + mSourceBufBaseOffset, mElemLen, val ? 1 : 0);
        break;
    }
    case kTLVType_FloatingPointNumber:
    {
        double val;
        err = Get(val);
        SuccessOrExit(err);
        mLastItem = proto_tree_add_double(tree, hfindex, tvb, mElemStart + mSourceBufBaseOffset, mElemLen, val);
        break;
    }
    case kTLVType_UTF8String:
    {
        char *val;
        err = DupString(val);
        SuccessOrExit(err);
        mLastItem = proto_tree_add_string(tree, hfindex, tvb, mElemStart + mSourceBufBaseOffset, mElemLen, val);
        free(val);
        break;
    }
    case kTLVType_ByteString:
    {
        const uint8_t *val;
        uint32_t valLen;
        err = GetDataPtr(val);
        SuccessOrExit(err);
        valLen = GetLength();
        mLastItem = proto_tree_add_bytes_with_length(tree, hfindex, tvb, mElemStart + mSourceBufBaseOffset, mElemLen, val, valLen);
        break;
    }
    case kTLVType_Null:
        mLastItem = proto_tree_add_none_format(tree, hfindex, tvb, mElemStart + mSourceBufBaseOffset, mElemLen, "null");
        break;
    case kTLVType_Structure:
    case kTLVType_Array:
    case kTLVType_Path:
    default:
        ExitNow(err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
    }

#if FEATURE_SHOW_TAGS
    tag = static_cast<uint32_t>(GetTag());
    listItem = LastItem();
    if (listItem != NULL) {
        proto_item_append_text(listItem, (" [%" PRIu32 "]"), tag);
    }
#endif

exit:
    return err;
}

// TODO: move this to utils
static size_t AppendStringF(char *& strBuf, size_t& strBufSize, const char *format, ...)
{
    va_list ap;
    size_t curStrLen = (strBuf != NULL) ? strlen(strBuf) : 0;
    size_t remainingBufSize = strBufSize - curStrLen;
    size_t addedStrLen;

    va_start(ap, format);
    addedStrLen = vsnprintf(strBuf + curStrLen, remainingBufSize, format, ap);
    va_end(ap);

    if (addedStrLen >= remainingBufSize) {

        if (strBuf == NULL || strBufSize == 0) {
            strBufSize = addedStrLen + 1;
        }
        else {
            while (strBufSize < (curStrLen + addedStrLen + 1))
                strBufSize *= 2;
        }

        strBuf = (char *)realloc(strBuf, strBufSize);

        remainingBufSize = strBufSize - curStrLen;

        va_start(ap, format);
        addedStrLen = vsnprintf(strBuf + curStrLen, remainingBufSize, format, ap);
        va_end(ap);
    }

    return curStrLen + addedStrLen;
}

static void AppendRepeated(const char *inStr, int repeatCount, char *& strBuf, size_t& strBufSize)
{
    for (int i = 0; i < repeatCount; i++) {
        AppendStringF(strBuf, strBufSize, "%s", inStr);
    }
}

MATTER_ERROR
AppendIMPath(TLVReader& reader, char *& strBuf, size_t& strBufSize)
{
    MATTER_ERROR err;
    TLVType pathContainer, instanceLocatorContainer;
    bool addSep = false;

    VerifyOrExit(reader.GetType() == kTLVType_Path, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

    err = reader.EnterContainer(pathContainer);
    SuccessOrExit(err);

/*
    err = reader.Next(kTLVType_Structure, ContextTag(Path::kTag_InstanceLocator));
    SuccessOrExit(err);

    err = reader.EnterContainer(instanceLocatorContainer);
    SuccessOrExit(err);
*/
    AppendStringF(strBuf, strBufSize, "//");

    while (true) {
        err = reader.Next();
        if (err == MATTER_END_OF_TLV)
            break;
        SuccessOrExit(err);

        TLVType type = reader.GetType();
        uint64_t tag = reader.GetTag();
        unsigned tagNum = TagNumFromTag(tag);

        VerifyOrExit(IsContextTag(tag), err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

        if (addSep) {
            AppendStringF(strBuf, strBufSize, ",");
        }

        switch (TagNumFromTag(tag)) {
        case CommandPathIB::kTag_Endpoint:
        case CommandPathIB::kTag_Cluster:
        case CommandPathIB::kTag_Command:
        {
            VerifyOrExit(type == kTLVType_UnsignedInteger, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            uint32_t pathElement;
            err = reader.Get(pathElement);
            SuccessOrExit(err);

            char *pathElementName;
            switch (tagNum) {
                case CommandPathIB::kTag_Endpoint: pathElementName = "Endpoint"; break;
                case CommandPathIB::kTag_Cluster:  pathElementName = "Cluster"; break;
                case CommandPathIB::kTag_Command:  pathElementName = "Command"; break;
                default:
                    pathElementName = "Unknown";
            }
            AppendStringF(strBuf, strBufSize, "%s=0x%08" PRIX32, pathElementName, pathElement);
            break;
        }

/*
        case Path::kTag_ResourceID:
            if (type == kTLVType_UnsignedInteger) {
                uint64_t resourceId;
                err = reader.Get(resourceId);
                SuccessOrExit(err);
                AppendStringF(strBuf, strBufSize, "ResourceId=%" PRIx64, resourceId);
            }
            else if (type == kTLVType_ByteString) {
                const uint8_t *val;
                err = reader.GetDataPtr(val);
                SuccessOrExit(err);
                uint32_t valLen = reader.GetLength();
                AppendStringF(strBuf, strBufSize, "ResourceId=");
                for (uint32_t i = 0; i < valLen; i++)
                    AppendStringF(strBuf, strBufSize, "%02X", val[i]);
            }
            else if (type == kTLVType_UTF8String) {
                const uint8_t *val;
                err = reader.GetDataPtr(val);
                SuccessOrExit(err);
                uint32_t valLen = reader.GetLength();
                AppendStringF(strBuf, strBufSize, "ResourceId=\"%.*s\"", val, valLen);
            }
            else {
                ExitNow(err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            }
            break;
        case Path::kTag_TraitProfileID:
        {
            VerifyOrExit(type == kTLVType_UnsignedInteger, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            uint32_t traitProfileId;
            err = reader.Get(traitProfileId);
            SuccessOrExit(err);
            AppendStringF(strBuf, strBufSize, "TraitProfileId=0x%08" PRIX32, traitProfileId);
            break;
        }
        case Path::kTag_TraitInstanceID:
        {
            VerifyOrExit(type == kTLVType_UnsignedInteger, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
            uint32_t traitInstanceId;
            err = reader.Get(traitInstanceId);
            SuccessOrExit(err);
            AppendStringF(strBuf, strBufSize, "TraitInstanceId=%" PRId32, traitInstanceId);
            break;
        }
*/
        default:
            ExitNow(err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
        }

        addSep = true;
    }

    AppendStringF(strBuf, strBufSize, "/");
/*
    err = reader.ExitContainer(instanceLocatorContainer);
    SuccessOrExit(err);
*/
    addSep = false;

    while (true) {
        err = reader.Next();
        if (err == MATTER_END_OF_TLV)
            break;
        SuccessOrExit(err);

        TLVType type = reader.GetType();
        uint64_t tag = reader.GetTag();

        VerifyOrExit(IsContextTag(tag), err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
        VerifyOrExit(type == kTLVType_Null, err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);

        AppendStringF(strBuf, strBufSize, "%s%" PRId32, (addSep) ? "/" : "", TagNumFromTag(tag));

        addSep = true;
    }

    err = reader.ExitContainer(pathContainer);
    SuccessOrExit(err);

exit:
    if (err != MATTER_NO_ERROR) {
        if (strBuf != NULL) {
            free(strBuf);
            strBuf = NULL;
        }
    }
    return err;
}

MATTER_ERROR TLVDissector::AddGenericTLVItem(proto_tree *tree, int hfindex, tvbuff_t *tvb, bool suppressTag)
{
    return AddGenericTLVItem(tree, hfindex, tvb, suppressTag, false, 0);
}

MATTER_ERROR TLVDissector::AddListItem(proto_tree* tree, int hfindex, int ett, tvbuff_t* tvb, ListElemHandler elemHandler)
{
    MATTER_ERROR err;
    proto_tree *listTree;
    proto_item *listItem;
    uint32_t elemCount = 0;

    VerifyOrExit(GetType() == kTLVType_Array || GetType() == kTLVType_Path, err = MATTER_ERROR_INCORRECT_STATE);

    err = AddSubTreeItem(tree, hfindex, ett, tvb, listTree);
    SuccessOrExit(err);

    listItem = LastItem();

    err = EnterContainer();
    SuccessOrExit(err);

    while (true) {
        err = Next();
        if (err == MATTER_END_OF_TLV)
            break;
        SuccessOrExit(err);

        err = elemHandler(*this, listTree, tvb);
        SuccessOrExit(err);

        elemCount++;
    }

    err = ExitContainer();
    SuccessOrExit(err);

    if (listItem != NULL) {
        proto_item_append_text(listItem, (" (len = %" PRIu32 ")"), elemCount);
    }

exit:
    return err;
}

MATTER_ERROR TLVDissector::AddGenericTLVItem(proto_tree *tree, int hfindex, tvbuff_t *tvb, bool suppressTag, bool suppressHeader, int indentLevel)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    TLVType type = GetType();
    int64_t tag = GetTag();
    char *strBuf = NULL;
    size_t strBufSize = 0;
    char closeChar = ' ';

    if (suppressHeader) {
        AppendRepeated("    ", indentLevel, strBuf, strBufSize);
    }

    if (!suppressTag) {
        if (IsContextTag(tag)) {
            uint32_t contextTagNum = TagNumFromTag(tag);
            AppendStringF(strBuf, strBufSize, ("%" PRId32 " = "), contextTagNum);
        }
        else if (IsProfileTag(tag)) {
            uint32_t profileId = ProfileIdFromTag(tag);
            uint32_t tagNum = TagNumFromTag(tag);
            AppendStringF(strBuf, strBufSize, ("%08" PRIX32 ":" PRId32 " = "), profileId, tagNum);
        }
    }

    switch (type) {
    case kTLVType_SignedInteger:
    {
        int64_t val;
        err = Get(val);
        SuccessOrExit(err);
        AppendStringF(strBuf, strBufSize, ("%" PRId64), val);
        break;
    }
    case kTLVType_UnsignedInteger:
    {
        uint64_t val;
        err = Get(val);
        SuccessOrExit(err);
        AppendStringF(strBuf, strBufSize, ("%" PRIu64), val);
        break;
    }
    case kTLVType_Boolean:
    {
        bool val;
        err = Get(val);
        SuccessOrExit(err);
        AppendStringF(strBuf, strBufSize, "%s", (val) ? "true" : "false");
        break;
    }
    case kTLVType_FloatingPointNumber:
    {
        double val;
        err = Get(val);
        SuccessOrExit(err);
        AppendStringF(strBuf, strBufSize, "%g", val); // TODO: make sure this always has decimal point, to distinguish integers from floats.
        break;
    }
    case kTLVType_UTF8String:
    {
        char *val;
        err = DupString(val);
        SuccessOrExit(err);
        uint32_t escapedLen = escape_string_len(val);
        char *escapedVal = (char *)malloc(escapedLen + 1);
        escape_string(escapedVal, val);
        AppendStringF(strBuf, strBufSize, "%s", escapedVal);
        free(val);
        free(escapedVal);
        break;
    }
    case kTLVType_ByteString:
    {
        const uint8_t *data;
        uint32_t dataLen = GetLength();
        err = GetDataPtr(data);
        SuccessOrExit(err);
        for (uint32_t i = 0; i < dataLen; i++, data++) {
            AppendStringF(strBuf, strBufSize, " %02x", *data);
        }
        break;
    }
    case kTLVType_Null:
        AppendStringF(strBuf, strBufSize, "null");
        break;
    case kTLVType_Structure:
        AppendStringF(strBuf, strBufSize, "{");
        closeChar = '}';
        break;
    case kTLVType_Array:
        AppendStringF(strBuf, strBufSize, "[");
        closeChar = ']';
        break;
    case kTLVType_Path:
        AppendStringF(strBuf, strBufSize, "<");
        closeChar = '>';
        break;
    default:
        ExitNow(err = MATTER_ERROR_UNEXPECTED_TLV_ELEMENT);
    }

    if (!suppressHeader) {
        err = AddStringItemF(tree, hfindex, tvb, "%s", strBuf);
        SuccessOrExit(err);
    }

    else {
        err = AddStringItemWithHeaderF(tree, hfindex, tvb, "%s", strBuf);
        SuccessOrExit(err);
    }

    // Reset the string.
    strBuf[0] = 0;

    if (type == kTLVType_Structure || type == kTLVType_Array || type == kTLVType_Path) {

        err = EnterContainer();
        SuccessOrExit(err);

        while (true) {
            err = Next();
            if (err == MATTER_END_OF_TLV)
                break;
            SuccessOrExit(err);

            err = AddGenericTLVItem(tree, hfindex, tvb, false, true, indentLevel + 1);
            SuccessOrExit(err);
        }

        err = ExitContainer();
        SuccessOrExit(err);

        AppendRepeated("    ", indentLevel, strBuf, strBufSize);
        AppendStringF(strBuf, strBufSize, "%c", closeChar);

        err = AddStringItemWithHeaderF(tree, hfindex, tvb, "%s", strBuf);
        SuccessOrExit(err);
    }

exit:
    if (strBuf != NULL)
        free(strBuf);
    return err;
}

MATTER_ERROR
TLVDissector::AddIMPathItem(proto_tree *tree, int hfindex, tvbuff_t* tvb, const char *header)
{
    MATTER_ERROR err;
    char *pathStr = NULL;
    size_t pathStrBufSize = 0;
    TLVReader readerCopy = *this;

    if (header != NULL)
        AppendStringF(pathStr, pathStrBufSize, "%s", header);

    err = AppendIMPath(readerCopy, pathStr, pathStrBufSize);
    SuccessOrExit(err);

    if (header != NULL) {
        err = AddStringItemWithHeaderF(tree, hfindex, tvb, "%s", pathStr);
        SuccessOrExit(err);
    }
    else {
        err = AddStringItemF(tree, hfindex, tvb, "%s", pathStr);
        SuccessOrExit(err);
    }

exit:
    if (pathStr != NULL)
        free(pathStr);
    return err;
}

MATTER_ERROR TLVDissector::AddStringItemF(proto_tree* tree, int hfindex, tvbuff_t* tvb, const char* format, ...)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    char *msg = NULL;
    va_list ap;

    va_start(ap, format);
    vasprintf(&msg, format, ap);
    va_end(ap);

    mLastItem = proto_tree_add_string_format_value(tree, hfindex, tvb, mElemStart + mSourceBufBaseOffset, mElemLen, msg, "%s", msg);

    if (msg != NULL)
        free(msg);

    return err;
}

MATTER_ERROR TLVDissector::AddStringItemWithHeaderF(proto_tree* tree, int hfindex, tvbuff_t* tvb, const char* format, ...)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    char *msg = NULL;
    va_list ap;

    va_start(ap, format);
    vasprintf(&msg, format, ap);
    va_end(ap);

    mLastItem = proto_tree_add_string_format(tree, hfindex, tvb, mElemStart + mSourceBufBaseOffset, mElemLen, msg, "%s", msg);

    if (msg != NULL)
        free(msg);

    return err;
}

MATTER_ERROR TLVDissector::AddSubTreeItem(proto_tree* tree, int hfindex, int ett, tvbuff_t* tvb, proto_tree*& subTree)
{
    MATTER_ERROR err = MATTER_NO_ERROR;

    VerifyOrExit(GetType() != kTLVType_NotSpecified, err = MATTER_ERROR_INCORRECT_STATE);

    mLastItem = proto_tree_add_item(tree, hfindex, tvb, mElemStart + mSourceBufBaseOffset, mElemLen, ENC_NA);

    subTree = proto_item_add_subtree(mLastItem, ett);

exit:
    return err;
}

MATTER_ERROR TLVDissector::AddSubTreeItemF(proto_tree* tree, int hfindex, int ett, tvbuff_t* tvb, proto_tree*& subTree, const char* format, ...)
{
    MATTER_ERROR err = MATTER_NO_ERROR;
    char *msg = NULL;
    va_list ap;

    err = AddSubTreeItem(tree, hfindex, ett, tvb, subTree);
    SuccessOrExit(err);

    va_start(ap, format);
    vasprintf(&msg, format, ap);
    va_end(ap);

    proto_item_set_text(mLastItem, "%s", msg);

exit:
    if (msg != NULL)
        free(msg);
    return err;
}

MATTER_ERROR TLVDissector::MarkElemStart()
{
    MATTER_ERROR err = MATTER_NO_ERROR;

    VerifyOrExit(GetType() == kTLVType_NotSpecified, err = MATTER_ERROR_INCORRECT_STATE);

    mElemStart = GetLengthRead();

exit:
    return err;
}

MATTER_ERROR TLVDissector::MarkElemLength()
{
    MATTER_ERROR err;
    TLVReader readerCopy = *this;

    err = readerCopy.Skip();
    SuccessOrExit(err);

    mElemLen = readerCopy.GetLengthRead() - mElemStart;

exit:
    return err;
}

MATTER_ERROR TLVDissector::PushContainer(matter::TLV::TLVType containerType)
{
    MATTER_ERROR err = MATTER_NO_ERROR;

    if (mContainerStack == NULL || mContainerStackSize == 0 || mContainerStackSize == mContainerDepth) {
        mContainerStackSize = (mContainerStackSize == 0) ? 16 : mContainerStackSize * 2;
        mContainerStack = (ContainerContext *)realloc(mContainerStack, mContainerStackSize * sizeof(ContainerContext));
        VerifyOrExit(mContainerStack != NULL, err = MATTER_ERROR_NO_MEMORY);
    }

    mContainerStack[mContainerDepth].ContainerType = containerType;
    mContainerStack[mContainerDepth].ContainerItem = mLastItem;
    mContainerStack[mContainerDepth].ElemStart = mElemStart;
    mContainerStack[mContainerDepth].ElemLen = mElemLen;
    mContainerDepth++;

exit:
    return err;
}

matter::TLV::TLVType TLVDissector::PopContainer()
{
    if (mContainerDepth > 0) {
        mContainerDepth--;
        mLastItem = mContainerStack[mContainerDepth].ContainerItem;
        mElemStart = mContainerStack[mContainerDepth].ElemStart;
        mElemLen = mContainerStack[mContainerDepth].ElemLen;
        return mContainerStack[mContainerDepth].ContainerType;
    }
    else {
        return kTLVType_NotSpecified;
    }
}


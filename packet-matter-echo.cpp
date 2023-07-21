/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#include <glib.h>
#include "config.h"

#include <epan/packet.h>

#include <Matter/Core/MatterCore.h>
#include <Matter/Protocols/MatterProfiles.h>
#include <Matter/Protocols/echo/MatterEcho.h>

#include "packet-matter.h"

using namespace matter;
using namespace matter::Profiles;

static int proto_matter_echo = -1;
static int ett_matter_echo = -1;

static int hf_echo_payload = -1;

static int
DissectMatterEcho(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    const MatterMessageInfo& msgInfo = *(const MatterMessageInfo *)data;

    AddMessageTypeToInfoColumn(pinfo, msgInfo);

    proto_item *top = proto_tree_add_item(tree, proto_matter_echo, tvb, 0, -1, ENC_NA);
    proto_tree *echo_tree = proto_item_add_subtree(top, ett_matter_echo);

    switch (msgInfo.msgType) {
    case kEchoMessageType_EchoRequest:
        proto_item_append_text(top, ": Echo Request");
        proto_tree_add_bytes_item(echo_tree, hf_echo_payload, tvb, 0, msgInfo.payloadLen, ENC_LITTLE_ENDIAN, NULL, NULL, NULL);
        return msgInfo.payloadLen;
    case kEchoMessageType_EchoResponse:
        proto_item_append_text(top, ": Echo Response");
        proto_tree_add_bytes_item(echo_tree, hf_echo_payload, tvb, 0, msgInfo.payloadLen, ENC_LITTLE_ENDIAN, NULL, NULL, NULL);
        return msgInfo.payloadLen;
    default:
        return 0;
    }
}

void
proto_register_matter_echo(void)
{
    static hf_register_info hf[] = {
        { &hf_echo_payload,
            { "Payload", "matter_echo.payload",
            FT_BYTES, SEP_SPACE, NULL, 0x0, NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_matter_echo
    };

    proto_matter_echo = proto_register_protocol(
        "Matter Echo Protocol",
        "Matter-Echo",
        "matter-echo"
    );

    proto_register_field_array(proto_matter_echo, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_matter_echo(void)
{
    static dissector_handle_t matter_echo_handle;

    matter_echo_handle = create_dissector_handle(DissectMatterEcho, proto_matter_echo);
    dissector_add_uint("matter.profile_id", kMatterProfile_Echo, matter_echo_handle);
}


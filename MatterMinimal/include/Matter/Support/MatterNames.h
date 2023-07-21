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
 *      This file declares functions for converting various ids into human-readable strings.
 *
 */

namespace matter {

const char *GetVendorName(uint16_t vendorId);
const char *GetProtocolName(uint32_t profileId);
const char *GetMessageName(uint32_t profileId, uint8_t msgType);

} // namespace matter

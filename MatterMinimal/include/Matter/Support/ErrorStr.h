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
 *      This file defines functions to translate error codes and status reports
 *      used throughout the Matter package into human-readable strings.
 *
 */

#ifndef ERRORSTR_H_
#define ERRORSTR_H_

#include <stdint.h>

namespace matter {

extern const char *ErrorStr(int32_t err);
extern const char *StatusReportStr(uint32_t profileId, uint16_t statusCode);

} // namespace nl

#endif /* ERRORSTR_H_ */

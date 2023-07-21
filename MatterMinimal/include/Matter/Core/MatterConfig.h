/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MATTER_CONFIG_H_
#define MATTER_CONFIG_H_

#include <stdint.h>

#ifndef MATTER_PORT
#define MATTER_PORT                                          5540
#endif // MATTER_PORT

#ifndef MATTER_CONFIG_ERROR_TYPE
#define MATTER_CONFIG_ERROR_TYPE                             int32_t
#endif // MATTER_CONFIG_ERROR_TYPE

#ifndef MATTER_CONFIG_NO_ERROR
#define MATTER_CONFIG_NO_ERROR                               0
#endif // MATTER_CONFIG_NO_ERROR

#ifndef MATTER_CONFIG_ERROR_MIN
#define MATTER_CONFIG_ERROR_MIN                              4000
#endif // MATTER_CONFIG_ERROR_MIN

#ifndef MATTER_CONFIG_ERROR_MAX
#define MATTER_CONFIG_ERROR_MAX                              4999
#endif // MATTER_CONFIG_ERROR_MAX

#ifndef _MATTER_CONFIG_ERROR
#define _MATTER_CONFIG_ERROR(e)                              (MATTER_ERROR_MIN + (e))
#endif // _MATTER_CONFIG_ERROR

#endif /* MATTER_CONFIG_H_ */

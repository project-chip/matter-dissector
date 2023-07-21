/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef CODEUTILS_H_
#define CODEUTILS_H_

#include <Matter/Core/MatterError.h>

#define IgnoreUnusedVariable(aVariable)                                \
    ((void)(aVariable))

#define SuccessOrExit(aStatus)                                         \
    do                                                                 \
    {                                                                  \
        if ((aStatus) != MATTER_NO_ERROR)                                 \
        {                                                              \
            goto exit;                                                 \
        }                                                              \
    } while (0)

#define VerifyOrExit(aCondition, anAction)                             \
    do                                                                 \
    {                                                                  \
        if (!(aCondition))                                             \
        {                                                              \
            anAction;                                                  \
            goto exit;                                                 \
        }                                                              \
    } while (0)


#define ExitNow(...)                                                   \
    do {                                                               \
        __VA_ARGS__;                                                   \
        goto exit;                                                     \
    } while (0)

#endif /* CODEUTILS_H_ */

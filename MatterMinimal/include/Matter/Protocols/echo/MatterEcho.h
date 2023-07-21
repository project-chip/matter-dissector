/*
 *  Copyright (c) 2023 Project CHIP Authors.
 * 
 *  Use of this source code is governed by a BSD-style
 *  license that can be found in the LICENSE file or at
 *  https://opensource.org/license/bsd-3-clause
 * 
 *  SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef MATTER_ECHO_H_
#define MATTER_ECHO_H_

namespace matter {
namespace Profiles {

enum
{
	kEchoMessageType_EchoRequest			= 1,
	kEchoMessageType_EchoResponse			= 2
};

} // namespace Profiles
} // namespace matter


#endif // MATTER_ECHO_H_

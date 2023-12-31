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
 *      Utilities for safely working with integer types.
 *
 */

#pragma once

#include <limits>
#include <stdint.h>
#include <type_traits>

namespace matter {

/**
 * A template function that determines whether it's safe to cast the given value
 * of type U to the given type T.  It does this by verifying that the value is
 * in the range of valid values for T.
 */
template <typename T, typename U>
bool CanCastTo(U arg)
{
    using namespace std;
    // U might be a reference to an integer type, if we're assigning from
    // something passed by reference.
    typedef typename remove_reference<U>::type V; // V for "value"
    static_assert(is_integral<T>::value, "Must be assigning to an integral type");
    static_assert(is_integral<V>::value, "Must be assigning from an integral type");

    // We want to check that "arg" can fit inside T but without doing any tests
    // that are always true or always false due to the types involved, which
    // would trigger compiler warnings themselves.  So for example, we can't
    // compare arg to max values for T if all U values are representable in T,
    // etc, because those trigger warnings on some compilers.

    // We also can't directly compare signed to unsigned values in general,
    // because that will trigger sign conversion warnings. In fact, it will
    // trigger them even on runtime-unreached codepaths, so for example we can't
    // directly compare two min() values to each other!

    // Oh, and some compilers warn on theoretical signed-to-unsigned compares
    // even when those can't be reached, and that's known at compile time.
    // Hence all the casts to intmax_t and uintmax_t below.

    // A bunch of these tests could sure benefit from "if constexpr", but let's
    // hope compilers just manage to optimize them properly anyway.
    // We can't blindly compare "arg" to the minimal or maximal value of T one
    // of T and V is signed and the other is unsigned: there might not be a
    // single integer type that can represent _both_ the value of arg and the
    // minimal/maximal value.
    if (numeric_limits<T>::is_signed && numeric_limits<V>::is_signed)
    {
        if (static_cast<intmax_t>(numeric_limits<V>::max()) <= static_cast<intmax_t>(numeric_limits<T>::max()) &&
            static_cast<intmax_t>(numeric_limits<V>::min()) >= static_cast<intmax_t>(numeric_limits<T>::min()))
        {
            // Any checks on arg would be trivially true; don't even do them, to
            // avoid warnings.
            return true;
        }

        return static_cast<intmax_t>(numeric_limits<T>::min()) <= static_cast<intmax_t>(arg) &&
            static_cast<intmax_t>(arg) <= static_cast<intmax_t>(numeric_limits<T>::max());
    }

    if (!numeric_limits<T>::is_signed && !numeric_limits<V>::is_signed)
    {
        if (static_cast<uintmax_t>(numeric_limits<V>::max()) <= static_cast<uintmax_t>(numeric_limits<T>::max()))
        {
            // Any checks on arg would be trivially true; don't even do them, to
            // avoid warnings.
            return true;
        }

        return static_cast<uintmax_t>(arg) <= static_cast<uintmax_t>(numeric_limits<T>::max());
    }

    if (numeric_limits<T>::is_signed)
    {
#if !defined(__clang__)
        static_assert(numeric_limits<T>::max() >= 0, "What weird type is this?");
#endif
        if (static_cast<uintmax_t>(numeric_limits<V>::max()) <= static_cast<uintmax_t>(numeric_limits<T>::max()))
        {
            return true;
        }

        return static_cast<uintmax_t>(arg) <= static_cast<uintmax_t>(numeric_limits<T>::max());
    }

    return 0 <= arg && static_cast<uintmax_t>(arg) <= static_cast<uintmax_t>(numeric_limits<T>::max());
}

/**
 * A function to reverse the effects of a signed-to-unsigned integer cast.
 *
 * If the argument is small enough to be representable as a positive signed
 * integer, returns that integer.  Otherwise, returns a negative integer which
 * would, if cast to the type of the argument, produce the given value.
 *
 * So for example, if a uint8_t with value 254 is passed in this function will
 * return an int8_t with value -2.
 *
 * @note This function might become unnecessary if C++20 standardizes
 * 2s-complement signed integers and defines casting of out-of-range values to
 * signed types.
 */
template <typename T>
typename std::enable_if<std::is_unsigned<T>::value, typename std::make_signed<T>::type>::type CastToSigned(T arg)
{
    using namespace std;
    typedef typename make_signed<T>::type signed_type;

    if (arg <= static_cast<T>(numeric_limits<signed_type>::max()))
    {
        return static_cast<signed_type>(arg);
    }

    // We want to return arg - (numeric_limits<T>::max() + 1), but do it without
    // hitting overflow.  We do this by rewriting it as:
    //
    // -(numeric_limits<T>::max() - arg) - 1
    //
    // then noting that both (numeric_limits<T>::max() - arg) and its negation
    // are guaranteed to fit in signed_type.
    signed_type diff = static_cast<signed_type>(numeric_limits<T>::max() - arg);
    return static_cast<signed_type>(-diff - 1);
}

} // namespace matter

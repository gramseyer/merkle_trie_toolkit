#pragma once

/**     
 * based on stellar-core src/util/NonCopyable.h
 * 
 * Original license notification
 * ```
 * Copyright 2015 Stellar Development Foundation and contributors. Licensed
 * under the Apache License, Version 2.0. See the COPYING file at the root
 * of this distribution or at http://www.apache.org/licenses/LICENSE-2.0
 * ```
 * where the "root of this distribution" refers to the stellar/stellar-core
 * repository.
 */

namespace utils
{

struct NonCopyable
{
    NonCopyable() = default;
    NonCopyable(NonCopyable const&) = delete;
    NonCopyable& operator=(NonCopyable const&) = delete;
};

struct NonMovable
{
    NonMovable() = default;
    NonMovable(NonMovable&&) = delete;
    NonMovable& operator=(NonMovable&&) = delete;
};

struct NonMovableOrCopyable : private NonCopyable, NonMovable
{
    NonMovableOrCopyable() = default;
};
}

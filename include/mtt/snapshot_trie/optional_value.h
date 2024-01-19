/**
 * Copyright 2023 Geoffrey Ramseyer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <optional>

namespace trie {

/**
 * Wrapper class to inject extra validation criteria on whether a value should
 *exist within AtomicMerkleTrie
 **/

namespace detail {
template<typename T>
auto default_value_selector = [](T const&) -> bool { return true; };
}

template<typename value_t,
         auto has_value_f>
class OptionalValue
{
    std::optional<value_t> base;

  public:
    using value_type = value_t;

    template<typename... T>
    OptionalValue(T&&... args)
        : base(std::forward<T>(args)...)
    {
    }

    template<typename... T>
    void emplace(T&&... args)
    {
        base.emplace(std::forward<T>(args)...);
    }

    void reset() { base.reset(); }

    value_t& operator*() { return *base; }

    const value_t& operator*() const { return *base; }

    value_t* operator->() { return &(*base); }

    const value_t* operator->() const { return &(*base); }

    bool has_opt_value() const {
        return base.has_value();
    }

    bool has_logical_value() const
    {
        if (!has_opt_value()) {
            return false;
        }
        return has_value_f(*base);
    }
};

} // namespace trie

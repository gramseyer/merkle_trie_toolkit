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
        if (!base.has_value()) {
            return false;
        }
        return has_value_f(*base);
    }
};

} // namespace trie

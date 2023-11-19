#pragma once

#include <concepts>
#include <cstdint>
#include <vector>

namespace trie {

struct EphemeralTrieMetadataBase
{
    bool hash_valid = false;

    Hash hash;

    void
    write_to(std::vector<uint8_t>& digest_bytes) const
    {
        if (!hash_valid) {
            throw std::runtime_error("invalid metadata write");
        }
        digest_bytes.insert(digest_bytes.end(),
            hash.begin(), hash.end());
    }

    template<typename T>
    void from_value(T const& value) {}

    EphemeralTrieMetadataBase&
    operator+=(const EphemeralTrieMetadataBase& other)
    {
        if (hash_valid) {
            throw std::runtime_error("invalid metadata modification");
        }
        return *this;
    }

    void clear() {
        hash_valid = false;
    }
};

template<typename T>
concept EphemeralTrieMetadata = requires(T)
{
    std::is_base_of<EphemeralTrieMetadataBase, T>::value;
} &&
requires(T a)
{
    a.clear();
} &&
requires(T a, T b)
{
    a += b;
} &&
requires(const T& a, std::vector<uint8_t>& v)
{
    a.write_to(v);
};

} // namespace trie

#pragma once

#include <concepts>
#include <cstdint>
#include <vector>

namespace trie {

struct __attribute__((packed))
SnapshotTrieMetadataBase
{
    int32_t size = 0;

    void write_to(std::vector<uint8_t>& digest_bytes) const
    {}

    template<typename T>
    void from_value(T const& value)
    {
        size = 1;
    }

    SnapshotTrieMetadataBase& operator+=(const SnapshotTrieMetadataBase& other)
    {
        size += other.size;
        return *this;
    }
};

template<typename T>
concept SnapshotTrieMetadata = requires(T)
{
    std::is_base_of<SnapshotTrieMetadataBase, T>::value;
}
&&requires(T a, T b)
{
    a += b;
}
&&requires(const T& a, std::vector<uint8_t>& v)
{
    a.write_to(v);
};

} // namespace trie

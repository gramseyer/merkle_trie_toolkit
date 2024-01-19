#pragma once

#include <concepts>
#include <cstdint>
#include <vector>

namespace trie {

struct __attribute__((packed))
SnapshotTrieMetadataBase
{
    //uint32_t size = 0;

    void write_to(std::vector<uint8_t>& digest_bytes) const
    {}

    template<typename T>
    void from_value(T const& value)
    {
    //    size = 1;
    }

    bool try_parse(const uint8_t* data, size_t len)
    {
        return len == 0;
   /*     if (len != hash.size())
        {
            return false;
        }
        std::memcpy(hash.data(), data, len);
        hash_valid = true;
        return true; */
    }


    SnapshotTrieMetadataBase& operator+=(const SnapshotTrieMetadataBase& other)
    {
    //    size += other.size;
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

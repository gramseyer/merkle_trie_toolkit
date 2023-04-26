#include <concepts>
#include <cstdint>
#include <vector>

namespace trie {

struct LayeredTrieNodeMetadataBase
{
    bool hash_valid = false;

    //! No children below current node, so 
    //! return null. Can't use size
    //! variable directly, as that's set to 0
    //! before its computed as part of the hash
    //! calculation (so we at least need some
    //! flag for `hash code has been run once`)
    bool return_null = false;
    Hash hash;
    uint32_t size = 0;

    template<typename T>
    void
    read_from(T const&)
    {}

    void
    write_to(std::vector<uint8_t>& digest_bytes) const
    {
        digest_bytes.insert(digest_bytes.end(),
            hash.begin(), hash.end());
    }

    LayeredTrieNodeMetadataBase&
    operator+=(const LayeredTrieNodeMetadataBase& other)
    {
        size += other.size;
        return *this;
    }
};

template<typename T>
concept LayeredTrieNodeMetadata = requires(T)
{
    std::is_base_of<LayeredTrieNodeMetadataBase, T>::value;
} &&
requires(T a, T b)
{
    a += b;
} &&
requires(const T& a, std::vector<uint8_t>& v)
{
    a.write_to(v);
};

template<typename T>
concept ValueType =
    requires(const T& t)
    {
        { t.is_active() } -> std::same_as<bool>;
        t.get_layer_commitment();
        T(*t.get_layer_commitment());
    }
    && requires(const T& t, std::vector<uint8_t>& v)
    {
        t.get_layer_commitment()->write_to(v);
    };

} // namespace trie

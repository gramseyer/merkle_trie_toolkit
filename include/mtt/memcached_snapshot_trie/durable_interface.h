#pragma once

#include "mtt/common/bitvector.h"
#include "mtt/common/concepts.h"
#include "mtt/common/prefix.h"
#include "mtt/common/types.h"

#include <utils/non_movable.h>
#include <utils/debug_utils.h>

#include <array>
#include <cstdint>
#include <compare>
#include <cstddef>

namespace trie {

/**
 * Schema for durable interface
 *
 * Keys are (last modified ts, pointer address).
 * Guaranteed to be unique.
 *
 * Timestamp ensures we only write to storage the modified entries.
 * Can't use a statically allocated UID unless we did something like the layered
 * trie, with entirely immutable entries.  But that requires a lot more mem
 * reallocations.
 *
 * Does not require complicated range scans to find a value.
 *
 * Nodes also include the id for the key they're replacing.  This enables async
 * garbage collection in the db/state pruning, as necessary. This requires
 * adding a node for when something is deleted.
 */
struct  __attribute__ ((packed))
TimestampPointerPair
{
    uint32_t timestamp;
    const void* ptr;

    static_assert(sizeof(const void*) == 8, "unexpected pointer size");

    template<typename node_t>
    TimestampPointerPair(node_t const& n)
        : timestamp(n.get_last_modified_ts())
        , ptr(static_cast<const void*>(&n))
    {}

    TimestampPointerPair()
        : timestamp()
        , ptr(nullptr)
        {}

    std::strong_ordering operator<=>(const TimestampPointerPair&) const = default;
    bool operator==(const TimestampPointerPair&) const = default;
};

static_assert(offsetof(TimestampPointerPair, timestamp) == 0, "timestamp should come first");


// This is standard-layout, and importantly,
// we can take a slice of a list and get a valid node.
struct 
__attribute__ ((packed))
DurableMapNode
{
    Hash h;
    uint16_t key_len_bits;
    uint16_t bv;
    TimestampPointerPair children[16];
};

/**
 * Value serialization format:
 * hash : 32bytes
 * value_len: 32 bits
 * value: value_len bytes
 */
struct DurableValueSlice
{
    const uint8_t* ptr;
    uint32_t len;
};

struct 
__attribute__ ((packed))
DurableValueHeader
{
    Hash h;
    uint32_t value_len;

    DurableValueSlice to_value_slice() const;
};

DurableValueSlice
DurableValueHeader::to_value_slice() const
{
    return DurableValueSlice{ reinterpret_cast<const uint8_t*>(this)
                                  + sizeof(DurableValueHeader),
                              value_len };
}

struct DurableDeleteNode
{
    PrefixLenBits key_len_bits;
};

template<uint8_t KEY_LEN_BYTES>
class DurableValue
{
    std::vector<uint8_t> buffer;

    void reset_to_map_node()
    {
        buffer.clear();
        buffer.push_back(0);
    }

    void reset_to_value_node()
    {
        buffer.clear();
        buffer.push_back(1);
    }

    void reset_to_delete_node()
    {
        buffer.clear();
        buffer.push_back(2);
    }

    template<TriviallyCopyable T>
    void append_type(const T& v, uint32_t sz = sizeof(T))
    {
        const uint8_t* vp = reinterpret_cast<const uint8_t*>(&v);
        buffer.insert(buffer.end(), vp, vp + std::min<uint32_t>(sz, sizeof(T)));
    }

    void add_key(const TriePrefix auto& key)
    {
        static_assert(key.size_bytes() == KEY_LEN_BYTES, "key len mismatch");

        key.write_bytes_to(buffer, key.len());
    }

  public:
    void make_delete_node(const TriePrefix auto& key, PrefixLenBits key_len)
    {
        reset_to_delete_node();
        add_key(key);
        append_type(key_len.len);
    }

    /**
     * TODO: There's a way to rework this API that avoids a memcpy
     * TODO: Truncate map_node to only include active children
     */
    void make_map_node(const TriePrefix auto& key,
                       DurableMapNode const& map_node)
    {
        reset_to_map_node();
        add_key(key);
        append_type(map_node, 
            sizeof(Hash) 
            + 2 * sizeof(uint16_t) 
            + utils::detail::BVManipFns<uint16_t>::size(map_node.bv) * sizeof(TimestampPointerPair));
    }

    template<typename ValueType>
    void make_value_node(const TriePrefix auto& key,
                         Hash const& h,
                         ValueType const& v)
    {
        reset_to_value_node();
        add_key(key);
        uint32_t value_h_offset = buffer.size();
        constexpr uint32_t value_h_size = sizeof(DurableValueHeader);
        append_type(h);
        append_type(static_cast<uint32_t>(0));
        v.copy_data(buffer);
        auto* vh = reinterpret_cast<DurableValueHeader*>(buffer.data()
                                                         + value_h_offset);
        vh->value_len = buffer.size() - (value_h_offset + value_h_size);
    }

    const std::vector<uint8_t>& get_buffer() const { return buffer; }

    DurableValue()
        : buffer()
    {
        buffer.push_back(255); // invalid start
    }
};

template<uint8_t KEY_LEN_BYTES>
struct DurableKeySlice
{
    const uint8_t* ptr;
};

template<uint8_t KEY_LEN_BYTES, typename BackingType = std::string>
class DurableResult
{
    // TODO: investigate whether,
    // depending on the impl for the persistent storage,
    // something like PinnableSlice in rocksdb would be better
    //
    // Should assert that backing.size() >= 1 + KEY_LEN_BYTES before exposing
    // to external caller
    BackingType backing;

  public:
    // ctor methods
    BackingType& get_backing_data() { return backing; }

    DurableResult() = default;

    bool is_map() const { return backing[0] == 0; }

    bool is_value() const { return backing[0] == 1; }

    bool is_delete() const { return backing[0] == 2; }

    const DurableValueHeader& get_value() const
    {
        if (!is_value()) {
            throw std::runtime_error("get_value() on non value result");
        }

        return *reinterpret_cast<const DurableValueHeader*>(backing.data() + 1
                                                            + KEY_LEN_BYTES);
    }

    DurableKeySlice<KEY_LEN_BYTES> get_key() const
    {
        return DurableKeySlice{ backing.data() + 1 };
    }

    PrefixLenBits get_delete() const
    {
        if (!is_delete()) {
            throw std::runtime_error("get_value() on non value result");
        }

        return *reinterpret_cast<const PrefixLenBits*>(backing.data() + 1
                                                       + KEY_LEN_BYTES);
    }

    const DurableMapNode& get_map() const
    {
        if (!is_map()) {
            throw std::runtime_error("get_map() on non map result");
        }
        return *reinterpret_cast<const DurableMapNode*>(backing.data() + 1
                                                        + KEY_LEN_BYTES);
    }
};

template<typename T>
concept DurableInterface = requires(T t,
                                    TimestampPointerPair const& k,
                                    DurableValue<T::KEY_LEN_BYTES> const& v)
{
    t.log_durable_value(k, v);
}
&&requires(T t, TimestampPointerPair const& k)
{
    // credit to https://stackoverflow.com/a/66275373
    []<typename BackingType>(DurableResult<T::KEY_LEN_BYTES, BackingType>) {
    }(t.restore_durable_value(k));
};

} // namespace trie

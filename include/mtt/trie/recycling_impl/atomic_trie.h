#pragma once

#include <array>
#include <atomic>
#include <cstdint>

#include "mtt/trie/prefix.h"
#include "mtt/trie/recycling_impl/allocator.h"
#include "mtt/trie/types.h"
#include "mtt/trie/utils.h"

#include <utils/non_movable.h>

namespace trie {

/**
 * IMPORTANT WARNING:
 * InsertFn::value_insert must be threadsafe
 */

class AtomicChildrenMap : private utils::NonMovableOrCopyable
{
    std::array<std::atomic<uint64_t>, 16> children;

  public:

    AtomicChildrenMap()
    {
        clear();
    }

    bool try_set(uint8_t bb, uint64_t& expected, uint64_t desired)
    {
        bool res = children[bb].compare_exchange_weak(
            expected, desired, std::memory_order_acq_rel);

        std::printf("tried to swap on %p res %lu desired %llx current value %llx \n", this, res, desired, expected);
        return res;
    }

    uint64_t get(uint8_t bb) const
    {
        return children[bb].load(std::memory_order_acquire);
    }

    void clear()
    {
        for (uint8_t i = 0; i < 16; i++) {
            children[i].store(0xFFFF'FFFF'0000'0000, std::memory_order_release);
        }
    }

    void set_unique_child(uint8_t single_child_branch_bits,
                          uint64_t single_child_ptr)
    {
        clear();
        children[single_child_branch_bits].store(
            single_child_ptr,
            std::memory_order_release);
    }


    void print() const
    {
        std::printf("self: %p\n", this);
        for (uint8_t i = 0; i < 16; i++) {
            std::printf("    %u %llx\n", i, children[i].load(std::memory_order_acquire));
        }
    }
};

template<typename ValueType, typename PrefixT>
class AtomicTrie;

template<typename ValueType, typename PrefixT>
class alignas(64) AtomicTrieNode : private utils::NonMovableOrCopyable
{

  public:
    using prefix_t = PrefixT;
    using node_t = AtomicTrieNode<ValueType, prefix_t>;
    using allocation_context_t = AllocationContext<node_t>;
    using allocator_t = RecyclingTrieNodeAllocator<node_t>;
    using value_t = ValueType;
    using main_trie_t = AtomicTrie<ValueType, PrefixT>;

  private:
    constexpr static uint8_t KEY_LEN_BYTES = PrefixT::size_bytes();

    constexpr static PrefixLenBits MAX_KEY_LEN_BITS
        = PrefixLenBits{ KEY_LEN_BYTES * 8 };

    AtomicChildrenMap children;

    prefix_t prefix;

    PrefixLenBits prefix_len;

    uint32_t value_pointer = UINT32_MAX;

    bool hash_valid = false;

    Hash hash;

  public:
    // constructors

    template<typename InsertFn, typename InsertedValueType>
    void set_as_new_value_leaf(
        const prefix_t& key,
        typename std::enable_if<
            !std::is_same<ValueType, InsertedValueType>::value,
            InsertedValueType&&>::type value,
        allocation_context_t& allocator)
    {
        // no need to clear children
        value_pointer = allocator.allocate_value();
        auto& new_value = allocator.get_value(value_pointer);
        new_value = InsertFn::new_value(key);
        InsertFn::value_insert(new_value, std::move(value));

        prefix = key;
        prefix_len = MAX_KEY_LEN_BITS;

        hash_valid = false;
    }

    template<typename InsertFn, typename InsertedValueType>
    void set_as_new_value_leaf(
        const prefix_t& key,
        typename std::enable_if<
            std::is_same<ValueType, InsertedValueType>::value,
            InsertedValueType&&>::type value,
        allocation_context_t& allocator)
    {
        // no need to clear children
        value_pointer = allocator.allocate_value();
        allocator.get_value(value_pointer) = std::move(value);

        prefix = key;
        prefix_len = MAX_KEY_LEN_BITS;

        hash_valid = false;
    }

    void set_as_new_branch_node(const prefix_t& key,
                                const PrefixLenBits& len,
                                uint64_t single_child_pointer,
                                uint8_t single_child_branch_bits,
                                allocation_context_t& allocator)
    {
        // could clear value, but unnecessary

        prefix = key;
        prefix_len = len;

        prefix.truncate(prefix_len);

        std::printf("new branch node bb %lu ptr %lx\n", single_child_branch_bits, single_child_pointer);

        children.set_unique_child(single_child_branch_bits, single_child_pointer);

        hash_valid = false;
    }

    void set_as_empty_node()
    {
        prefix.clear();
        prefix_len = PrefixLenBits{0};

        children.clear();

        hash_valid = false;
    }

    PrefixLenBits get_prefix_match_len(const prefix_t& other_key,
                                       const PrefixLenBits other_len
                                       = MAX_KEY_LEN_BITS) const
    {
        return prefix.get_prefix_match_len(prefix_len, other_key, other_len);
    }

    bool insert_can_recurse(const prefix_t& query_prefix) const
    {
        return get_prefix_match_len(query_prefix) >= prefix_len;
    }

    uint8_t get_branch_bits(const PrefixLenBits& query) const
    {
        if (query >= prefix_len) {
            throw std::runtime_error("invalid");
        }

        return prefix.get_branch_bits(query);
    }

    void print_self(std::string padding) const
    {
        std::printf("%s prefix=%s len=%u\n", padding.c_str(), prefix.to_string(prefix_len).c_str(),
                 prefix_len.len);
        children.print();
    }

    template<typename InsertFn, typename InsertedValue>
    void insert(prefix_t const& new_prefix,
                InsertedValue&& value,
                allocation_context_t& allocator)
    {
        print_self("insert");
        auto prefix_match_len = get_prefix_match_len(new_prefix);
        // correctness assertion
        if (prefix_match_len < prefix_len) {
            throw std::runtime_error("invalid insertion");
        }

        if (prefix_len == MAX_KEY_LEN_BITS) {
            InsertFn::value_insert(allocator.get_value(value_pointer),
                                   std::move(value));
            return;
        }

        const uint8_t bb = new_prefix.get_branch_bits(prefix_len);

        auto get_ptr = [](uint64_t ptr_and_size) -> uint32_t {
            return ptr_and_size >> 32;
        };
        auto get_sz = [](uint64_t ptr_and_size) -> uint32_t {
            return ptr_and_size & 0xFFFF'FFFF;
        };

        uint64_t relevant_child = children.get(bb);

        uint32_t new_ptr = UINT32_MAX;

        while (true) {

            uint32_t ptr = get_ptr(relevant_child);
            if (ptr == UINT32_MAX) {
                if (new_ptr == UINT32_MAX) {
                    new_ptr = allocator.allocate(1);
                }

                auto& new_child = allocator.get_object(new_ptr);

                new_child.template set_as_new_value_leaf<InsertFn, InsertedValue>(
                    new_prefix, std::move(value), allocator);

                uint64_t swap = (static_cast<uint64_t>(new_ptr) << 32) + 1;

                std::printf("new node create %llx\n", swap);

                if (children.try_set(bb, relevant_child, swap)) {
                    // nothing to do
                    return;
                }
            } else {
                // check if should recurse
                auto& child = allocator.get_object(ptr);
                if (child.insert_can_recurse(new_prefix)) {

                    std::printf("bump size and recurse\n");
                    if (children.try_set(
                            bb, relevant_child, relevant_child + 1)) {
                        child.template insert<InsertFn>(new_prefix, std::move(value), allocator);
                        return;
                    }
                } else {
                    if (new_ptr == UINT32_MAX) {
                        new_ptr = allocator.allocate(1);
                    }

                    PrefixLenBits join_len
                        = child.get_prefix_match_len(new_prefix);

                    auto& new_node = allocator.get_object(new_ptr);

                    new_node.set_as_new_branch_node(
                        new_prefix,
                        join_len,
                        relevant_child,
                        child.get_branch_bits(join_len),
                        allocator);

                    uint64_t swap = (static_cast<uint64_t>(new_ptr) << 32)
                                    + get_sz(relevant_child) + 1;

                    std::printf("allocate intermediate node: relevant_child (new_node) %llx swap %llx\n", relevant_child, swap);

                    if (children.try_set(bb, relevant_child, swap)) {
                        new_node.template insert<InsertFn>(
                            new_prefix, std::move(value), allocator);
                        return;
                    }
                }
            }
            __builtin_ia32_pause();
        }
    }

    // TESTING

    uint32_t deep_sizecheck(allocator_t const& allocator) const
    {
        print_self("sizecheck");
        if (prefix_len == MAX_KEY_LEN_BITS)
        {
            return 1;
        }

        uint32_t total_size = 0;

        for (uint8_t bb = 0; bb < 16; bb++)
        {
            uint64_t res = children.get(bb);

            std::printf("query for %llx\n", res);

            uint32_t expected_sz = res & 0xFFFF'FFFF;

            uint32_t ptr = res >> 32;

            if (ptr == UINT32_MAX) {
                continue;
            }

            auto const& child = allocator.get_object(ptr);

            uint32_t got_sz = child.deep_sizecheck(allocator);
            if (got_sz != expected_sz)
            {
                std::printf("expected %lu, got %lu\n", expected_sz, got_sz);
                throw std::runtime_error("size mismatch");
            }

            total_size += got_sz;
        }
        return total_size;
    }
};

template<typename ValueType, typename PrefixT>
class AtomicTrie
{
public:
    using prefix_t = PrefixT;
    using node_t = AtomicTrieNode<ValueType, prefix_t>;
    using allocation_context_t = AllocationContext<node_t>;
    using allocator_t = RecyclingTrieNodeAllocator<node_t>;
    using value_t = ValueType;
    using main_trie_t = AtomicTrie<ValueType, PrefixT>;

private:
    allocator_t allocator;

    node_t root;

public:

    allocation_context_t get_new_allocation_context()
    {
        return allocator.get_new_allocator();
    }

    AtomicTrie()
        : allocator()
        , root()
        {
            root.set_as_empty_node();
        }

    template<typename InsertFn = OverwriteInsertFn<ValueType>, typename InsertedValueType = ValueType>
    void insert(prefix_t const& new_prefix,
            InsertedValueType&& value,
            allocation_context_t& allocator)
    {
        root.template insert<InsertFn, InsertedValueType>(new_prefix, std::move(value), allocator);
    }

    void clear()
    {
        root.set_as_empty_node();
        allocator.reset();
    }

    // TESTING

    uint32_t deep_sizecheck() const
    {
        return root.deep_sizecheck(allocator);
    }
};

} // namespace trie

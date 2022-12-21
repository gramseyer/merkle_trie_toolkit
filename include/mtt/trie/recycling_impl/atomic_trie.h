#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <cinttypes>

#include "mtt/trie/bitvector.h"
#include "mtt/trie/debug_macros.h"
#include "mtt/trie/prefix.h"
#include "mtt/trie/recycling_impl/allocator.h"
#include "mtt/trie/recycling_impl/ranges.h"
#include "mtt/trie/recycling_impl/atomic_ranges.h"
#include "mtt/trie/types.h"
#include "mtt/trie/utils.h"

#include <utils/non_movable.h>

#include <sodium.h>

#include <tbb/parallel_for.h>

namespace trie {

/**
 * IMPORTANT WARNING:
 * InsertFn::value_insert must be threadsafe
 */

class AtomicChildrenMap : private utils::NonMovableOrCopyable
{
    std::array<std::atomic<uint64_t>, 16> children;

  public:
    AtomicChildrenMap() { clear(); }

    bool try_set(uint8_t bb, uint64_t& expected, uint64_t desired)
    {
        bool res = children[bb].compare_exchange_weak(
            expected, desired, std::memory_order_acq_rel);

        /*std::printf(
            "tried to swap on %p res %lu desired %llx current value %llx \n",
            this,
            res,
            desired,
            expected); */
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
        children[single_child_branch_bits].store(single_child_ptr,
                                                 std::memory_order_release);
    }

    void print() const
    {
        std::printf("self: %p\n", this);
        for (uint8_t i = 0; i < 16; i++) {
            std::printf("    %u %llx\n",
                        i,
                        children[i].load(std::memory_order_acquire));
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
    using ptr_t = uint32_t;

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

        children.set_unique_child(single_child_branch_bits,
                                  single_child_pointer);

        hash_valid = false;
    }

    void set_as_empty_node()
    {
        prefix.clear();
        prefix_len = PrefixLenBits{ 0 };

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
        std::printf("%s prefix=%s len=%u\n",
                    padding.c_str(),
                    prefix.to_string(prefix_len).c_str(),
                    prefix_len.len);
        children.print();
    }

    template<typename InsertFn, typename InsertedValue>
    bool __attribute__((warn_unused_result))
    insert(prefix_t const& new_prefix,
           InsertedValue&& value,
           allocation_context_t& allocator);

    void bump_size(prefix_t const& bump_prefix, allocation_context_t& allocator);

    std::vector<uint32_t> children_list() const;
    //legacy compat
    std::vector<uint32_t> children_list_nolock() const
    {
        return children_list();
    }

    std::vector<uint64_t> children_and_sizes_list() const;

    uint32_t size() const;

    void append_hash_to_vec(std::vector<uint8_t>& digest_buffer) const;
    void compute_hash(allocator_t& allocator, std::vector<uint8_t>& digest_buffer);

    Hash get_hash() const {
        return hash;
    }

    const prefix_t& get_prefix() const {
        return prefix;
    }

    const PrefixLenBits& get_prefix_len() const { return prefix_len; }

    template<typename ApplyFn>
    void apply_to_kvs(ApplyFn& fn, const allocator_t& allocator) const
    {
        if (prefix_len == MAX_KEY_LEN_BITS)
        {
            fn(prefix, allocator.get_value(value_pointer));
            return;
        }

        for (uint8_t bb = 0; bb < 16; bb++)
        {
            uint32_t ptr = children.get(bb) >> 32;
            if (ptr != UINT32_MAX)
            {
                auto const& child = allocator.get_object(ptr);
                child.apply_to_kvs(fn, allocator);
            }
        }
    }

    template<typename VectorType, auto get_fn>
    void accumulate_values_parallel_worker(VectorType& output,
                                            size_t vector_offset,
                                            const allocator_t& allocator) const;

    // TESTING

    uint32_t deep_sizecheck(allocator_t const& allocator) const
    {
        if (prefix_len == MAX_KEY_LEN_BITS) {
            return 1;
        }

        uint32_t total_size = 0;

        for (uint8_t bb = 0; bb < 16; bb++) {
            uint64_t res = children.get(bb);

            uint32_t expected_sz = res & 0xFFFF'FFFF;

            uint32_t ptr = res >> 32;

            if (ptr == UINT32_MAX) {
                continue;
            }

            auto const& child = allocator.get_object(ptr);

            uint32_t got_sz = child.deep_sizecheck(allocator);
            if (got_sz != expected_sz) {
                std::printf("expected %" PRIu32 ", got %" PRIu32 "\n", expected_sz, got_sz);
                throw std::runtime_error("size mismatch");
            }

            total_size += got_sz;
        }
        return total_size;
    }

    const value_t* get_value(const prefix_t& query_prefix, allocator_t const& allocator) const
    {
        auto match_len = get_prefix_match_len(query_prefix);
        if (match_len < prefix_len) {
            return nullptr;
        }
        //match_len == prefix_len

        if (match_len == MAX_KEY_LEN_BITS)
        {
            return &allocator.get_value(value_pointer);
        }

        auto bb = query_prefix.get_branch_bits(match_len);

        uint32_t relevant_child = (children.get(bb) >> 32);

        if (relevant_child == UINT32_MAX)
        {
            return nullptr;
        }

        return allocator.get_object(relevant_child).get_value(query_prefix, allocator);

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

  private:
    allocator_t allocator;

    node_t root;

    bool hashed = false;

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

    template<typename InsertFn = OverwriteInsertFn<ValueType>,
             typename InsertedValueType = ValueType>
    void insert(prefix_t const& new_prefix,
                InsertedValueType&& value,
                allocation_context_t& allocator_context)
    {
        if (hashed)
        {
            throw std::runtime_error("cannot insert after hashing");
        }

        if (root.template insert<InsertFn, InsertedValueType>(
                new_prefix, std::move(value), allocator_context)) {
            root.bump_size(new_prefix, allocator_context);
        }
    }

    Hash hash_serial() {
        std::vector<uint8_t> digest_bytes;
        root.compute_hash(allocator, digest_bytes);
        // no need for double hash root -- 
        // hash of root already records that prefix len is 0, ensures
        // we can't embed this hash into another fake trie to 
        // fake a proof
        hashed = true;
        return root.get_hash();
    }

    Hash hash()
    {
        tbb::parallel_for(RecyclingHashRange<node_t>(&root, allocator),
          [this](const auto& r) {
              std::vector<uint8_t> digest_buffer;
              for (size_t i = 0; i < r.num_nodes(); i++) {
                  r[i].compute_hash(
                      allocator, digest_buffer);
              }
          });

        return hash_serial();
    }

    template<typename ValueModifyFn>
    void parallel_batch_value_modify_const(ValueModifyFn& fn, uint32_t GRAIN_SIZE) const
    {
        AtomicRecyclingApplyRange<node_t> range(&root, allocator, GRAIN_SIZE);
        // guaranteed that range.work_list contains no overlaps

        tbb::parallel_for(range, [&fn, this](const auto& range) {
            for (size_t i = 0; i < range.work_list.size(); i++) {

                auto const* ptr = &allocator.get_object(range.work_list[i] >> 32);

                ConstApplyableSubnodeRef ref{ ptr, allocator };
                fn(ref);
            }
        });
    }

    template<typename ValueModifyFn>
    void parallel_batch_value_modify(ValueModifyFn& fn, uint32_t GRAIN_SIZE)
    {
        AtomicRecyclingApplyRange<node_t> range(&root, allocator, GRAIN_SIZE);
        // guaranteed that range.work_list contains no overlaps

        tbb::parallel_for(range, [&fn, this](const auto& range) {
            for (size_t i = 0; i < range.work_list.size(); i++) {

                auto* ptr = &allocator.get_object(range.work_list[i] >> 32);

                ApplyableSubnodeRef ref{ ptr, allocator };
                fn(ref);
            }
        });
    }

    template<typename VectorType, auto get_fn>
    void accumulate_values_parallel(VectorType& out, uint32_t GRAIN_SIZE) const
    {
        AtomicRecyclingAccumulateValuesRange<node_t> range(root.children_and_sizes_list(), allocator, GRAIN_SIZE);

        out.resize(size());

        tbb::parallel_for(range, [this, &out] (const auto& range)
        {
            uint32_t vector_offset = range.vector_offset;

            for (size_t i = 0; i < range.work_list.size(); i++) {
                uint32_t ptr = range.work_list[i] >> 32;
                uint32_t sz = range.work_list[i] & 0xFFFF'FFFF;

                auto& work_node = allocator.get_object(ptr);
                work_node.template accumulate_values_parallel_worker<VectorType, get_fn>(
                    out, vector_offset, allocator);
                vector_offset += sz;
            }
        });
    }

    void clear()
    {
        hashed = false;
        root.set_as_empty_node();
        allocator.reset();
    }

    uint32_t size() const
    {
        return root.size();
    }

    // TESTING

    uint32_t deep_sizecheck() const { return root.deep_sizecheck(allocator); }

    const value_t* get_value(const prefix_t& query_prefix) const
    {
        return root.get_value(query_prefix, allocator);
    }
};

template<typename ValueType, typename prefix_t>
class AtomicTrieReference : public utils::NonMovableOrCopyable
{
    using node_t = AtomicTrieNode<ValueType, prefix_t>;
    using allocation_context_t = AllocationContext<node_t>;

    AtomicTrie<ValueType, prefix_t>& main_trie;
    allocation_context_t alloc;

public:

    AtomicTrieReference(AtomicTrie<ValueType, prefix_t>& main_trie)
        : main_trie(main_trie)
        , alloc(main_trie.get_new_allocation_context())
        {}

    template<typename InsertFn = OverwriteInsertFn<ValueType>,
             typename InsertedValueType = ValueType>
    void insert(prefix_t const& new_prefix,
                InsertedValueType&& value)
    {
        main_trie.template insert<InsertFn, InsertedValueType>(new_prefix, std::move(value), alloc);
    }

    void insert(prefix_t const& new_prefix)
    {
        main_trie.template insert<OverwriteInsertFn<EmptyValue>, EmptyValue>(new_prefix, EmptyValue{}, alloc);
    }
};

#define ATN_TEMPLATE template<typename ValueType, typename PrefixT>
#define ATN_DECL AtomicTrieNode<ValueType, PrefixT>

ATN_TEMPLATE
template<typename InsertFn, typename InsertedValue>
bool __attribute__((warn_unused_result))
ATN_DECL :: insert(prefix_t const& new_prefix,
                  InsertedValue&& value,
                  allocation_context_t& allocator)
{
    auto prefix_match_len = get_prefix_match_len(new_prefix);
    // correctness assertion
    if (prefix_match_len < prefix_len) {
        throw std::runtime_error("invalid insertion");
    }

    if (prefix_len == MAX_KEY_LEN_BITS) {
        InsertFn::value_insert(allocator.get_value(value_pointer),
                               std::move(value));
        return false;
    }

    const uint8_t bb = new_prefix.get_branch_bits(prefix_len);

    auto get_ptr
        = [](uint64_t ptr_and_size) -> uint32_t { return ptr_and_size >> 32; };
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

            uint64_t swap = (static_cast<uint64_t>(new_ptr) << 32);

            if (children.try_set(bb, relevant_child, swap)) {
                // nothing to do
                return true;
            }
        } else {
            // check if should recurse
            auto& child = allocator.get_object(ptr);
            if (child.insert_can_recurse(new_prefix)) {

                return child.template insert<InsertFn>(
                    new_prefix, std::move(value), allocator);

            } else {
                if (new_ptr == UINT32_MAX) {
                    new_ptr = allocator.allocate(1);
                }

                PrefixLenBits join_len = child.get_prefix_match_len(new_prefix);

                auto& new_node = allocator.get_object(new_ptr);

                new_node.set_as_new_branch_node(new_prefix,
                                                join_len,
                                                relevant_child,
                                                child.get_branch_bits(join_len),
                                                allocator);

                uint64_t swap = (static_cast<uint64_t>(new_ptr) << 32)
                                + get_sz(relevant_child);

                if (children.try_set(bb, relevant_child, swap)) {
                    return new_node.template insert<InsertFn>(
                        new_prefix, std::move(value), allocator);
                }
            }
        }
        __builtin_ia32_pause();
    }
}

ATN_TEMPLATE
void
ATN_DECL :: bump_size(prefix_t const& bump_prefix,
                     allocation_context_t& allocator)
{
    if (prefix_len == MAX_KEY_LEN_BITS) {
        return;
    }

    const uint8_t bb = bump_prefix.get_branch_bits(prefix_len);

    uint64_t relevant_child = children.get(bb);

    while (true) {
        if (children.try_set(bb, relevant_child, relevant_child + 1)) {
            auto& child = allocator.get_object(relevant_child >> 32);

            child.bump_size(bump_prefix, allocator);
            return;
        }
        __builtin_ia32_pause();
    }
}

ATN_TEMPLATE
std::vector<uint32_t> 
ATN_DECL :: children_list() const
{
    std::vector<uint32_t> out;
    for (uint8_t i = 0; i < 16; i++)
    {
        uint32_t ptr = (children.get(i) >> 32);
        if (ptr != UINT32_MAX)
        {
            out.push_back(ptr);
        }

    }
    return out;
}

ATN_TEMPLATE
std::vector<uint64_t> 
ATN_DECL :: children_and_sizes_list() const
{
    std::vector<uint64_t> out;
    for (uint8_t i = 0; i < 16; i++)
    {
        uint64_t ptr_and_size = children.get(i);
        uint32_t ptr = (ptr_and_size >> 32);
        if (ptr != UINT32_MAX)
        {
            out.push_back(ptr_and_size);
        }

    }
    return out;
}

ATN_TEMPLATE
template<typename VectorType, auto get_fn>
void
ATN_DECL :: accumulate_values_parallel_worker(VectorType& output,
                                            size_t vector_offset,
                                            const allocator_t& allocator) const
{
    if (prefix_len == MAX_KEY_LEN_BITS) {
        output[vector_offset] = get_fn(allocator.get_value(value_pointer));
        //AccumulatorFn::accumulate(output, vector_offset, children.value(allocator));
        //output[vector_offset] = children.value(allocator);
        return;
    }

    for (uint8_t bb = 0; bb < 16; bb++)
    {
        uint64_t ptr_and_sz = children.get(bb);

        uint32_t ptr = ptr_and_sz >> 32;
        if (ptr == UINT32_MAX)
        {
            continue;
        }
        auto& ref = allocator.get_object(ptr);
        ref.template accumulate_values_parallel_worker<VectorType, get_fn>(output, vector_offset, allocator);
        vector_offset == (ptr_and_sz & 0xFFFF'FFFF);
    }
}

ATN_TEMPLATE
uint32_t
ATN_DECL :: size() const
{
    if (prefix_len == MAX_KEY_LEN_BITS)
    {
        return 1;
    }
    uint32_t acc = 0;
    for (uint8_t bb = 0; bb < 16; bb++)
    {
        acc += (children.get(bb) & 0xFFFF'FFFF);
    }
    return acc;
}

ATN_TEMPLATE 
void
ATN_DECL :: append_hash_to_vec(std::vector<uint8_t>& digest_buffer) const
{
    digest_buffer.insert(
        digest_buffer.end(),
        hash.begin(),
        hash.end());
}

ATN_TEMPLATE
void
ATN_DECL :: compute_hash(allocator_t& allocator, std::vector<uint8_t>& digest_buffer)
{
    if (hash_valid)
    {
        return;
    }

    if (prefix_len == MAX_KEY_LEN_BITS)
    {

        digest_buffer.clear();
        write_node_header(digest_buffer, prefix, prefix_len);
        
        auto const& value = allocator.get_value(value_pointer);
        value.copy_data(digest_buffer);
    }
    else
    {
        TrieBitVector bv;

        for (uint8_t bb = 0; bb < 16; bb++)
        {
            uint64_t res = children.get(bb);

            if ((res >> 32) != UINT32_MAX)
            {
                allocator.get_object(res >> 32).compute_hash(allocator, digest_buffer);
                bv.add(bb);
            }
        }

        digest_buffer.clear();
        write_node_header(digest_buffer, prefix, prefix_len);
        bv.write(digest_buffer);

        for (uint8_t bb = 0; bb < 16; bb++)
        {
            uint64_t res = children.get(bb);

            if ((res >> 32) != UINT32_MAX)
            {
                allocator.get_object(res >> 32).append_hash_to_vec(digest_buffer);
            }
        }
    }

    //print_self("hash time");
    //std::printf("input data %s\n", detail::array_to_str(digest_buffer).c_str());

    if (crypto_generichash(hash.data(),
                           hash.size(),
                           digest_buffer.data(),
                           digest_buffer.size(),
                           NULL,
                           0)
        != 0) {
        throw std::runtime_error("error from crypto_generichash");
    }
    hash_valid = true;
}

#undef ATN_DECL
#undef ATN_TEMPLATE

} // namespace trie

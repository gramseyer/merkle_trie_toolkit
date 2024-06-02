#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <cinttypes>
#include <optional>
#include <vector>

#include "mtt/common/bitvector.h"
#include "mtt/common/prefix.h"
#include "mtt/common/types.h"
#include "mtt/common/debug_macros.h"
#include "mtt/common/insert_fn.h"
#include "mtt/common/utils.h"
#include "mtt/common/proof.h"

#include "mtt/ephemeral_trie/allocator.h"
#include "mtt/ephemeral_trie/ranges.h"
#include "mtt/ephemeral_trie/concepts.h"

#include <utils/non_movable.h>
#include <utils/compat.h>

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
            std::printf("    %u %" PRIx64 "\n",
                        i,
                        children[i].load(std::memory_order_acquire));
        }
    }
};

template<typename ValueType, typename PrefixT, EphemeralTrieMetadata metadata_t, uint8_t LOG_BUFSIZE, uint8_t LOG_NUM_BUFFERS>
class AtomicTrie;

template<typename ValueType, typename PrefixT, uint8_t LOG_BUFSIZE, uint8_t LOG_NUM_BUFFERS, EphemeralTrieMetadata metadata_t>
class alignas(64) AtomicTrieNode : private utils::NonMovableOrCopyable
{

  public:
    using prefix_t = PrefixT;
    using node_t = AtomicTrieNode<ValueType, prefix_t, LOG_BUFSIZE, LOG_NUM_BUFFERS, metadata_t>;
    using allocator_t = EphemeralTrieNodeAllocator<node_t, ValueType, LOG_BUFSIZE, LOG_NUM_BUFFERS>;
    using allocation_context_t = typename allocator_t::context_t;
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

    metadata_t metadata;

  public:
    // constructors

    template<typename InsertFn, typename InsertedValueType>
    void set_as_new_value_leaf(
        const prefix_t& key,
        InsertedValueType&& value,
        allocation_context_t& allocator)
    {
        // no need to clear children
        value_pointer = allocator.allocate_value();
        auto& new_value = allocator.get_value(value_pointer);
        InsertFn::reset_value(new_value, key);
        InsertFn::value_insert(new_value, std::move(value));

        prefix = key;
        prefix_len = MAX_KEY_LEN_BITS;

        metadata.clear();
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

        // TODO, strange bug -- having this as prefix_len, instead of len,
        // somehow optimizes to inputting the value of prefix_len before
        // the prefix_len = len call. (in prior commit e527d13ae356b40025742f7eac7eb90eb46d52f5
        // of groundhog, using ./blockstm_comparison with short_stuff=true
        prefix.truncate(len);

        children.set_unique_child(single_child_branch_bits,
                                  single_child_pointer);

        metadata.clear();
    }

    void set_as_empty_node()
    {
        prefix.clear();
        prefix_len = PrefixLenBits{ 0 };

        children.clear();

        metadata.clear();
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

    void append_metadata(std::vector<uint8_t>& digest_buffer, metadata_t& acc) const;
    void compute_hash(allocator_t& allocator, std::vector<uint8_t>& digest_buffer);

    Hash get_hash() const {
        return metadata.hash;
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

    template<typename ApplyFn>
    void apply_to_keys(ApplyFn& fn, const PrefixLenBits max_len, const allocator_t& allocator) const
    {
        if (prefix_len >= max_len)
        {
            fn(prefix);
            return;
        }

        for (uint8_t bb = 0; bb < 16; bb++)
        {
            uint32_t ptr = children.get(bb) >> 32;
            if (ptr != UINT32_MAX)
            {
                auto const& child = allocator.get_object(ptr);
                child.apply_to_keys(fn, max_len, allocator);
            }
        }
    }

    template<typename VectorType, auto get_fn>
    void accumulate_values_parallel_worker(VectorType& output,
                                            size_t vector_offset,
                                            const allocator_t& allocator) const;

    value_t* get_value(const prefix_t& query_prefix, allocator_t const& allocator);

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

    metadata_t get_metadata(const prefix_t& query_prefix, PrefixLenBits query_len, allocator_t const& allocator) const
    {
        if (prefix_len > query_len)
        {
            throw std::runtime_error("invalid query");
        }
        if (prefix_len == query_len)
        {
            if (!metadata.hash_valid) {
                throw std::runtime_error("invalid metadata access");
            }
            return metadata;
        }

        auto bb = query_prefix.get_branch_bits(prefix_len);

        return allocator.get_object(children.get(bb) >> 32).get_metadata(query_prefix, query_len, allocator);
    }

    TrieProof<prefix_t> make_proof(prefix_t const& query_prefix, PrefixLenBits const& query_len, allocator_t const& allocator) const;
    
    const node_t* get_child(uint8_t bb, const allocator_t& allocator) const;
};

template<
    typename ValueType, 
    typename PrefixT, 
    EphemeralTrieMetadata metadata_t = EphemeralTrieMetadataBase, 
    uint8_t LOG_BUFSIZE = 19, 
    uint8_t LOG_NUM_BUFFERS = 32 - LOG_BUFSIZE>
class AtomicTrie
{
  public:
    using prefix_t = PrefixT;
    using node_t = AtomicTrieNode<ValueType, prefix_t, LOG_BUFSIZE, LOG_NUM_BUFFERS, metadata_t>;
    using allocator_t = typename node_t::allocator_t;
    using allocation_context_t = typename allocator_t::context_t;
    using value_t = ValueType;

    using const_applyable_ref = ConstApplyableNodeReference<allocator_t>;
    using applyable_ref = ApplyableNodeReference<allocator_t>;

  private:

    using self_t = AtomicTrie<ValueType, PrefixT, metadata_t, LOG_BUFSIZE>;

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
    bool insert(prefix_t const& new_prefix,
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
            return true;
        }
        return false;
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
        tbb::parallel_for(EphemeralTrieHashRange<node_t>(&root, allocator),
          [this](const auto& r) {
              std::vector<uint8_t> digest_buffer;
              for (size_t i = 0; i < r.num_nodes(); i++) {
                  r[i].compute_hash(
                      allocator, digest_buffer);
              }
          });

        return hash_serial();
    }

    template<typename ValueModifyFn, PrefixLenBits max_split_len>
    void parallel_batch_value_modify_const(ValueModifyFn& fn, uint32_t GRAIN_SIZE) const
    {
        EphemeralTrieApplyRange<node_t, max_split_len> range(&root, allocator, GRAIN_SIZE);
        // guaranteed that range.work_list contains no overlaps

        tbb::parallel_for(range, [&fn, this](const auto& range) {
            for (size_t i = 0; i < range.work_list.size(); i++) {

                auto const* ptr = &allocator.get_object(range.work_list[i] >> 32);

                const_applyable_ref ref{ ptr, allocator };
                fn(ref);
            }
        });
    }

    template<typename ValueModifyFn, PrefixLenBits max_split_len>
    void parallel_batch_value_modify(ValueModifyFn& fn, uint32_t GRAIN_SIZE)
    {
        EphemeralTrieApplyRange<node_t, max_split_len> range(&root, allocator, GRAIN_SIZE);
        // guaranteed that range.work_list contains no overlaps

        tbb::parallel_for(range, [&fn, this](const auto& range) {
            for (size_t i = 0; i < range.work_list.size(); i++) {

                auto* ptr = &allocator.get_object(range.work_list[i] >> 32);

                applyable_ref ref{ ptr, allocator };
                fn(ref);
            }
        });
    }

    template<typename VectorType, auto get_fn>
    void accumulate_values_parallel(VectorType& out, uint32_t GRAIN_SIZE) const
    {
        EphemeralTrieAccumulateValuesRange<node_t> range(root.children_and_sizes_list(), allocator, GRAIN_SIZE);

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

    TrieProof<PrefixT> make_proof(const prefix_t& query, PrefixLenBits const& query_len) const
    {
        return root.make_proof(query, query_len, allocator);
    }

    static bool verify_proof(TrieProof<prefix_t> const& proof, const Hash& root_hash);

    // TESTING

    uint32_t deep_sizecheck() const { return root.deep_sizecheck(allocator); }

    value_t* get_value(const prefix_t& query_prefix)
    {
        return root.get_value(query_prefix, allocator);
    }

    const value_t* get_value(const prefix_t& query_prefix) const {
        return const_cast<const value_t*>(
            const_cast<self_t*>(this)->get_value(query_prefix));
    }

    const_applyable_ref get_applyable_ref() const {
        return const_applyable_ref { &root, allocator };
    }

    metadata_t get_metadata(const prefix_t& query_prefix, PrefixLenBits prefix_len) const {
        return root.get_metadata(query_prefix, prefix_len, allocator);
    }
};

template<typename main_trie_t>
class AtomicTrieReference : public utils::NonMovableOrCopyable
{
    using node_t = typename main_trie_t::node_t;//AtomicTrieNode<ValueType, prefix_t, LOG_BUFSIZE>;
    using allocation_context_t = typename node_t::allocation_context_t;

    using value_t = typename node_t::value_t;
    using prefix_t = typename node_t::prefix_t;

    main_trie_t& main_trie;

    allocation_context_t alloc;

public:

    AtomicTrieReference(main_trie_t& main_trie) //AtomicTrie<ValueType, prefix_t, LOG_BUFSIZE>& main_trie)
        : main_trie(main_trie)
        , alloc(main_trie.get_new_allocation_context())
        {}

    template<typename InsertFn = OverwriteInsertFn<value_t>,
             typename InsertedValueType = value_t>
    bool insert(prefix_t const& new_prefix,
                InsertedValueType&& value)
    {
        return main_trie.template insert<InsertFn, InsertedValueType>(new_prefix, std::move(value), alloc);
    }

    bool insert(prefix_t const& new_prefix)
    {
        return main_trie.template insert<OverwriteInsertFn<EmptyValue>, EmptyValue>(new_prefix, EmptyValue{}, alloc);
    }
};

#define ATN_TEMPLATE template<typename ValueType, typename PrefixT, uint8_t LOG_BUFSIZE, uint8_t LOG_NUM_BUFFERS, EphemeralTrieMetadata metadata_t>
#define ATN_DECL AtomicTrieNode<ValueType, PrefixT, LOG_BUFSIZE, LOG_NUM_BUFFERS, metadata_t>

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
	   SPINLOCK_PAUSE();
        //__builtin_ia32_pause();
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
	SPINLOCK_PAUSE();
        //__builtin_ia32_pause();
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
        output[vector_offset] = get_fn(prefix, allocator.get_value(value_pointer));
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
        vector_offset += (ptr_and_sz & 0xFFFF'FFFF);
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
ATN_DECL :: append_metadata(std::vector<uint8_t>& digest_buffer, metadata_t& acc) const
{

    metadata.write_to(digest_buffer);
    acc += metadata;
  /*  digest_buffer.insert(
        digest_buffer.end(),
        metadata.hash.begin(),
        metadata.hash.end()); */
}

ATN_TEMPLATE
void
ATN_DECL :: compute_hash(allocator_t& allocator, std::vector<uint8_t>& digest_buffer)
{
    if (metadata.hash_valid)
    {
        return;
    }

    if (prefix_len == MAX_KEY_LEN_BITS)
    {
        digest_buffer.clear();
        write_node_header(digest_buffer, prefix, prefix_len);
        
        auto const& value = allocator.get_value(value_pointer);
        value.copy_data(digest_buffer);
        metadata.from_value(value);
    }
    else
    {
        TrieBitVector bv;

        for (uint8_t bb = 0; bb < 16; bb++)
        {
            const uint32_t ptr = (children.get(bb) >> 32);

            if (ptr != UINT32_MAX)
            {
                allocator.get_object(ptr).compute_hash(allocator, digest_buffer);
                bv.add(bb);
            }
        }

        digest_buffer.clear();
        write_node_header(digest_buffer, prefix, prefix_len);
        bv.write(digest_buffer);

        for (uint8_t bb = 0; bb < 16; bb++)
        {
            const uint32_t ptr = (children.get(bb) >> 32);

            if (ptr != UINT32_MAX)
            {
                allocator.get_object(ptr).append_metadata(digest_buffer, metadata);
            }
        }
    }

    if (crypto_generichash(metadata.hash.data(),
                           metadata.hash.size(),
                           digest_buffer.data(),
                           digest_buffer.size(),
                           NULL,
                           0)
        != 0) {
        throw std::runtime_error("error from crypto_generichash");
    }
    metadata.hash_valid = true;
}

ATN_TEMPLATE 
typename ATN_DECL::value_t*
ATN_DECL::get_value(const prefix_t& query_prefix, allocator_t const& allocator)
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

ATN_TEMPLATE
const typename ATN_DECL::node_t*
ATN_DECL::get_child(uint8_t bb, allocator_t const& allocator) const
{
    if (prefix_len == MAX_KEY_LEN_BITS) {
        throw std::runtime_error("invalid access");
    }
    uint32_t ptr = children.get(bb) >> 32;
    if (ptr == UINT32_MAX) {
        return nullptr;
    }
    return children.get(ptr);
}

ATN_TEMPLATE
TrieProof<PrefixT> 
ATN_DECL::make_proof(prefix_t const& query, PrefixLenBits const& query_len, allocator_t const& allocator) const
{
    auto match_len = get_prefix_match_len(query);

    uint32_t ptr = UINT32_MAX;
    if (prefix_len != MAX_KEY_LEN_BITS)
    {
        auto bb_self = query.get_branch_bits(prefix_len);
        ptr = (children.get(bb_self) >> 32);
    }

    if ((match_len < prefix_len) || (match_len == prefix_len && prefix_len >= std::min(query_len, MAX_KEY_LEN_BITS)) || (ptr == UINT32_MAX))
    {
        // new base proof
        TrieProof<prefix_t> p;
        p.proved_prefix = query;

        p.proof_stack.emplace_back();
        auto& cur_layer = p.proof_stack.back();

        cur_layer.len = prefix_len;

        if (prefix_len == MAX_KEY_LEN_BITS)
        {
            cur_layer.child_data.emplace_back();
            auto const& value = allocator.get_value(value_pointer);
            value.copy_data(cur_layer.child_data.back());
        } else
        {
            for (uint8_t bb = 0; bb < 16; bb++)
            {
                const uint32_t ptr = (children.get(bb) >> 32);

                if (ptr != UINT32_MAX)
                {
                    cur_layer.child_data.emplace_back();
                    metadata_t temp;
                    allocator.get_object(ptr).append_metadata(cur_layer.child_data.back(), temp);
                    cur_layer.bv.add(bb);
                }
            }
        }
        return p;
    }

    // match_len == prefix_len && query_len > prefix_len && exists active child at the right branch bits

    if (prefix_len == MAX_KEY_LEN_BITS)
    {
        throw std::runtime_error("absurd");
    }

    auto bb_self = query.get_branch_bits(prefix_len);

    auto p = allocator.get_object(ptr).make_proof(query, query_len, allocator);

    p.proof_stack.emplace_back();
    auto& cur_layer = p.proof_stack.back();

    cur_layer.len = prefix_len;

    //make new proof layer

    for (uint8_t bb = 0; bb < 16; bb++)
    {    
        const uint32_t ptr_child = (children.get(bb) >> 32);

        if (ptr_child != UINT32_MAX)
        {
            cur_layer.bv.add(bb);
            if (bb == bb_self) continue;

            // create new layer entry for bb

            cur_layer.child_data.emplace_back();
            metadata_t temp;
            allocator.get_object(ptr_child).append_metadata(cur_layer.child_data.back(), temp);
        }
    }

    return p;
}


#undef ATN_DECL
#undef ATN_TEMPLATE

template<typename ValueType, typename PrefixT, EphemeralTrieMetadata metadata_t, uint8_t LOG_BUFSIZE, uint8_t LOG_NUM_BUFFERS>
bool
AtomicTrie<ValueType, PrefixT, metadata_t, LOG_BUFSIZE, LOG_NUM_BUFFERS>::verify_proof(const TrieProof<PrefixT>& proof, const Hash& root_hash)
{
    std::optional<metadata_t> carried_meta;
    std::optional<PrefixLenBits> carried_len;

    for (auto const& layer : proof.proof_stack)
    {
        if (layer.len == prefix_t::len())
        {
            if (carried_meta.has_value())
            {
                // max len prefix must be first proof layer
                return false;
            }

            std::vector<uint8_t> digest_buffer;
            write_node_header(digest_buffer, proof.proved_prefix, layer.len);

            if (layer.child_data.size() != 1)
            {
                // value has only one child_data
                return false;
            }

            if (!layer.bv.empty())
            {
                return false;
            }

            ValueType v;
            v.from_bytes(layer.child_data.at(0));

            metadata_t m;
            m.from_value(v);

            digest_buffer.insert(
                digest_buffer.end(),
                layer.child_data.at(0) . begin(),
                layer.child_data.at(0) . end());

            if (crypto_generichash(m.hash.data(),
                           m.hash.size(),
                           digest_buffer.data(),
                           digest_buffer.size(),
                           NULL,
                           0)
                != 0) {
                throw std::runtime_error("error from crypto_generichash");
            }
            m.hash_valid = true;

            carried_meta = m;
            carried_len = layer.len;
        } 
        else
        {
            if (carried_meta.has_value())
            {
                if (*carried_len <= layer.len)
                {
                    // proof lengths should monotonically decrease going towards root
                    return false;
                }
            }
            auto bb_self = proof.proved_prefix.get_branch_bits(layer.len);

            metadata_t sum;

            bool used_carried = false;
            TrieBitVector bv = layer.bv;

            size_t idx = 0;

            std::vector<uint8_t> digest_buffer;
            write_node_header(digest_buffer, proof.proved_prefix, layer.len);

            bv.write(digest_buffer);

            while(!bv.empty())
            {
                auto bb = bv.pop();

                if (bb == bb_self)
                {
                    if (!carried_meta.has_value())
                    {
                        // this wouldn't make sense, have to start at a value
                        return false;
                    }
                    sum += *carried_meta;
                    carried_meta->write_to(digest_buffer);
                    used_carried = true;
                    continue;
                }

                metadata_t new_meta;

                if (layer.child_data.size() <= idx) {
                    // missing child_data for some bb
                    return false;
                }
                if (!new_meta.try_parse(layer.child_data.at(idx).data(), layer.child_data.at(idx).size()))
                {
                    return false;
                }
                idx++;

                sum += new_meta;
                new_meta.write_to(digest_buffer);
            }
            if (carried_meta.has_value() && !used_carried)
            {
                // didn't consume the metadata carried from prev proof layer
                return false;
            }

            if (crypto_generichash(sum.hash.data(),
                        sum.hash.size(),
                        digest_buffer.data(),
                        digest_buffer.size(),
                        NULL,
                        0)
                != 0) {
                throw std::runtime_error("error from crypto_generichash");
            }
            sum.hash_valid = true;
            carried_meta = sum;
            carried_len = layer.len;
        }
    }

    if (!carried_meta.has_value())
    {
        // proof was empty
        return false;
    }
    return carried_meta->hash == root_hash;
}

} // namespace trie

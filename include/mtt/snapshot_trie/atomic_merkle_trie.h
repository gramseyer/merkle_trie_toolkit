#pragma once

#include "mtt/common/prefix.h"
#include "mtt/common/types.h"

#include "mtt/common/bitvector.h"
#include "mtt/common/debug_macros.h"
#include "mtt/common/insert_fn.h"
#include "mtt/common/utils.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <utility>
#include <type_traits>

#include <utils/threadlocal_cache.h>

#include "mtt/snapshot_trie/concepts.h"

#include <sodium.h>

#include "mtt/snapshot_trie/optional_value.h"

namespace trie {

// avoid ABA problem
template<typename node_t, uint32_t TLCACHE_SIZE>
class AtomicMerkleTrieGC
{
    struct LocalGC
    {
        std::vector<node_t*> nodes;
    };

    utils::ThreadlocalCache<LocalGC, TLCACHE_SIZE> cache;

  public:
    void free(node_t* ptr) { cache.get().nodes.push_back(ptr); }

    void gc()
    {
        auto& locals = cache.get_objects();

        for (auto& l : locals) {
            if (l) {
                auto& ptrs = l->nodes;
                for (auto* ptr : ptrs) {
                    delete ptr;
                }
            }
        }

        cache.clear();
    }

    ~AtomicMerkleTrieGC() { gc(); }
};

// credit to https://stackoverflow.com/a/66275373
template<typename T>
concept AMT_gc_t = requires(T** a)
{
    []<typename node_t, uint32_t x>(AtomicMerkleTrieGC<node_t, x>**) {}(a);
};

template<typename prefix_t, typename optional_value_t, SnapshotTrieMetadata metadata_t>
class AtomicMerkleTrieNode
{
    using node_t = AtomicMerkleTrieNode<prefix_t, optional_value_t, metadata_t>;

    static_assert(std::atomic<node_t*>::is_always_lock_free,
                  "ptr should be lockfree");

    union
    {
        std::array<std::atomic<node_t*>, 16> children;
        optional_value_t value; //std::optional<value_t> value;
    };

    const prefix_t prefix;
    const PrefixLenBits prefix_len;

    std::atomic<bool> hash_valid;
    bool children_owned = false;
   // bool value_valid = false;

    metadata_t metadata;
    // int32_t size;
    Hash hash;

    constexpr static uint16_t KEY_LEN_BYTES = prefix_t::size_bytes();

    constexpr static PrefixLenBits MAX_KEY_LEN_BITS
        = PrefixLenBits{ KEY_LEN_BYTES * 8 };

  public:
    struct value_nullopt_t {};
    struct value_opt_t {};

    using value_t = optional_value_t::value_type;

    AtomicMerkleTrieNode(prefix_t const& prefix, value_nullopt_t const&)
        : value(std::nullopt)
        , prefix(prefix)
        , prefix_len(MAX_KEY_LEN_BITS)
        , hash_valid(false)
        , children_owned(false)
        , metadata()
        , hash()
    {
    }

    template<typename... value_args>
    // value node
    AtomicMerkleTrieNode(prefix_t const& prefix, value_opt_t const&, value_args const& ...args)
        : value(std::in_place_t{}, args...)
        , prefix(prefix)
        , prefix_len(MAX_KEY_LEN_BITS)
        , hash_valid(false)
        , children_owned(false)
        , metadata()
        , hash()
    // size(0)
    //, hash()
    {
    }

    struct map_node_args_t {
        prefix_t const& prefix;
        PrefixLenBits len;
    };

    // map node
    AtomicMerkleTrieNode(map_node_args_t const& args)
        : children()
        , prefix([args](const prefix_t& p) -> prefix_t {
            prefix_t out = p;
            out.truncate(args.len);
            return out;
        }(args.prefix))
        , prefix_len(args.len)
        , hash_valid(false)
        , children_owned(false)
        , metadata()
        , hash()
    //, size(0)
    //, hash()
    {
        if (prefix_len == MAX_KEY_LEN_BITS) {
            throw std::runtime_error("wrong ctor used");
        }
    }

    void set_unique_child(uint8_t bb, node_t* ptr)
    {
        // possible memory leak -- won't be freed unless commit_ownership() also
        // called
        children[bb] = ptr;
    }

    // root node
    AtomicMerkleTrieNode()
        : children()
        , prefix()
        , prefix_len(0)
        , hash_valid(false)
        , children_owned(true)
        , metadata()
        , hash()
    //, size(0)
    //, hash()
    {}

    void validate_value() {};// value_valid = true; }

/*
    template<typename InsertFn, typename InsertedValueType>
    static value_t create_new_value(
        const prefix_t& key,
        typename std::enable_if<
            !std::is_same<value_t, InsertedValueType>::value,
            InsertedValueType&&>::type v)
    {
        auto val = InsertFn::new_value(key);
        InsertFn::value_insert(val, std::move(v));
        return val;
    }

    template<typename InsertFn, typename InsertedValueType>
    static value_t create_new_value(
        const prefix_t& key,
        typename std::enable_if<std::is_same<value_t, InsertedValueType>::value,
                                InsertedValueType&&>::type v)
    {
        return v;
    } */

    void commit_ownership() { children_owned = true; }

    static void trie_assert(bool expr, const char* msg)
    {
        if (!expr) {
            std::printf("error: %s\n", msg);
            std::fflush(stdout);
            throw std::runtime_error(msg);
        }
    }

    ~AtomicMerkleTrieNode()
    {
        using dtor_t = optional_value_t;
        if (is_leaf()) {
            value.~dtor_t();
        } else {
            if (children_owned) {
                for (uint8_t bb = 0; bb < 16; bb++) {
                    node_t* ptr = children[bb].load(std::memory_order_relaxed);
                    if (ptr != nullptr) {
                        delete ptr;
                    }
                }
            }
        }
    }

    bool is_leaf() const { return prefix_len == MAX_KEY_LEN_BITS; }

    template<auto value_merge_fn, typename... value_args>
    void insert(prefix_t const& new_prefix,
                AMT_gc_t auto& gc,
                value_args const& ...args);

    const metadata_t& compute_hash_and_normalize(
        AMT_gc_t auto& gc,
        std::vector<uint8_t>& digest_bytes);

    uint8_t get_num_children() const;

    node_t* extract_singlechild();

    void invalidate_hash()
    {
        hash_valid.store(false, std::memory_order_release);
    }

    PrefixLenBits get_prefix_match_len(const prefix_t& other_key,
                                       const PrefixLenBits other_len
                                       = MAX_KEY_LEN_BITS) const
    {
        return prefix.get_prefix_match_len(prefix_len, other_key, other_len);
    }

    prefix_t const& get_prefix() const { return prefix; }

    PrefixLenBits get_prefix_len() const { return prefix_len; }

    node_t* get_child(uint8_t bb)
    {
        return children[bb].load(std::memory_order_acquire);
    }

    const node_t* get_child(uint8_t bb) const
    {
        return children[bb].load(std::memory_order_acquire);
    }

    void erase_child(uint8_t bb, AMT_gc_t auto& gc)
    {
        gc.free(children[bb].exchange(nullptr, std::memory_order_acq_rel));
    }

    bool try_add_child(uint8_t bb, node_t*& expect, node_t* new_ptr)
    {
        return children[bb].compare_exchange_strong(
            expect, new_ptr, std::memory_order_acq_rel);
    }

    void invalidate_hash_to_node(const node_t* target);
    void invalidate_hash_to_key(const prefix_t& query);

    node_t* get_or_make_subnode_ref(const prefix_t& query_prefix,
                                    const PrefixLenBits query_len,
                                    AMT_gc_t auto& gc);

    void append_hash_to_vec(std::vector<uint8_t>& bytes) const
    {
        trie_assert(hash_valid.load(std::memory_order_acquire),
                    "invalid hash appended");

        metadata.write_to(bytes);

         bytes.insert(bytes.end(),
        	hash.begin(),
        	hash.end());
    }

    Hash get_hash() const
    {
        trie_assert(hash_valid.load(std::memory_order_acquire),
                    "invalid hash appended");

        return hash;
    }

    void delete_value(const prefix_t& delete_prefix, AMT_gc_t auto& gc);

    const value_t* get_value(const prefix_t& query_prefix) const;

    value_t* get_value(prefix_t const& query)
    {
        return const_cast<value_t*>(
            const_cast<const node_t*>(this)
                ->get_value(query));
    }

    void log(std::string pref) const
    {
        std::printf("%s %p %s\n",
                    pref.c_str(),
                    this,
                    prefix.to_string(prefix_len).c_str());
        if (is_leaf()) {
            return;
        }

        for (uint8_t bb = 0; bb < 16; bb++) {
            auto const* ptr = get_child(bb);
            if (ptr != nullptr) {
                std::printf("  %s child %p %u\n", pref.c_str(), ptr, bb);
                ptr->log(std::string("  ") + pref);
            }
        }
    }
};

template<typename prefix_t,
         typename value_t,
         uint32_t TLCACHE_SIZE,
         SnapshotTrieMetadata metadata_t = SnapshotTrieMetadataBase,
         auto has_value_f = detail::default_value_selector<value_t>>
class AtomicMerkleTrie
{
    using node_t = AtomicMerkleTrieNode<prefix_t, OptionalValue<value_t, has_value_f>, metadata_t>;
    using gc_t = AtomicMerkleTrieGC<node_t, TLCACHE_SIZE>;

    node_t* root;

    gc_t gc;

  public:
    node_t* get_subnode_ref_and_invalidate_hash(const prefix_t& query_prefix,
                                                const PrefixLenBits query_len)
    {
        auto* out = root->template get_or_make_subnode_ref(
            query_prefix, query_len, gc);
        root->invalidate_hash_to_node(out);
        return out;
    }

    node_t* get_root_and_invalidate_hash()
    {
        root->invalidate_hash_to_node(root);
        return root;
    }

    gc_t& get_gc() { return gc; }

    AtomicMerkleTrie()
        : root(new node_t())
        , gc()
    {}

    void clear()
    {
        gc.free(root);
        root = new node_t();
        gc.gc();
    }

    void do_gc() { gc.gc(); }

    ~AtomicMerkleTrie()
    {
        gc.free(root);
        root = nullptr;
        gc.gc();
    }

    Hash hash_and_normalize()
    {
        std::vector<uint8_t> digest_bytes;
        root->compute_hash_and_normalize(gc, digest_bytes);
        return root->get_hash();
    }

    const value_t* get_value(prefix_t const& query) const
    {
        return root->get_value(query);
    }

    value_t* get_value(prefix_t const& query)
    {
        using const_self_t = const std::remove_pointer<decltype(this)>::type;
        return const_cast<value_t*>(
            const_cast<const_self_t*>(this)
                ->get_value(query));
    }
};

#define AMTN_TEMPLATE                                                          \
    template<typename prefix_t,                                                \
             typename optional_value_t,                                        \
             SnapshotTrieMetadata metadata_t>
#define AMTN_DECL AtomicMerkleTrieNode<prefix_t, optional_value_t, metadata_t>

AMTN_TEMPLATE
template<auto value_merge_fn, typename... value_args>
void
AMTN_DECL::insert(prefix_t const& new_prefix,
                  AMT_gc_t auto& gc,
                  value_args const& ...args)
{
    invalidate_hash();

    // std::printf("insert of %p to prefix %s cur prefix %s\n", &new_value,
    // new_prefix.to_string(MAX_KEY_LEN_BITS).c_str(),
    //	prefix.to_string(prefix_len).c_str());

    auto prefix_match_len = get_prefix_match_len(new_prefix);
    trie_assert(prefix_match_len == prefix_len, "invalid insertion");

    if (is_leaf()) {
        if (value.has_opt_value())
        {
            value_merge_fn(*value, args...);
        }
        else {
            value.emplace(args...);
        }
        validate_value();
        return;
    }

    const uint8_t bb = new_prefix.get_branch_bits(prefix_len);

    node_t* child = get_child(bb);

    while (true) {

        if (child == nullptr) {
            // insert new node
            node_t* new_node
                = new node_t(new_prefix, value_opt_t{},
                            args...);
            new_node->validate_value();

            if (try_add_child(bb, child, new_node)) {
                // inserted new child
                return;
            }
            // only reference to new_node is here, so we can delete freely.
            delete new_node;
        } else {

            PrefixLenBits join_len = child->get_prefix_match_len(new_prefix);

            if (join_len >= child->get_prefix_len()) {
                child -> template insert<value_merge_fn, value_args...>(
                    new_prefix, gc, args...);
               // child->template insert<InsertFn, InsertedValue>(
               //     new_prefix, std::move(new_value), gc);
                return;
            }

            node_t* new_node = new node_t(map_node_args_t{new_prefix, join_len});
            new_node->set_unique_child(
                child->get_prefix().get_branch_bits(join_len), child);

            if (try_add_child(bb, child, new_node)) {
                new_node->commit_ownership();
                new_node -> template insert<value_merge_fn, value_args...>(
                    new_prefix, gc, args...);
                //new_node->template insert<InsertFn, InsertedValue>(
                //    new_prefix, std::move(new_value), gc);
                return;
            }
            delete new_node;
            // only reference to new_node is local
        }
        __builtin_ia32_pause();
    }
}

AMTN_TEMPLATE
void
AMTN_DECL ::invalidate_hash_to_node(const node_t* target)
{
    invalidate_hash();
    if (target == this) {
        return;
    }

    auto match_len
        = get_prefix_match_len(target->get_prefix(), target->get_prefix_len());

    trie_assert(match_len == prefix_len, "invalid invalidate");

    const uint8_t bb = target->get_prefix().get_branch_bits(prefix_len);

    node_t* child = get_child(bb);
    trie_assert(child != nullptr,
                "found null child in invalidate_hash_to_node");

    child->invalidate_hash_to_node(target);
}

AMTN_TEMPLATE
void
AMTN_DECL ::invalidate_hash_to_key(const prefix_t& query)
{
    invalidate_hash();

    if (is_leaf()) {
        trie_assert(prefix == query, "mismatch on invalidate_hash_to_key");
        return;
    }

    auto bb = query.get_branch_bits(prefix_len);
    node_t* child = get_child(bb);
    trie_assert(child != nullptr, "invalid child found");

    child->invalidate_hash_to_key(query);
}

AMTN_TEMPLATE
uint8_t
AMTN_DECL ::get_num_children() const
{
    if (is_leaf()) {
        if (value.has_logical_value()) {
            return UINT8_MAX;
        }
        return 0;
    }
    uint8_t count = 0;

    for (uint8_t bb = 0; bb < 16; bb++) {
        if (get_child(bb) != nullptr) {
            count++;
        }
    }
    return count;
}

AMTN_TEMPLATE
AMTN_DECL*
AMTN_DECL ::extract_singlechild()
{
    trie_assert(!is_leaf(), "invalid extract");

    for (uint8_t bb = 0; bb < 16; bb++) {
        auto* ptr = get_child(bb);
        if (ptr == nullptr)
            continue;

        return children[bb].exchange(nullptr, std::memory_order_acq_rel);
    }

    trie_assert(false, "there was no child");
    throw std::runtime_error("invalid");
}

AMTN_TEMPLATE
AMTN_DECL*
AMTN_DECL ::get_or_make_subnode_ref(const prefix_t& query_prefix,
                                    const PrefixLenBits query_len,
                                    AMT_gc_t auto& gc)
{
    //	std::printf("get_or_make_subnode_ref: prefix %s query %s\n",
    //		prefix.to_string(prefix_len).c_str(),
    //		query_prefix.to_string(query_len).c_str());

    auto matchlen = get_prefix_match_len(query_prefix, query_len);

    trie_assert(matchlen >= prefix_len, "invalid get_or_make_subnode_ref");

    if (query_len == prefix_len) {
        return this;
    }

    const uint8_t bb = query_prefix.get_branch_bits(prefix_len);

    node_t* ptr = get_child(bb);

    while (true) {
        if (ptr == nullptr) {
            node_t* new_child = nullptr;
            if (query_len == MAX_KEY_LEN_BITS) {
                new_child = new node_t(query_prefix, value_nullopt_t{});
                                      // InsertFn::new_value(query_prefix));
            } else {
                new_child = new node_t(map_node_args_t{query_prefix, query_len});
            }
            if (try_add_child(bb, ptr, new_child)) {
                new_child->commit_ownership();
                return new_child;
            }
            gc.free(new_child);
        } else {
            // std::printf("child exists: %s\n", ptr ->
            // get_prefix().to_string(ptr -> get_prefix_len()).c_str());
            auto child_match_len
                = ptr->get_prefix_match_len(query_prefix, query_len);
            // std::printf("match len: %u\n", child_match_len.len);
            if (child_match_len == ptr->get_prefix_len()) {
                return ptr->get_or_make_subnode_ref(
                    query_prefix, query_len, gc);
            }

            node_t* intermediate = new node_t(map_node_args_t{query_prefix, child_match_len});
            uint8_t child_bb
                = ptr->get_prefix().get_branch_bits(child_match_len);
            intermediate->set_unique_child(child_bb, ptr);

            if (try_add_child(bb, ptr, intermediate)) {
                intermediate->commit_ownership();

                return intermediate->get_or_make_subnode_ref(
                    query_prefix, query_len, gc);
            }
            gc.free(intermediate);
        }
        __builtin_ia32_pause();
    }
}

AMTN_TEMPLATE
const metadata_t&
AMTN_DECL ::compute_hash_and_normalize(AMT_gc_t auto& gc,
                                       std::vector<uint8_t>& digest_bytes)
{
    if (hash_valid) {
        return metadata;
    }

    if (is_leaf()) {
        if (!value.has_logical_value()) {
            metadata.size = 0;
            hash_valid = true;
            return metadata;
        }

        digest_bytes.clear();

        write_node_header(digest_bytes, prefix, prefix_len);
        value->copy_data(digest_bytes);

        // sets size = 1
        metadata.from_value(*value);

        if (crypto_generichash(hash.data(),
                               hash.size(),
                               digest_bytes.data(),
                               digest_bytes.size(),
                               NULL,
                               0)
            != 0) {
            throw std::runtime_error("error from crypto_generichash");
        }
        // metadata.size = 1;
        hash_valid = true;
        //	size = 1;
        //	size.exchange(1, std::memory_order_acq_rel);
        return metadata;
    }

    metadata = metadata_t();

    //metadata_t new_metadata;
    // int32_t new_size = 0;

    int32_t num_children = 0;
    TrieBitVector bv;

    for (uint8_t bb = 0; bb < 16; bb++) {
        node_t* child = get_child(bb);
        if (child == nullptr)
            continue;

       /* auto child_m = child -> compute_hash_and_normalize(gc, digest_bytes);
        if (child_m.size == 0)
        {
            erase_child(bb, gc);
            continue;
        }

        metadata += child_m; */

        metadata += child->compute_hash_and_normalize(gc, digest_bytes);

        uint8_t child_count = child->get_num_children();
        // if child is leaf and has_logical_value() == false,
        // then child_count is 0 and the child is deleted.
        if (child_count == 0) {
            erase_child(bb, gc);
        } else if (child_count == 1) {
            node_t* new_child = child->extract_singlechild();

            gc.free(child);

            trie_assert(try_add_child(bb, child, new_child),
                        "concurrency fail");

            bv.add(bb);
            num_children++;
        } else {
            bv.add(bb);
            num_children++;
        }
    }
    //metadata = new_metadata;
    // metadata.size = new_size;

    // size.store(new_size, std::memory_order_release);
    if (num_children <= 1 && prefix_len.len != 0) {
        // don't bother hashing, except special casing the root node
        return metadata;
    }

    digest_bytes.clear();

    write_node_header(digest_bytes, prefix, prefix_len);
    bv.write(digest_bytes);

    for (uint8_t bb = 0; bb < 16; bb++) {
        auto* ptr = get_child(bb);
        if (ptr == nullptr)
            continue;

        ptr->append_hash_to_vec(digest_bytes);
    }

    if (crypto_generichash(hash.data(),
                           hash.size(),
                           digest_bytes.data(),
                           digest_bytes.size(),
                           NULL,
                           0)
        != 0) {
        throw std::runtime_error("error from crypto_generichash");
    }

    hash_valid = true;

    return metadata;
}

AMTN_TEMPLATE
void
AMTN_DECL ::delete_value(const prefix_t& delete_prefix, AMT_gc_t auto& gc)
{
    invalidate_hash();

    if (is_leaf()) {
        trie_assert(delete_prefix == prefix, "mismatch");
        value.reset();
       // value_valid = false;
        return;
    }

    auto bb = delete_prefix.get_branch_bits(prefix_len);

    auto* ptr = get_child(bb);
    trie_assert(ptr != nullptr, "must exist");

    if (ptr->is_leaf() && ptr->get_prefix() == delete_prefix) {
        auto* prev = children[bb].exchange(nullptr, std::memory_order_acq_rel);
        if (prev) {
            gc.free(prev);
        }
        return;
    }

    ptr->delete_value(delete_prefix, gc);
}

AMTN_TEMPLATE
const 
AMTN_DECL::value_t*
AMTN_DECL::get_value(const prefix_t& query_prefix) const
{
    if (is_leaf()) {
        if (query_prefix == prefix && value.has_opt_value()) {
            return &(*value);
        }
        return nullptr;
    }

    auto match_len = get_prefix_match_len(query_prefix);

    if (match_len < prefix_len) {
        return nullptr;
    }

    const auto bb = query_prefix.get_branch_bits(prefix_len);

    auto* ptr = get_child(bb);
    if (ptr == nullptr) {
        return nullptr;
    }
    return ptr->get_value(query_prefix);
}


#undef AMTN_DECL
#undef AMTN_TEMPLATE

} // namespace trie

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

#include <utils/threadlocal_cache.h>

#include "mtt/common/deferred_gc.h"

#include "mtt/snapshot_trie/concepts.h"

#include "mtt/memcached_snapshot_trie/durable_interface.h"

#include <sodium.h>

namespace trie {

template<typename prefix_t, typename value_t, SnapshotTrieMetadata metadata_t>
class MemcacheTrieNode
{
    using node_t = MemcacheTrieNode<prefix_t, value_t, metadata_t>;

    static_assert(std::atomic<node_t*>::is_always_lock_free,
                  "ptr should be lockfree");

    using variant_value_t = std::optional<value_t>;
    using variant_children_t = std::array<std::atomic<node_t*>, 16>;
    using variant_storage_ptr_t = TimestampPointerPair;

    std::variant<variant_value_t, variant_children_t, variant_storage_ptr_t>
        body;

    const prefix_t prefix;
    const PrefixLenBits prefix_len;

    std::atomic<bool> metadata_valid;
    std::atomic<uint32_t> last_updated_timestamp;

    bool children_owned = false;
    metadata_t metadata;

    constexpr static uint16_t KEY_LEN_BYTES = prefix_t::size_bytes();
    static_assert(KEY_LEN_BYTES <= UINT8_MAX,
                  "too long (need to rework templates");

    constexpr static PrefixLenBits MAX_KEY_LEN_BITS
        = PrefixLenBits{ KEY_LEN_BYTES * 8 };

    using durable_value_t = DurableValue<KEY_LEN_BYTES>;

  public:
    struct value_nullopt_t
    {};

    MemcacheTrieNode(prefix_t const& prefix,
                     uint32_t ts,
                     value_nullopt_t const&)
        : body(std::in_place_type<variant_value_t>, std::nullopt)
        , prefix(prefix)
        , prefix_len(MAX_KEY_LEN_BITS)
        , metadata_valid(false)
        , last_updated_timestamp(ts)
        , children_owned(false)
        , metadata()
    {}

    template<typename... value_args>
    // value node
    MemcacheTrieNode(prefix_t const& prefix,
                     uint32_t ts,
                     value_args const&... args)
        : body(std::in_place_type<variant_value_t>, std::in_place_t{}, args...)
        , prefix(prefix)
        , prefix_len(MAX_KEY_LEN_BITS)
        , metadata_valid(false)
        , last_updated_timestamp(ts)
        , children_owned(false)
        , metadata()
    {}

    struct map_node_args_t
    {
        prefix_t const& prefix;
        PrefixLenBits len;
    };

    // map node
    MemcacheTrieNode(map_node_args_t const& args, uint32_t ts)
        : body(std::in_place_type<variant_children_t>)
        , prefix([args](const prefix_t& p) -> prefix_t {
            prefix_t out = p;
            out.truncate(args.len);
            return out;
        }(args.prefix))
        , prefix_len(args.len)
        , metadata_valid(false)
        , last_updated_timestamp(ts)
        , children_owned(false)
        , metadata()
    {
        trie_assert(prefix_len != MAX_KEY_LEN_BITS, "wrong ctor used");
    }

    struct ptr_node_args_t
    {
        TimestampPointerPair const& tsp;
        prefix_t const& prefix;
        PrefixLenBits prefix_len;
        metadata_t const& metadata;
    };

    // ptr node
    MemcacheTrieNode(ptr_node_args_t args)
        : body(args.tsp)
        , prefix(args.prefix)
        , prefix_len(args.prefix_len)
        , metadata_valid(true)
        , last_updated_timestamp(args.tsp.timestamp)
        , children_owned(false)
        , metadata(args.metadata)
    {}

    void set_unique_child(uint8_t bb, node_t* ptr)
    {
        // possible memory leak -- won't be freed unless commit_ownership() also
        // called
        std::get<variant_children_t>(body)[bb].store(ptr,
                                                     std::memory_order_relaxed);
    }

    // root node
    MemcacheTrieNode(uint32_t ts)
        : body(std::in_place_type<variant_children_t>)
        , prefix()
        , prefix_len(0)
        , metadata_valid(false)
        , last_updated_timestamp(ts)
        , children_owned(true)
        , metadata()
    {}

    void commit_ownership() { children_owned = true; }

    static void trie_assert(bool expr, const char* msg)
    {
        if (!expr) {
            std::printf("error: %s\n", msg);
            std::fflush(stdout);
            throw std::runtime_error(msg);
        }
    }

    ~MemcacheTrieNode()
    {
        if (children_owned
            && std::holds_alternative<variant_children_t>(body)) {
            for (uint8_t bb = 0; bb < 16; bb++) {
                node_t* ptr = std::get<variant_children_t>(body)[bb].load(
                    std::memory_order_relaxed);
                if (ptr != nullptr) {
                    delete ptr;
                }
            }
        }
    }

    bool is_leaf() const { return prefix_len == MAX_KEY_LEN_BITS; }
    bool is_evicted() const
    {
        return std::holds_alternative<variant_storage_ptr_t>(body);
    }

    TimestampPointerPair get_ts_ptr() const
    {
        if (is_evicted()) {
            return std::get<variant_storage_ptr_t>(body);
        } else {
            return TimestampPointerPair(*this);
        }
    }

    template<auto value_merge_fn, typename... value_args>
    void insert(prefix_t const& new_prefix,
                deferred_gc_t auto& gc,
                const uint32_t current_timestamp,
                DurableInterface auto& storage,
                value_args const&... args);

    const metadata_t& compute_hash_and_normalize(
        deferred_gc_t auto& gc,
        const uint32_t timestamp_evict_threshold,
        std::vector<uint8_t>& digest_bytes,
        DurableInterface auto& storage);

    uint8_t get_num_children() const;

    node_t* extract_singlechild();

    node_t* evict_self() const;

    void invalidate_hash(uint32_t current_timestamp)
    {
        metadata_valid.store(false, std::memory_order_release);
        last_updated_timestamp.store(current_timestamp,
                                     std::memory_order_release);
    }

    uint32_t get_last_modified_ts() const
    {
        return last_updated_timestamp.load(std::memory_order_acquire);
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
        return std::get<variant_children_t>(body)[bb].load(
            std::memory_order_acquire);
    }

    const node_t* get_child(uint8_t bb) const
    {
        return std::get<variant_children_t>(body)[bb].load(
            std::memory_order_acquire);
    }

    void erase_child(uint8_t bb, deferred_gc_t auto& gc)
    {
        gc.free(std::get<variant_children_t>(body)[bb].exchange(
            nullptr, std::memory_order_acq_rel));
    }

    bool try_add_child(uint8_t bb, node_t*& expect, node_t* new_ptr)
    {
        return std::get<variant_children_t>(body)[bb].compare_exchange_strong(
            expect, new_ptr, std::memory_order_acq_rel);
    }

    // void invalidate_hash_to_node(const node_t* target, uint32_t
    // current_timestamp);
    void invalidate_hash_to_key(const prefix_t& query,
                                uint32_t current_timestamp);

    // invalidates the hash up to that node as well
    node_t* get_or_make_subnode_ref(const prefix_t& query_prefix,
                                    const PrefixLenBits query_len,
                                    uint32_t current_timestamp);

    const metadata_t& get_metadata() const
    {
        trie_assert(metadata_valid.load(std::memory_order_acquire),
                    "invalid metadata acquired");

        return metadata;
    }

    void delete_value(const prefix_t& delete_prefix,
                      uint32_t ts,
                      deferred_gc_t auto& gc,
                      DurableInterface auto& storage);

    value_t* get_value(const prefix_t& query_prefix,
                       DurableInterface auto& storage);

    void log_self_active(DurableInterface auto& interface) const;
    void log_self_deleted(DurableInterface auto& interface) const;

    void log(std::string pref) const
    {
        std::printf("%s %p %s\n",
                    pref.c_str(),
                    this,
                    prefix.to_string(prefix_len).c_str());
        if (is_leaf()) {
            return;
        }

        if (is_evicted()) {
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
         DurableInterface storage_t,
         SnapshotTrieMetadata metadata_t = SnapshotTrieMetadataBase>
class MemcacheTrie
{
    using node_t = MemcacheTrieNode<prefix_t, value_t, metadata_t>;
    using gc_t = DeferredGC<node_t, TLCACHE_SIZE>;

    node_t* root;

    gc_t gc;

    storage_t storage;

  public:
    node_t* get_subnode_ref_and_invalidate_hash(const prefix_t& query_prefix,
                                                const PrefixLenBits query_len,
                                                uint32_t current_timestamp)
    {
        return root->template get_or_make_subnode_ref(
            query_prefix, query_len, current_timestamp);
    }

    gc_t& get_gc() { return gc; }

    storage_t& get_storage() { return storage; }

    MemcacheTrie(uint32_t current_ts)
        : root(new node_t(current_ts))
        , gc()
    {}

    void do_gc() { gc.gc(); }

    ~MemcacheTrie()
    {
        gc.free(root);
        root = nullptr;
        gc.gc();
    }

    Hash hash_and_normalize(uint32_t eviction_threshold)
    {
        std::vector<uint8_t> digest_bytes;
        root->compute_hash_and_normalize(
            gc, eviction_threshold, digest_bytes, storage);
        return root->get_metadata().hash;
    }

    value_t* get_value(prefix_t const& query)
    {
        return root->get_value(query, storage);
    }
};

#define MCTN_TEMPLATE                                                          \
    template<typename prefix_t,                                                \
             typename value_t,                                                 \
             SnapshotTrieMetadata metadata_t>
#define MCTN_DECL MemcacheTrieNode<prefix_t, value_t, metadata_t>

MCTN_TEMPLATE
template<auto value_merge_fn, typename... value_args>
void
MCTN_DECL::insert(prefix_t const& new_prefix,
                  deferred_gc_t auto& gc,
                  uint32_t current_timestamp,
                  DurableInterface auto& storage,
                  value_args const&... args)
{
    invalidate_hash(current_timestamp);

    auto prefix_match_len = get_prefix_match_len(new_prefix);

    trie_assert(prefix_match_len == prefix_len, "invalid insertion");
    trie_assert(!is_evicted(), "cannot insert to evicted node");

    if (is_leaf()) {
        auto& value = std::get<variant_value_t>(body);
        if (value.has_value()) {
            value_merge_fn(*value, args...);
        } else {
            value.emplace(args...);
        }
        return;
    }

    const uint8_t bb = new_prefix.get_branch_bits(prefix_len);

    node_t* child = get_child(bb);

    while (true) {

        if (child == nullptr) {
            // insert new node
            node_t* new_node
                = new node_t(new_prefix, current_timestamp, args...);

            if (try_add_child(bb, child, new_node)) {
                // inserted new child
                return;
            }
            // only reference to new_node is here, so we can delete freely.
            delete new_node;
        } else {

            PrefixLenBits join_len = child->get_prefix_match_len(new_prefix);

            if (join_len >= child->get_prefix_len()) {

                if (child->is_evicted()) {
                    node_t* reloaded = nullptr;
                    throw std::runtime_error("unimplemented");

                    if (try_add_child(bb, child, reloaded)) {
                        reloaded
                            ->template insert<value_merge_fn, value_args...>(
                                new_prefix,
                                gc,
                                current_timestamp,
                                storage,
                                args...);
                        return;
                    }
                    // only reference to reloaded is local
                    delete reloaded;
                } else {
                    child->template insert<value_merge_fn, value_args...>(
                        new_prefix, gc, current_timestamp, storage, args...);
                    return;
                }
            } else {
                node_t* new_node = new node_t(
                    map_node_args_t{ new_prefix, join_len }, current_timestamp);
                new_node->set_unique_child(
                    child->get_prefix().get_branch_bits(join_len), child);

                if (try_add_child(bb, child, new_node)) {
                    new_node->commit_ownership();
                    // new_node guaranteed to not be evicted
                    new_node->template insert<value_merge_fn, value_args...>(
                        new_prefix, gc, current_timestamp, storage, args...);
                    return;
                }
                delete new_node;
                // only reference to new_node is local
            }
        }
        __builtin_ia32_pause();
    }
}

MCTN_TEMPLATE
void
MCTN_DECL ::invalidate_hash_to_key(const prefix_t& query,
                                   uint32_t current_timestamp)
{
    invalidate_hash(current_timestamp);

    if (is_leaf()) {
        trie_assert(prefix == query, "mismatch on invalidate_hash_to_key");
        return;
    }

    auto bb = query.get_branch_bits(prefix_len);
    node_t* child = get_child(bb);
    trie_assert(child != nullptr, "invalid child found");

    child->invalidate_hash_to_key(query, current_timestamp);
}

MCTN_TEMPLATE
uint8_t
MCTN_DECL ::get_num_children() const
{
    if (is_leaf()) {
        auto const& value = std::get<variant_value_t>(body);
        if (value.has_value()) {
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

MCTN_TEMPLATE
MCTN_DECL*
MCTN_DECL ::extract_singlechild()
{
    trie_assert(!is_leaf(), "invalid extract");

    for (uint8_t bb = 0; bb < 16; bb++) {
        auto* ptr = get_child(bb);
        if (ptr == nullptr)
            continue;

        return std::get<variant_children_t>(body)[bb].exchange(
            nullptr, std::memory_order_acq_rel);
    }

    trie_assert(false, "there was no child");
    throw std::runtime_error("invalid");
}

MCTN_TEMPLATE
MCTN_DECL*
MCTN_DECL ::get_or_make_subnode_ref(const prefix_t& query_prefix,
                                    const PrefixLenBits query_len,
                                    uint32_t current_timestamp)
{
    auto matchlen = get_prefix_match_len(query_prefix, query_len);

    trie_assert(matchlen >= prefix_len, "invalid get_or_make_subnode_ref");
    trie_assert(!is_evicted(),
                "should not be getting subnode refs in parts of the trie that "
                "are currently evicted");

    invalidate_hash(current_timestamp);

    if (query_len == prefix_len) {
        return this;
    }

    const uint8_t bb = query_prefix.get_branch_bits(prefix_len);

    node_t* ptr = get_child(bb);

    while (true) {
        if (ptr == nullptr) {
            node_t* new_child = nullptr;
            if (query_len == MAX_KEY_LEN_BITS) {
                new_child = new node_t(
                    query_prefix, current_timestamp, value_nullopt_t{});
            } else {
                new_child
                    = new node_t(map_node_args_t{ query_prefix, query_len },
                                 current_timestamp);
            }
            if (try_add_child(bb, ptr, new_child)) {
                new_child->commit_ownership();
                return new_child;
            }
            // only reference to new_child is local
            delete new_child;
        } else {
            auto child_match_len
                = ptr->get_prefix_match_len(query_prefix, query_len);
            if (child_match_len == ptr->get_prefix_len()) {
                return ptr->get_or_make_subnode_ref(
                    query_prefix, query_len, current_timestamp);
            }

            node_t* intermediate
                = new node_t(map_node_args_t{ query_prefix, child_match_len },
                             current_timestamp);
            uint8_t child_bb
                = ptr->get_prefix().get_branch_bits(child_match_len);
            intermediate->set_unique_child(child_bb, ptr);

            if (try_add_child(bb, ptr, intermediate)) {
                intermediate->commit_ownership();

                return intermediate->get_or_make_subnode_ref(
                    query_prefix, query_len, current_timestamp);
            }
            // only reference to intermediate is local
            delete intermediate;
        }
        __builtin_ia32_pause();
    }
}

MCTN_TEMPLATE
const metadata_t&
MCTN_DECL ::compute_hash_and_normalize(deferred_gc_t auto& gc,
                                       const uint32_t timestamp_evict_threshold,
                                       std::vector<uint8_t>& digest_bytes,
                                       DurableInterface auto& storage)
{
    if (metadata_valid) {
        return metadata;
    }

    trie_assert(!is_evicted(), "metadata should be valid if evicted");

    if (is_leaf()) {
        auto const& value = std::get<variant_value_t>(body);
        if (!value.has_value()) {
            metadata.size = 0;
            metadata_valid = true;
            return metadata;
        }

        digest_bytes.clear();

        write_node_header(digest_bytes, prefix, prefix_len);
        value->copy_data(digest_bytes);

        // sets size = 1
        metadata.from_value(*value);

        if (crypto_generichash(metadata.hash.data(),
                               metadata.hash.size(),
                               digest_bytes.data(),
                               digest_bytes.size(),
                               NULL,
                               0)
            != 0) {
            throw std::runtime_error("error from crypto_generichash");
        }
        metadata_valid = true;

        log_self_active(storage);
        return metadata;
    }

    metadata_t new_metadata;

    int32_t num_children = 0;
    TrieBitVector bv;

    for (uint8_t bb = 0; bb < 16; bb++) {
        node_t* child = get_child(bb);
        if (child == nullptr)
            continue;

        new_metadata += child->compute_hash_and_normalize(
            gc, timestamp_evict_threshold, digest_bytes, storage);

        uint8_t child_count = child->get_num_children();
        if (child_count == 0) {
            child->log_self_deleted(storage);
            erase_child(bb, gc);
        } else if (child_count == 1) {

            child->log_self_deleted(storage);

            node_t* new_child = child->extract_singlechild();

            gc.free(child);

            bool res = try_add_child(bb, child, new_child);
            trie_assert(res, "concurrency fail");

            bv.add(bb);
            num_children++;
        } else {
            bv.add(bb);
            num_children++;
        }

        if (child->get_last_modified_ts() <= timestamp_evict_threshold) {
            node_t* new_child = child->evict_self();
            trie_assert(new_child != nullptr, "invalid eviction");
            gc.free(child);
            bool res = try_add_child(bb, child, new_child);
            trie_assert(res, "concurrency fail");
        }
    }
    metadata = new_metadata;

    if (num_children <= 1 && prefix_len.len != 0) {
        // don't bother hashing, except special casing the root node
        // parent node will manage deletion, if necessary
        return metadata;
    }

    digest_bytes.clear();

    write_node_header(digest_bytes, prefix, prefix_len);
    bv.write(digest_bytes);

    for (uint8_t bb = 0; bb < 16; bb++) {
        auto* ptr = get_child(bb);
        if (ptr == nullptr)
            continue;

        auto const& m = ptr->get_metadata();
        m.write_to(digest_bytes);
    }

    if (crypto_generichash(metadata.hash.data(),
                           metadata.hash.size(),
                           digest_bytes.data(),
                           digest_bytes.size(),
                           NULL,
                           0)
        != 0) {
        throw std::runtime_error("error from crypto_generichash");
    }

    metadata_valid = true;
    log_self_active(storage);
    return metadata;
}

MCTN_TEMPLATE
void
MCTN_DECL ::delete_value(const prefix_t& delete_prefix,
                         uint32_t ts,
                         deferred_gc_t auto& gc,
                         DurableInterface auto& storage)
{
    /** in our use cases, values are always at least loaded
     * into cache before deletion.
     * (see e.g. StateDB::try_apply_delta always calls get_value
     * without inspecting StorageDelta, even if the delta is just a delete)
     * It would not be hard to add in code to load in from durable storage here,
     * if necessary.
     */
    trie_assert(!is_evicted(), "must load value into cache before deleting");

    invalidate_hash(ts);

    if (is_leaf()) {
        // won't actually remove node from tree, but such nodes will get cleaned
        // up during normalize
        trie_assert(delete_prefix == prefix, "mismatch");
        auto const& v = std::get<variant_value_t>(body);
        v.reset();
        return;
    }

    auto bb = delete_prefix.get_branch_bits(prefix_len);

    auto* ptr = get_child(bb);
    trie_assert(ptr != nullptr, "must exist");

    if (ptr->is_leaf() && ptr->get_prefix() == delete_prefix) {
        auto* prev = std::get<variant_children_t>(body)[bb].exchange(
            nullptr, std::memory_order_acq_rel);
        if (prev) {
            prev->log_self_deleted(storage);
            gc.free(prev);
        }
        return;
    }

    ptr->delete_value(delete_prefix, ts, gc, storage);
}

MCTN_TEMPLATE
value_t*
MCTN_DECL::get_value(const prefix_t& query_prefix,
                     DurableInterface auto& storage)
{
    trie_assert(!is_evicted(), "cannot get_value from evicted node");

    if (is_leaf()) {
        auto const& v = std::get<variant_value_t>(body);
        if (query_prefix == prefix && v.has_value()) {
            return &(*v);
        }
        return nullptr;
    }

    auto match_len = get_prefix_match_len(query_prefix);

    if (match_len < prefix_len) {
        return nullptr;
    }

    const auto bb = query_prefix.get_branch_bits(prefix_len);

    while (true) {
        auto* ptr = get_child(bb);
        if (ptr == nullptr) {
            return nullptr;
        }

        if (ptr->is_evicted()) {
            throw std::runtime_error("unimplemented");
        } else {
            return ptr->get_value(query_prefix, storage);
        }

        __builtin_ia32_pause();
    }
}

MCTN_TEMPLATE
void
MCTN_DECL::log_self_active(DurableInterface auto& interface) const
{
    trie_assert(metadata_valid, "cannot commit self before hash");
    trie_assert(!is_evicted(), "cannot log active something already evicted");

    if (is_leaf() && std::get<variant_value_t>(body).has_value()) {
        // if not has_value, self is not active, so node will be deleted in a
        // hash and normalize operation we don't delete here, assumign the
        // normalize takes care of that as well.

        durable_value_t v;

        v.make_value_node(
            prefix, metadata.hash, *std::get<variant_value_t>(body));
        interface.log_durable_value(TimestampPointerPair(*this), v);
        return;
    }

    DurableMapNode m;

    m.h = metadata.hash;
    m.key_len_bits = prefix_len.len;
    TrieBitVector bv;
    uint8_t sz = 0;

    for (uint8_t bb = 0; bb < 16; bb++) {
        const node_t* child = get_child(bb);
        if (child == nullptr)
            continue;

        bv.add(bb);
        m.children[sz] = child->get_ts_ptr();
        sz++;
    }
    m.bv = bv.get();

    durable_value_t v;
    v.make_map_node(prefix, m);

    interface.log_durable_value(get_ts_ptr(), v);
}

MCTN_TEMPLATE
void
MCTN_DECL::log_self_deleted(DurableInterface auto& interface) const
{
    durable_value_t v;
    v.make_delete_node(prefix, prefix_len);
    interface.log_durable_value(get_ts_ptr(), v);
}

MCTN_TEMPLATE
MCTN_DECL*
MCTN_DECL::evict_self() const
{
    // care must be taken to ensure that data is logged
    // at time of eviction (mainly, during hash and normalize,
    // compute hash and log data before evicting).
    trie_assert(!is_evicted(), "double eviction");

    if (is_leaf()) {
        trie_assert(std::get<variant_value_t>(body).has_value(),
                    "cannot evict deleted object");
    }

    return new node_t(
        ptr_node_args_t{ get_ts_ptr(), prefix, prefix_len, metadata });
}

#undef MCTN_DECL
#undef MCTN_TEMPLATE

} // namespace trie

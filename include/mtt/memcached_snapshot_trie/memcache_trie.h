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

#include "mtt/snapshot_trie/optional_value.h"

#include "mtt/memcached_snapshot_trie/durable_interface.h"

#include <sodium.h>

#include <utils/assert.h>
#include <utils/debug_utils.h>

namespace trie {

template<typename _prefix_t, typename opt_value_t, SnapshotTrieMetadata _metadata_t>
class MemcacheTrieNode
{
  public:
    using prefix_t = _prefix_t;
    using metadata_t = _metadata_t;
    using node_t = MemcacheTrieNode<prefix_t, opt_value_t, metadata_t>;
    using value_t = opt_value_t::value_type;

  private:
    static_assert(std::atomic<node_t*>::is_always_lock_free,
                  "ptr should be lockfree");

    using variant_value_t = opt_value_t;//std::optional<value_t>;
    using variant_children_t = std::array<std::atomic<node_t*>, 16>;
    using variant_storage_ptr_t = TimestampPointerPair;

    constexpr static TimestampPointerPair null_ts_ptr = TimestampPointerPair();

    std::variant<variant_value_t, variant_children_t, variant_storage_ptr_t>
        body;

    const prefix_t prefix;
    const PrefixLenBits prefix_len;

    std::atomic<bool> metadata_valid;
    std::atomic<uint32_t> last_updated_timestamp;

    std::optional<TimestampPointerPair> previous_logged_ts;

    bool children_owned = false;
    metadata_t metadata;
    Hash hash;

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
        , previous_logged_ts(std::nullopt)
        , children_owned(false)
        , metadata()
        , hash()
    {}

    template<typename... value_args>
    // value node
    MemcacheTrieNode(
        prefix_t const& prefix,
        uint32_t ts,
        std::optional<TimestampPointerPair> const& previous_logged_ts,
        value_args const&... args)
        : body(std::in_place_type<variant_value_t>, std::in_place_t{}, args...)
        , prefix(prefix)
        , prefix_len(MAX_KEY_LEN_BITS)
        , metadata_valid(false)
        , last_updated_timestamp(ts)
        , previous_logged_ts(previous_logged_ts)
        , children_owned(false)
        , metadata()
        , hash()
    {}

    struct map_node_args_t
    {
        prefix_t const& prefix;
        PrefixLenBits len;
    };

    // map node
    MemcacheTrieNode(
        map_node_args_t const& args,
        uint32_t ts,
        std::optional<TimestampPointerPair> const& previous_logged_ts
        = std::nullopt)
        : body(std::in_place_type<variant_children_t>)
        , prefix([args](const prefix_t& p) -> prefix_t {
            prefix_t out = p;
            out.truncate(args.len);
            return out;
        }(args.prefix))
        , prefix_len(args.len)
        , metadata_valid(false)
        , last_updated_timestamp(ts)
        , previous_logged_ts(previous_logged_ts)
        , children_owned(false)
        , metadata()
        , hash()
    {
        trie_assert(prefix_len != MAX_KEY_LEN_BITS, "wrong ctor used");
    }

    struct ptr_node_args_t
    {
        TimestampPointerPair const& tsp;
        prefix_t const& prefix;
        PrefixLenBits prefix_len;
        metadata_t const& metadata;
        Hash const& hash;
    };

    // ptr node
    // note that pointer node must have been logged
    // at time args.tsp.timestamp
    MemcacheTrieNode(ptr_node_args_t args)
        : body(args.tsp)
        , prefix(args.prefix)
        , prefix_len(args.prefix_len)
        , metadata_valid(true)
        , last_updated_timestamp(args.tsp.timestamp)
        , previous_logged_ts(std::nullopt)
        , children_owned(false)
        , metadata(args.metadata)
        , hash(args.hash)
    {}

    void set_unique_child(uint8_t bb, node_t* ptr)
    {
        // possible memory leak -- won't be freed unless commit_ownership() also
        // called
        std::get<variant_children_t>(body)[bb].store(ptr,
                                                     std::memory_order_relaxed);
    }

    // root node
    MemcacheTrieNode(
        uint32_t ts,
        std::optional<TimestampPointerPair> const& previous_logged_ts
        = std::nullopt)
        : body(std::in_place_type<variant_children_t>)
        , prefix()
        , prefix_len(0)
        , metadata_valid(false)
        , last_updated_timestamp(ts)
        , previous_logged_ts(previous_logged_ts)
        , children_owned(true)
        , metadata()
        , hash()
    {}

    void commit_ownership() { children_owned = true; }

    void set_metadata(const metadata_t& m, const Hash& h)
    {
        metadata = m;
        hash = h;
        metadata_valid.store(true, std::memory_order_release);
    }

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

    TimestampPointerPair const& get_ptr_to_evicted_data() const
    {
        return std::get<variant_storage_ptr_t>(body);
    }

    TimestampPointerPair get_ts_ptr() const
    {
        if (is_evicted()) {
            return std::get<variant_storage_ptr_t>(body);
        } else {
            return TimestampPointerPair(*this);
        }
    }

    TimestampPointerPair const& get_previous_ts_ptr() const
    {
        trie_assert(!is_evicted(),
                    "can't get previous ts ptr from something evicted");
        if (previous_logged_ts.has_value()) {
            return *previous_logged_ts;
        }
        return null_ts_ptr;
    }

    void update_previous_ts_ptr()
    {
        trie_assert(!is_evicted(), "can't update ts ptr in evicted node");
        previous_logged_ts = TimestampPointerPair(*this);
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

    bool __attribute__((warn_unused_result))
    try_add_child(uint8_t bb, node_t*& expect, node_t* new_ptr)
    {
        return std::get<variant_children_t>(body)[bb].compare_exchange_strong(
            expect, new_ptr, std::memory_order_acq_rel);
    }

    void invalidate_hash_to_node(const node_t* target,
                                 uint32_t current_timestamp);
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

    void write_metadata_and_hash_to(std::vector<uint8_t>& digest_bytes) const {
        trie_assert(metadata_valid.load(std::memory_order_acquire),
                    "invalid metadata acquired");
       
        metadata.write_to(digest_bytes);
        digest_bytes.insert(
            digest_bytes.end(),
            hash.begin(),
            hash.end());
    }

    const Hash& get_hash() const {
        trie_assert(metadata_valid.load(std::memory_order_acquire),
                    "invalid hash acquired");
        return hash;
    }

    void delete_value(const prefix_t& delete_prefix,
                      uint32_t ts,
                      deferred_gc_t auto& gc,
                      DurableInterface auto& storage);

    value_t* get_value(const prefix_t& query_prefix,
                       DurableInterface auto const& storage);

    void log_self_active(DurableInterface auto& interface);
    void log_self_deleted(DurableInterface auto& interface);

    void log(std::string pref) const
    {
        std::printf("%s %p %s (%u)\n",
                    pref.c_str(),
                    this,
                    prefix.to_string(prefix_len).c_str(),
                    prefix_len);
        if (is_leaf()) {
            auto& value = std::get<variant_value_t>(body);
            std::printf("%s value opt %u logical %u\n", pref.c_str(), value.has_opt_value(), value.has_logical_value());
            return;
        }

        if (is_evicted()) {
            return;
        }

        for (uint8_t bb = 0; bb < 16; bb++) {
            auto const* ptr = get_child(bb);
            if (ptr != nullptr) {
                std::printf("  %s child %p %u\n", pref.c_str(), ptr, bb);
                ptr->log(pref + std::string("  "));
            }
        }
    }
};

template<typename prefix_t,
         typename value_t,
         uint32_t TLCACHE_SIZE,
         DurableInterface storage_t,
         SnapshotTrieMetadata metadata_t = SnapshotTrieMetadataBase,
         auto has_value_f = detail::default_value_selector<value_t>>
class MemcacheTrie
{
    using node_t = MemcacheTrieNode<prefix_t, OptionalValue<value_t, has_value_f>, metadata_t>;
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

    node_t* get_root_and_invalidate_hash(uint32_t current_timestamp)
    {
        root->invalidate_hash_to_node(root, current_timestamp);
        return root;
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
        return root->get_hash();
    }

    value_t* get_value(prefix_t const& query)
    {
        return root->get_value(query, storage);
    }

    const value_t* get_value(prefix_t const& query) const
    {
        return root->get_value(query, storage);
    }

    void log(std::string pref) const
    {
        root -> log(pref);
    }
};

#define MCTN_TEMPLATE                                                          \
    template<typename _prefix_t,                                               \
             typename opt_value_t,                                             \
             SnapshotTrieMetadata _metadata_t>
#define MCTN_DECL MemcacheTrieNode<_prefix_t, opt_value_t, _metadata_t>

template<typename node_t>
static node_t*
load_evicted_ptr(TimestampPointerPair const& storage_ptr,
                 DurableInterface auto const& storage)
{
    auto result = storage.restore_durable_value(storage_ptr);

    using prefix_t = typename node_t::prefix_t;
    using metadata_t = typename node_t::metadata_t;

    utils::print_assert(!result.is_delete(),
                        "should not be reloaded a deletion marker");

    if (result.is_value()) {
        auto const& value_header = result.template get_value<metadata_t>();

        auto value_slice = value_header.to_value_slice();

        node_t* out = new node_t(prefix_t(result.get_key().ptr, slice_ctor_t{}),
                                 storage_ptr.timestamp,
                                 value_header.previous,
                                 value_slice);

        out->set_metadata(value_header.metadata, value_header.hash);
        return out;
    }

    utils::print_assert(result.is_map(), "no other types");

    auto const& map_node = result.template get_map<metadata_t>();

    typename node_t::map_node_args_t args{
        .prefix = prefix_t(result.get_key().ptr, slice_ctor_t{}),
        .len = PrefixLenBits{ map_node.key_len_bits }
    };

    // map node
    auto* out
        = new node_t(args, map_node.previous.timestamp, map_node.previous);

    TrieBitVector bv(map_node.bv);

    uint8_t counter = 0;

    while (!bv.empty()) {
        uint8_t bb = bv.pop();

        auto res_child
            = storage.restore_durable_value(map_node.children[counter]);

        auto get_meta = [&res_child]() -> const metadata_t& {
            if (res_child.is_value()) {
                return res_child.template get_value<metadata_t>().metadata;
            }
            utils::print_assert(!res_child.is_delete(), "invalid load");
            return res_child.template get_map<metadata_t>().metadata;
        };

         auto get_hash = [&res_child]() -> const Hash& {
            if (res_child.is_value()) {
                return res_child.template get_value<metadata_t>().hash;
            }
            utils::print_assert(!res_child.is_delete(), "invalid load");
            return res_child.template get_map<metadata_t>().hash;
        };

        typename node_t::ptr_node_args_t ptr_args{
            .tsp = map_node.children[counter],
            .prefix = prefix_t(result.get_key().ptr, slice_ctor_t{}),
            .prefix_len
            = result.is_value()
                  ? prefix_t::len()
                  : result.template get_map<metadata_t>().key_len_bits,
            .metadata = get_meta(),
            .hash = get_hash()
        };

        node_t* ptr_child = new node_t(ptr_args);
        node_t* expect = nullptr;

        auto res = out->try_add_child(bb, expect, ptr_child);
        utils::print_assert(res, "concurrency fail");

        counter++;
    }
    return out;
}

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
        if (value.has_opt_value()) {
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
            node_t* new_node = new node_t(
                new_prefix, current_timestamp, std::nullopt, args...);

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
                    node_t* reloaded = load_evicted_ptr<node_t>(
                        child->get_ptr_to_evicted_data(), storage);
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
MCTN_DECL ::invalidate_hash_to_node(const node_t* target,
                                    uint32_t current_timestamp)
{
    invalidate_hash(current_timestamp);
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

    child->invalidate_hash_to_node(target, current_timestamp);
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
const _metadata_t&
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
        if (!value.has_logical_value()) {
            metadata.size = 0;
            metadata_valid = true;
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

        /** 
         * Should be a less than, not leq
         * Some instantiation might start with timestamp 0,
         * and leq would make it easy to have 
         * accidental error.
         * 0 should mean "never evict"
         */
        if (child->get_last_modified_ts() < timestamp_evict_threshold) {
            node_t* new_child = child->evict_self();
            trie_assert(new_child != nullptr, "invalid eviction");
            gc.free(child); // has to be before try_add_child modifies 'child' variable
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

        ptr -> write_metadata_and_hash_to(digest_bytes);
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
        auto& v = std::get<variant_value_t>(body);
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
            prev->invalidate_hash(ts);
            prev->log_self_deleted(storage);
            gc.free(prev);
        }
        return;
    }

    ptr->delete_value(delete_prefix, ts, gc, storage);
}

MCTN_TEMPLATE
MCTN_DECL::value_t*
MCTN_DECL::get_value(const prefix_t& query_prefix,
                     DurableInterface auto const& storage)
{
    trie_assert(!is_evicted(), "cannot get_value from evicted node");

    if (is_leaf()) {
        auto& v = std::get<variant_value_t>(body);
        if (query_prefix == prefix && v.has_logical_value()) {
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

            node_t* reloaded = load_evicted_ptr<node_t>(
                ptr->get_ptr_to_evicted_data(), storage);

            if (try_add_child(bb, ptr, reloaded)) {
                return reloaded->get_value(query_prefix, storage);
            } else {
                delete reloaded;
            }
        } else {
            return ptr->get_value(query_prefix, storage);
        }

        __builtin_ia32_pause();
    }
}

MCTN_TEMPLATE
void
MCTN_DECL::log_self_active(DurableInterface auto& interface)
{
    trie_assert(metadata_valid, "cannot commit self before hash");
    trie_assert(!is_evicted(), "cannot log active something already evicted");

    if (is_leaf() && std::get<variant_value_t>(body).has_logical_value()) {
        // if not has_value, self is not active, so node will be deleted in a
        // hash and normalize operation we don't delete here, assumign the
        // normalize takes care of that as well.

        durable_value_t v;

        v.make_value_node(prefix,
                          metadata,
                          hash,
                          get_previous_ts_ptr(),
                          *std::get<variant_value_t>(body));
        interface.log_durable_value(get_ts_ptr(), v);
        update_previous_ts_ptr();
        return;
    } 
    else if (is_leaf() && !std::get<variant_value_t>(body).has_logical_value())
    {
        throw std::runtime_error("should not log as active a deleted value");
    }

    DurableMapNode<metadata_t> m;

    m.metadata = metadata;
    m.hash = hash;
    m.key_len_bits = prefix_len.len;
    m.previous = get_previous_ts_ptr();
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
    update_previous_ts_ptr();
}

MCTN_TEMPLATE
void
MCTN_DECL::log_self_deleted(DurableInterface auto& interface)
{
    durable_value_t v;
    v.make_delete_node(get_previous_ts_ptr());
    interface.log_durable_value(get_ts_ptr(), v);
    // not strictly necessary,
    // but acts as a guard against future errors if this deleted node
    // is somehow still referenced
    update_previous_ts_ptr();
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
        trie_assert(std::get<variant_value_t>(body).has_logical_value(),
                    "cannot evict deleted object");
    }

    return new node_t(
        ptr_node_args_t{ get_ts_ptr(), prefix, prefix_len, metadata, hash });
}

#undef MCTN_DECL
#undef MCTN_TEMPLATE

} // namespace trie

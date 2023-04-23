#pragma once

#include "mtt/common/prefix.h"
#include "mtt/common/types.h"

#include "mtt/common/bitvector.h"
#include "mtt/common/debug_macros.h"
#include "mtt/common/insert_fn.h"
#include "mtt/common/utils.h"

#include "mtt/layered_trie/concepts.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <map>

#include <utils/threadlocal_cache.h>
#include <utils/assert.h>

#include <sodium.h>

namespace trie
{

namespace detail
{

template<typename... Ts>
struct overloaded : Ts... { 
	using Ts::operator()...;
};

}

template<typename prefix_t, ValueType value_t, LayeredTrieNodeMetadata metadata_t>
class LayeredTrieNode
{
	using node_t = LayeredTrieNode<prefix_t, value_t, metadata_t>;

	static_assert(std::atomic<node_t*>::is_always_lock_free, "ptr should be lockfree");

	using children_t = std::array<std::atomic<node_t*>, 16>;

	std::variant<value_t, children_t> children_or_value;

	const prefix_t prefix;
	const PrefixLenBits prefix_len;
	const uint64_t current_layer;

	metadata_t metadata;

	std::atomic<uint8_t> active_children = 0;

	// this node is rendered obsolete in a higher layer.
	// If 0, then this node does not own any references to child nodes.
	// If UINT64_MAX, then not superseded by anything.
	std::atomic<uint64_t> superseded_in_layer;

	constexpr static uint16_t KEY_LEN_BYTES = prefix_t::size_bytes();

    constexpr static PrefixLenBits MAX_KEY_LEN_BITS
        = PrefixLenBits{ KEY_LEN_BYTES * 8 };

public:

	// value node
	LayeredTrieNode(prefix_t const& prefix, value_t&& value, uint64_t layer)
		: children_or_value(std::move(value))
		, prefix(prefix)
		, prefix_len(MAX_KEY_LEN_BITS)
		, current_layer(layer)
		, metadata()
		, superseded_in_layer(0)
		{
			// active_children = 0
		}

	// map node
	LayeredTrieNode(prefix_t const& prefix, const PrefixLenBits len, uint64_t layer)
		: children_or_value(std::in_place_type<children_t>)
		, prefix([len] (const prefix_t& p) -> prefix_t { prefix_t out = p; out.truncate(len); return out; } (prefix))
		, prefix_len(len)
		, current_layer(layer)
		, metadata()
		, superseded_in_layer(0)
		{
			if (prefix_len == MAX_KEY_LEN_BITS)
			{
				throw std::runtime_error("wrong ctor used");
			}
			// active_children = 0
		}

	LayeredTrieNode(node_t* superseded, uint64_t layer)
		: children_or_value(
			std::visit( 
				detail::overloaded {
					[] (value_t& value) -> std::variant<value_t, children_t> {
						return std::variant<value_t, children_t>(std::in_place_type<value_t>, value.get_value_commitment());
					},
					[] (const children_t& children) -> std::variant<value_t, children_t>
					{
						return std::variant<value_t, children_t>(std::in_place_type<children_t>);
					}
				},
				superseded->children_or_value))
		, prefix(superseded->prefix)
		, prefix_len(superseded->prefix_len)
		, current_layer(layer)
		, metadata()
		, active_children(superseded->active_children.load(std::memory_order_acquire))
		, superseded_in_layer(0)
		{
			utils::print_assert(
				superseded ->current_layer < layer, 
				std::string("superseding constructor should increase current layer ")
				+ std::to_string(layer) + " " + std::to_string(superseded -> current_layer));

			if (std::holds_alternative<children_t>(children_or_value))
			{
				auto& children = std::get<1>(children_or_value);
				auto const& prev_children = std::get<1>(superseded->children_or_value);
				for (auto i = 0u; i < children.size(); i++)
				{
					children[i].store(prev_children[i].load(std::memory_order_acquire), std::memory_order_release);
				}
			}
			
		}

	void set_unique_child(uint8_t bb, node_t* ptr)
	{
		std::get<1>(children_or_value)[bb].store(ptr, std::memory_order_release);
		active_children.fetch_add(1, std::memory_order_release);
	}

	// root node
	LayeredTrieNode()
		: children_or_value(std::in_place_type<children_t>)
		, prefix()
		, prefix_len(0)
		, current_layer(0)
		, metadata()
		, superseded_in_layer(UINT64_MAX)
	{
		// active_children = 0
	}

	uint64_t get_superseded_layer() const {
		return superseded_in_layer.load(std::memory_order_acquire);
	}

	/**
	 * Suppose that a node is superseded by a node at layer A
	 * and a child is superseded by a node at layer B
	 * (which also includes deleting that node at layer B).
	 * If A < B, then the node that replaces A still has a reference
	 * to the child hode, so we don't delete B.
	 * If A == B, then the current node is the last node with
	 * a valid reference to the child, and so we delete it.
	 * If A > B,
	 * there is an error.
	 * 
	 * It must be the case that when freeing a node, the
	 * currently active layer is strictly higher
	 * than the layer at which the node is superseded.
	 * (I.e. don't free node at layer K while actively processing
	 * layer K+1)
	 */
	~LayeredTrieNode()
	{
		//std::printf("call dtor on %p\n", this);
		//std::printf("prefix %s (%lu)\n", prefix.to_string(prefix_len).c_str(), prefix_len);
		if (!is_leaf())
		{
		//	std::printf("not is_leaf\n");
			uint64_t superseded_layer = get_superseded_layer();
		//	std::printf("superseded_layer %lu\n", superseded_layer);
			if (superseded_layer == 0)
			{
				return;
			}

			auto& children = std::get<children_t>(children_or_value);

			for (uint8_t bb = 0; bb < 16; bb++)
			{
				node_t* ptr = children[bb].load(std::memory_order_relaxed);
				if (ptr != nullptr)
				{
					uint64_t child_superseded_layer = ptr -> get_superseded_layer();

					if (superseded_layer == child_superseded_layer)
					{
						//std::printf("start deleting child on %u at %p\n", bb, ptr);
						delete ptr;
					}
					if (superseded_layer > child_superseded_layer)
					{
						std::terminate();
					}
				}
			}	
		}
	}

	bool is_leaf() const
	{
		return prefix_len == MAX_KEY_LEN_BITS;
	}

	bool is_active_leaf(uint64_t querying_layer) const 
	{
		utils::print_assert(querying_layer > current_layer, "can't ask for is_active before taking a snapshot");
		return is_leaf() && std::get<value_t>(children_or_value).is_active();
	}

	void set_superseded_layer(uint64_t layer)
	{
	//	std::printf("superseding %s (%lu) @ %p with layer %lu\n", prefix.to_string(prefix_len).c_str(),
	//		prefix_len.len, this, layer);
		superseded_in_layer.store(layer, std::memory_order_release);
	}

	void commit_node()
	{
		set_superseded_layer(UINT64_MAX);
	}

	uint64_t get_layer() const {
		return current_layer;
	}

    auto
    insert(prefix_t const& new_prefix,
           auto modify_lambda,
           uint64_t current_layer,
           bool do_gc);

    bool try_add_child(uint8_t bb, node_t*& expect, node_t* new_ptr)
    {
    	utils::print_assert(std::holds_alternative<children_t>(children_or_value), "try_add_child on a value node");
    	bool res = std::get<children_t>(children_or_value)[bb].compare_exchange_strong(expect, new_ptr, std::memory_order_acq_rel);
    	if (res)
    	{
    		if (expect == nullptr)
    		{
    			active_children.fetch_add(1, std::memory_order_release);
    		}

    		// not one if-else ladder
    		if (new_ptr == nullptr)
    		{
    			active_children.fetch_sub(1, std::memory_order_release);
    		} 
    		else
    		{
    			new_ptr -> commit_node();
    		}
    	}
    	return res;
    }

    uint8_t get_num_active_children() const
    {
    	return active_children.load(std::memory_order_acquire);
    }

    node_t* get_unique_child()
    {
    	if (std::holds_alternative<value_t>(children_or_value))
    	{
    		return nullptr;
    	}

    	for (auto& ref : std::get<children_t>(children_or_value))
    	{
    		auto* ptr = ref.load(std::memory_order_acquire);
    		if (ptr != nullptr)
    		{
    			return ptr;
    		}
    	}
    	return nullptr;
    }

    node_t* get_child(uint8_t bb)
    {
    	utils::print_assert(std::holds_alternative<children_t>(children_or_value), "get_child on a value node");
    	return std::get<children_t>(children_or_value)[bb].load(std::memory_order_acquire);
    }

    const node_t* get_child(uint8_t bb) const
    {
    	utils::print_assert(std::holds_alternative<children_t>(children_or_value), "get_child const on a value node");
    	return std::get<children_t>(children_or_value)[bb].load(std::memory_order_acquire);
    }

    PrefixLenBits get_prefix_match_len(const prefix_t& other_key,
                                       const PrefixLenBits other_len
                                       = MAX_KEY_LEN_BITS) const
    {
        return prefix.get_prefix_match_len(prefix_len, other_key, other_len);
    }


    prefix_t const& get_prefix() const {
    	return prefix;
    }

    PrefixLenBits get_prefix_len() const {
    	return prefix_len;
    }

    auto const&
    compute_hash(std::vector<uint8_t>& digest_bytes);

    // TESTING ONLY

    bool in_normal_form() const
    {
    	utils::print_assert(get_superseded_layer() != 0, "no uncommitted nodes");
    	
    	if (is_leaf())
    	{
    	//	std::printf("this = %p, prefix = %s (%lu), is_leaf, superseded = %lu\n", this, prefix.to_string(prefix_len).c_str(), 
    	//		prefix_len.len, get_superseded_layer());
    		utils::print_assert(get_num_active_children() == 0, "no children of value nodes");
    		return std::get<value_t>(children_or_value).is_active();
    	}

    	//std::printf("this = %p, prefix = %s (%lu), not leaf, superseded = %lu\n", this, 
    	//	prefix.to_string(prefix_len).c_str(), prefix_len.len,
    	//	get_superseded_layer());

    	uint8_t found_active_children = 0;

    	for (uint8_t bb = 0; bb < 16; /*TODO get size statically from type information children_t::size(); */ bb++)
    	{
    		auto const* ptr = get_child(bb);

    		if (ptr == nullptr)
    		{
    			continue;
    		}
    		found_active_children ++;
    		if (!ptr -> in_normal_form())
    		{
    		//	std::printf("child %u was not normal\n", bb);
    			return false;
    		}

    		//std::printf("self %llu child %llu\n", get_superseded_layer(), ptr -> get_superseded_layer());

    		utils::print_assert(get_superseded_layer() == ptr -> get_superseded_layer() 
    			|| ptr -> get_superseded_layer() == UINT64_MAX, "should not increase unless not superseded");

    	}
    	if (found_active_children != get_num_active_children())
    	{
    	//	std::printf("mismatch in num active children\n");
    		return false;
    	}

    	if (found_active_children <= 1 && prefix_len.len != 0)
    	{
    		return false;
    	}

    	return true;
    }

    bool expect_superseded(const prefix_t& query, PrefixLenBits query_len, uint64_t superseded_expect) const
    {
    	if (prefix_len > query_len) {
    	//	std::printf("expect_superseded1: query %s (%lu) not found\n", query.to_string(query_len).c_str(), query_len.len);
    		return false;
    	}

    	auto prefix_match_len = get_prefix_match_len(query, query_len);

    	if (prefix_len == query_len && prefix_match_len == prefix_len)
    	{
    	//	std::printf("expect_superseded: found match %s (%lu) @ %p expect %lu got %lu\n", query.to_string(query_len).c_str(), query_len.len,
    	//		this,
    	//		superseded_expect, get_superseded_layer());
    		return superseded_expect == get_superseded_layer();
    	}

    	auto bb = query.get_branch_bits(prefix_len);

    	// value nodes should be ruled out by this point
    	auto const* child = get_child(bb);

    	if (child == nullptr)
    	{
    	//	std::printf("expect_superseded2: query %s (%lu) not found\n", query.to_string(query_len).c_str(), query_len.len);
    		return false;
    	}

    	return child -> expect_superseded(query, query_len, superseded_expect);
    }

/*
    int32_t
    compute_hash_and_normalize(gc_t& gc, std::vector<uint8_t>& digest_bytes);

    uint8_t get_num_children() const;

    node_t* extract_singlechild();

    void invalidate_hash() 
    {
    	hash_valid.store(false, std::memory_order_release);
    }


    node_t* get_child(uint8_t bb)
    {
    	return children[bb].load(std::memory_order_acquire);
    }

    const node_t* get_child(uint8_t bb) const
    {
    	return children[bb].load(std::memory_order_acquire);
    }

    void erase_child(uint8_t bb, gc_t& gc)
    {
    	gc.free(children[bb].exchange(nullptr, std::memory_order_acq_rel));
    }



    void invalidate_hash_to_node(const node_t* target);
    void invalidate_hash_to_key(const prefix_t& query);

    template<typename InsertFn>
    node_t* get_or_make_subnode_ref(const prefix_t& query_prefix, const PrefixLenBits query_len, gc_t& gc);

    void append_hash_to_vec(std::vector<uint8_t>& bytes)
    {
    	trie_assert(hash_valid.load(std::memory_order_acquire), "invalid hash appended");

    	bytes.insert(bytes.end(),
    		hash.begin(),
    		hash.end());
    }

    Hash get_hash() const
    {
    	trie_assert(hash_valid.load(std::memory_order_acquire), "invalid hash appended");

    	return hash;
    }

    void delete_value(const prefix_t& delete_prefix, gc_t& gc);

    const value_t* get_value(const prefix_t& query_prefix) const;

    void log(std::string pref) const
    {
    	std::printf("%s %p %s\n", pref.c_str(), this, prefix.to_string(prefix_len).c_str());
    	if (is_leaf())
    	{
    		return;
    	}

    	for (uint8_t bb = 0; bb < 16; bb++)
    	{
    		auto const* ptr = get_child(bb);
    		if (ptr != nullptr)
    		{
    			std::printf("  %s child %p %u\n", pref.c_str(), ptr, bb);
    			ptr -> log(std::string("  ") + pref);
    		}
    	}
    } */
};


/**
 * 
 * LayeredTrie
 * 		- holds each TrieLayerReference, manages when freeing is safe,
 * 		- hands out read/normalize/hash references on past layers
 */


template<typename prefix_t, typename value_t, LayeredTrieNodeMetadata metadata_t>
class TrieLayerRoot;

template<typename prefix_t, typename value_t, LayeredTrieNodeMetadata metadata_t>
class LayeredTrie;


template<typename prefix_t, typename value_t, LayeredTrieNodeMetadata metadata_t>
class WeakLayerReference
{
	using root_t = TrieLayerRoot<prefix_t, value_t, metadata_t>;
	friend class TrieLayerRoot<prefix_t, value_t, metadata_t>;

	root_t& base_reference;

	std::shared_lock<std::shared_mutex> lock;

	const bool layer_active;

	WeakLayerReference(root_t& reference)
		: base_reference(reference)
		, lock(reference.mtx)
		, layer_active(reference.active)
		{}

public:

	// access methods -- methods should check base_reference.active

	auto insert(const prefix_t& prefix, auto lambda)
	{
		utils::print_assert(layer_active, "invalid insert call");
		return base_reference.root -> insert(prefix, lambda, base_reference.layer, false);
	}

	Hash compute_hash()
	{
		utils::print_assert(!layer_active, "invalid compute hash");

		std::vector<uint8_t> digest_bytes;
		auto out = base_reference.root -> compute_hash(digest_bytes);
		utils::print_assert(out.hash_valid, "returned hash is valid");
		return out.hash;
	}

	void gc_inactive_leaf(const prefix_t& prefix)
	{
		utils::print_assert(layer_active, "invalid gc call");

		auto lambda = [] (value_t&) -> void
		{
			// no op
		};

		base_reference.root -> insert(prefix, lambda, base_reference.layer, true);
	}

	bool is_active() const {
		return layer_active;
	}

	// TESTING

	bool in_normal_form() const
	{
		return base_reference.root -> in_normal_form();
	}

	bool expect_superseded(const prefix_t& query, uint16_t query_len, uint64_t superseded_expect) const
	{
		return base_reference.root -> expect_superseded(query, PrefixLenBits{query_len}, superseded_expect);
	}
};

template<typename prefix_t, typename value_t, LayeredTrieNodeMetadata metadata_t>
class TrieLayerRoot : public utils::NonMovableOrCopyable
{
	const uint64_t layer;
	bool active = true;

	using node_t = LayeredTrieNode<prefix_t, value_t, metadata_t>;

	std::unique_ptr<node_t> root;

	std::shared_mutex mtx;

	friend class LayeredTrie<prefix_t, value_t, metadata_t>;
	friend class WeakLayerReference<prefix_t, value_t, metadata_t>;

	void finalize_layer()
	{
		// force the destruction of any WeakLayerReferences
		std::lock_guard lock(mtx);
		active = false;
	}

	TrieLayerRoot(TrieLayerRoot& previous_layer)
		: layer(previous_layer.layer + 1)
		, root(std::make_unique<node_t>(previous_layer.root.get(), layer))
		{
			previous_layer.set_superseded(layer);
			root -> commit_node();
		}

	TrieLayerRoot()
		: layer(0)
		, root(std::make_unique<node_t>())
		{
			// emptyargs root constructor sets root to be in committed state
			// (although layer0 root will never have any children anyways)
		}

	void set_superseded(uint64_t layer)
	{
		root -> set_superseded_layer(layer);
	}

public:

	WeakLayerReference<prefix_t, value_t, metadata_t>
	open_access_reference()
	{
		return WeakLayerReference<prefix_t, value_t, metadata_t>(*this);
	}
};

template<typename prefix_t, typename value_t, LayeredTrieNodeMetadata metadata_t = LayeredTrieNodeMetadataBase>
class LayeredTrie : public utils::NonMovableOrCopyable
{
	using layer_t = TrieLayerRoot<prefix_t, value_t, metadata_t>;

	std::mutex mtx;

	std::map<uint64_t, std::unique_ptr<layer_t>> roots;

	uint64_t freeable_lowerbound = 0;
	uint64_t active_layer = 0;

public:

	LayeredTrie() {
		roots.emplace(active_layer, std::unique_ptr<layer_t>(new layer_t()));
	}

	layer_t& bump_active_layer()
	{
		std::lock_guard lock(mtx);

		auto& prev_layer = roots.at(active_layer);
		prev_layer->finalize_layer();

		active_layer++;

		roots.emplace(active_layer, std::unique_ptr<layer_t>(new layer_t(*prev_layer)));

		return *roots.at(active_layer);
	}

	layer_t& get_layer(uint64_t layer)
	{
		std::lock_guard lock(mtx);
		return *roots.at(layer);
	}

	// raising garbage collection lower bound to layer N
	// immediately invalidates any references to layer <= N
	// exposed by get_layer() or bump_active_layer()
	void raise_gc_lowerbound(uint64_t layer)
	{
		std::lock_guard lock(mtx);

		freeable_lowerbound = std::max(layer, freeable_lowerbound);

		// cannot free active layer or the layer immediately below it
		uint64_t actually_to_be_freed = std::min(freeable_lowerbound, active_layer - 2);

		for (auto i = roots.begin(); i != roots.end();)
		{
			if (i->first <= actually_to_be_freed)
			{
				i = roots.erase(i);
			}
			else
			{
				i++;
			}
		}
	}

}; 





/*
	template<typename InsertFn = OverwriteInsertFn<value_t>>
	node_t* get_subnode_ref_and_invalidate_hash(const prefix_t& query_prefix, const PrefixLenBits query_len)
	{
		auto* out = root->template get_or_make_subnode_ref<InsertFn>(query_prefix, query_len, gc);
		root -> invalidate_hash_to_node(out);
		return out;
	}

	gc_t& get_gc()
	{
		return gc;
	}

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

	void do_gc()
	{
		gc.gc();
	}

	~AtomicMerkleTrie()
	{
		gc.free(root);
		root = nullptr;
		gc.gc();
	}

	Hash hash_and_normalize()
	{
		std::vector<uint8_t> digest_bytes;
		root -> compute_hash_and_normalize(gc, digest_bytes);
		return root -> get_hash();
	}

	const value_t* get_value(prefix_t const& query) const
	{
		return root -> get_value(query);
	}

	value_t* get_value(prefix_t const& query)
	{
		return const_cast<value_t*>(
			const_cast<const AtomicMerkleTrie<prefix_t, value_t, TLCACHE_SIZE>*>(this) -> get_value(query));
	} */

#define LTN_TEMPLATE template<typename prefix_t, typename value_t, LayeredTrieNodeMetadata metadata_t>
#define LTN_DECL LayeredTrieNode<prefix_t, value_t, metadata_t>

LTN_TEMPLATE
auto
LTN_DECL::insert(
	prefix_t const& new_prefix,
	auto modify_lambda,
	uint64_t current_layer,
	bool do_gc)
{
	//std::printf("insert %s to prefix %s (%lu) @ %p, do_gc=%lu\n", new_prefix.to_string(MAX_KEY_LEN_BITS).c_str(),
	//	prefix.to_string(prefix_len).c_str(), prefix_len.len, this, do_gc);

	using ret_type = decltype((modify_lambda)(std::declval<value_t&>()));

	auto prefix_match_len = get_prefix_match_len(new_prefix);

	utils::print_assert(current_layer == get_layer(), "layering mismatch");
	utils::print_assert(prefix_match_len == prefix_len, "mismatch in prefix match len");

	if (is_leaf())
	{
		return modify_lambda(std::get<value_t>(children_or_value));
	}

	const uint8_t bb = new_prefix.get_branch_bits(prefix_len);

	node_t* child = get_child(bb);

	while(true)
	{

		if (child == nullptr)
		{
			if (do_gc)
			{
				return ret_type();
			}
			// insert new node
			node_t* new_node = new node_t(new_prefix, value_t(), current_layer);

			if (try_add_child(bb, child, new_node))
			{
				return new_node -> insert(new_prefix, modify_lambda, current_layer, do_gc);
			}
			delete new_node;
		} 
		else 
		{
			PrefixLenBits join_len = child->get_prefix_match_len(new_prefix);

			utils::print_assert(join_len <= child -> get_prefix_len(), "too long");
			if (join_len == child -> get_prefix_len())
			{
				if (child -> get_layer() != current_layer)
				{
					node_t* new_node;
					if (child -> get_num_active_children() == 0 && !(child->is_active_leaf(current_layer)))
					{
						if (do_gc)
						{
							new_node = nullptr;
						} 
						else
						{
							new_node = new node_t(new_prefix, value_t(), current_layer);
						}
					}
					else
					{
						node_t* target_node = child;
						while (target_node -> get_num_active_children() == 1)
						{
							utils::print_assert(target_node -> get_layer() < current_layer, "layer mismatch");
							target_node = target_node -> get_unique_child();
						}

						new_node = new node_t(target_node, current_layer);
					}
					node_t* old_child = child;
					if (try_add_child(bb, child, new_node))
					{
						node_t* target_node = old_child;
						while (target_node -> get_num_active_children() == 1)
						{
							utils::print_assert(target_node -> get_layer() < current_layer, "layer mismatch2");
							target_node -> set_superseded_layer(current_layer);

							target_node = target_node -> get_unique_child();
						}
						utils::print_assert(target_node != nullptr, "invalid unique_child returned");
						target_node -> set_superseded_layer(current_layer);

						if (new_node != nullptr)
						{
							//child -> set_superseded_layer(current_layer);
							return new_node -> insert(new_prefix, modify_lambda, current_layer, do_gc);
						} else
						{
							return ret_type();
						}

					}
					if (new_node != nullptr)
					{
						delete new_node;
					}
				} 
				else
				{
					return child -> insert(new_prefix, modify_lambda, current_layer, do_gc);
				}
			} else
			{
				if (do_gc)
				{
					// node to be garbage collected already does not exist
					return ret_type();
				}

				node_t* new_node = new node_t(new_prefix, join_len, current_layer);
				new_node -> set_unique_child(child->get_prefix().get_branch_bits(join_len), child);

				if (try_add_child(bb, child, new_node))
				{
					return new_node -> insert(new_prefix, modify_lambda, current_layer, do_gc);
				}
				delete new_node;
			}
		}
		__builtin_ia32_pause();
	}
}

LTN_TEMPLATE
auto const&
LTN_DECL::compute_hash(std::vector<uint8_t>& digest_bytes)
{
	if (metadata.hash_valid) {
		return metadata;
	}
	auto hash_bytes = [] (std::vector<uint8_t>& bytes, metadata_t& meta) {
		if (crypto_generichash(
        	meta.hash.data(),
        	meta.hash.size(),
        	bytes.data(),
        	bytes.size(),
       		NULL,
      		0) != 0)
		{
    		throw std::runtime_error("error from crypto_generichash");
		}
		meta.hash_valid = true;
	};

	if (is_leaf())
	{
		digest_bytes.clear();
		utils::print_assert(std::get<value_t>(children_or_value).is_active(), "compute hash on inactive node");

		write_node_header(digest_bytes, prefix, prefix_len);
		auto commitment = std::get<value_t>(children_or_value).get_value_commitment();

		commitment.write_to(digest_bytes);

		metadata.read(commitment);
		metadata.size = 1;
		hash_bytes(digest_bytes, metadata);

		return metadata;
	}

	uint8_t found_active_children = 0;
	TrieBitVector bv;

	for (uint8_t bb = 0; bb < 16; bb++)
	{
		auto* ptr = get_child(bb);

		if (ptr == nullptr || ptr -> get_num_active_children() == 0)
		{
			continue;
		}
		found_active_children ++;
		bv.add(bb);
		ptr -> compute_hash(digest_bytes);
	}
	digest_bytes.clear();

	write_node_header(digest_bytes, prefix, prefix_len);
	bv.write(digest_bytes);

	for (uint8_t bb = 0; bb < 16; bb++)
	{
		auto* ptr = get_child(bb);

		if (ptr == nullptr || ptr -> get_num_active_children() == 0)
		{
			continue;
		}
		if (found_active_children == 1)
		{
			metadata = ptr -> compute_hash(digest_bytes);
			utils::print_assert(metadata.hash_valid, "must get valid hash from child");
			return metadata;
		}
		auto const& child_meta = ptr -> compute_hash(digest_bytes);
		metadata += child_meta;
		child_meta.write_to(digest_bytes);
	}

	hash_bytes(digest_bytes, metadata);
	return metadata;
}

/*

AMTN_TEMPLATE
void
AMTN_DECL :: invalidate_hash_to_node(const node_t* target)
{
	invalidate_hash();
	if (target == this)
	{
		return;
	}

	auto match_len = get_prefix_match_len(target -> get_prefix(), target -> get_prefix_len());

	trie_assert(match_len == prefix_len, "invalid invalidate");

	const uint8_t bb = target -> get_prefix().get_branch_bits(prefix_len);

	node_t* child = get_child(bb);
	trie_assert(child != nullptr, "found null child in invalidate_hash_to_node");

	child -> invalidate_hash_to_node(target);
}

AMTN_TEMPLATE
void
AMTN_DECL :: invalidate_hash_to_key(const prefix_t& query)
{
	invalidate_hash();

	if (is_leaf())
	{
		trie_assert(prefix == query, "mismatch on invalidate_hash_to_key");
		return;
	}

	auto bb = query.get_branch_bits(prefix_len);
	node_t* child = get_child(bb);
	trie_assert(child != nullptr, "invalid child found");

	child -> invalidate_hash_to_key(query);
}

AMTN_TEMPLATE
uint8_t 
AMTN_DECL :: get_num_children() const
{
	if (is_leaf())
	{
		if (value_valid)
		{
			return UINT8_MAX;
		}
		return 0;
	}
	uint8_t count = 0;

	for (uint8_t bb = 0; bb < 16; bb++)
	{
		if (get_child(bb) != nullptr)
		{
			count++;
		}
	}
	return count;
}

AMTN_TEMPLATE
AMTN_DECL*
AMTN_DECL :: extract_singlechild()
{
	trie_assert(!is_leaf(), "invalid extract");

	for (uint8_t bb = 0; bb < 16; bb++)
	{
		auto* ptr = get_child(bb);
		if (ptr == nullptr) continue;

		return children[bb].exchange(nullptr, std::memory_order_acq_rel);
	}

	trie_assert(false, "there was no child");
	throw std::runtime_error("invalid");
}

AMTN_TEMPLATE
template<typename InsertFn>
AMTN_DECL* 
AMTN_DECL :: get_or_make_subnode_ref(const prefix_t& query_prefix, const PrefixLenBits query_len, gc_t& gc)
{
//	std::printf("get_or_make_subnode_ref: prefix %s query %s\n", 
//		prefix.to_string(prefix_len).c_str(),
//		query_prefix.to_string(query_len).c_str());

	auto matchlen = get_prefix_match_len(query_prefix, query_len);

	trie_assert(matchlen >= prefix_len, "invalid get_or_make_subnode_ref");

	if (query_len == prefix_len)
	{
		return this;
	}

	const uint8_t bb = query_prefix.get_branch_bits(prefix_len);

	node_t* ptr = get_child(bb);

	while (true)
	{
		if (ptr == nullptr)
		{
			node_t* new_child = nullptr;
			if (query_len == MAX_KEY_LEN_BITS)
			{
				new_child = new node_t(query_prefix, InsertFn::new_value(query_prefix));
			} 
			else
			{
				new_child = new node_t(query_prefix, query_len);
			}
			if (try_add_child(bb, ptr, new_child))
			{
				new_child -> commit_ownership();
				return new_child;
			}
			gc.free(new_child);
		} 
		else
		{
			//std::printf("child exists: %s\n", ptr -> get_prefix().to_string(ptr -> get_prefix_len()).c_str());
			auto child_match_len = ptr -> get_prefix_match_len(query_prefix, query_len);
			//std::printf("match len: %u\n", child_match_len.len);
			if (child_match_len == ptr -> get_prefix_len())
			{
				return ptr -> template get_or_make_subnode_ref<InsertFn>(query_prefix, query_len, gc);
			}
			
			node_t* intermediate = new node_t(query_prefix, child_match_len);
			uint8_t child_bb = ptr -> get_prefix().get_branch_bits(child_match_len);
			intermediate -> set_unique_child(child_bb, ptr);

			if (try_add_child(bb, ptr, intermediate))
			{
				intermediate -> commit_ownership();

				return intermediate -> template get_or_make_subnode_ref<InsertFn>(query_prefix, query_len, gc);
			}
			gc.free(intermediate);
		}
		__builtin_ia32_pause();
	}
}


AMTN_TEMPLATE
int32_t
AMTN_DECL :: compute_hash_and_normalize(gc_t& gc, std::vector<uint8_t>& digest_bytes)
{
	if (hash_valid)
	{
		return size.load(std::memory_order_acquire);
	}

	if (is_leaf())
	{
		if (!value_valid)
		{
			return 0;
		}

		digest_bytes.clear();

		write_node_header(digest_bytes, prefix, prefix_len);
        value.copy_data(digest_bytes);

        if (crypto_generichash(
        	hash.data(),
           hash.size(),
           digest_bytes.data(),
           digest_bytes.size(),
           NULL,
           0) 
        != 0) {
        	throw std::runtime_error("error from crypto_generichash");
    	}
    	hash_valid = true;
    	size.exchange(1, std::memory_order_acq_rel);
    	return 1;
	}

	int32_t new_size = 0;

	int32_t num_children = 0;
	TrieBitVector bv;

	for (uint8_t bb = 0; bb < 16; bb++)
	{
		node_t* child = get_child(bb);
		if (child == nullptr) continue;

		new_size += child -> compute_hash_and_normalize(gc, digest_bytes);

		uint8_t child_count = child -> get_num_children();
		if (child_count == 0)
		{
			erase_child(bb, gc);
		} 
		else if (child_count == 1)
		{
			node_t* new_child = child -> extract_singlechild();

			gc.free(child);

			trie_assert(try_add_child(bb, child, new_child), "concurrency fail");

			bv.add(bb);
			num_children++;
		}
		else
		{
			bv.add(bb);
			num_children ++;
		}
	}

	size.store(new_size, std::memory_order_release);
	if (num_children <= 1 && prefix_len.len != 0)
	{
		// don't bother hashing, except special casing the root node
		return new_size;
	}

	digest_bytes.clear();

	write_node_header(digest_bytes, prefix, prefix_len);
    bv.write(digest_bytes);

    for (uint8_t bb = 0; bb < 16; bb++)
    {
    	auto* ptr = get_child(bb);
    	if (ptr == nullptr) continue;

    	ptr -> append_hash_to_vec(digest_bytes);
    }

    if (crypto_generichash(
    	hash.data(),
       hash.size(),
       digest_bytes.data(),
       digest_bytes.size(),
       NULL,
       0) 
    != 0) {
    	throw std::runtime_error("error from crypto_generichash");
	}

	hash_valid = true;

	return new_size;
}

AMTN_TEMPLATE
void
AMTN_DECL :: delete_value(const prefix_t& delete_prefix, gc_t& gc)
{
	invalidate_hash();

	if (is_leaf())
	{
		trie_assert(delete_prefix == prefix, "mismatch");
		value_valid = false;
		return;
	}

	auto bb = delete_prefix.get_branch_bits(prefix_len);

	auto* ptr = get_child(bb);
	trie_assert(ptr != nullptr, "must exist");

	if (ptr -> is_leaf()
		&& ptr -> get_prefix() == delete_prefix)
	{
		auto* prev = children[bb].exchange(nullptr, std::memory_order_acq_rel);
		if (prev) {
			gc.free(prev);
		}
		return;
	}

	ptr -> delete_value(delete_prefix, gc);
}

AMTN_TEMPLATE
const value_t* 
AMTN_DECL::get_value(const prefix_t& query_prefix) const
{
	if (is_leaf())
	{
		if (query_prefix == prefix && value_valid)
		{
			return &value;
		}
		return nullptr;
	}

	auto match_len = get_prefix_match_len(query_prefix);

	if (match_len < prefix_len)
	{
		return nullptr;
	}

	const auto bb = query_prefix.get_branch_bits(prefix_len);

	auto* ptr = get_child(bb);
	if (ptr == nullptr)
	{
		return nullptr;
	}
	return ptr -> get_value(query_prefix);
}
 */


#undef LTN_DECL
#undef LTN_TEMPLATE

} // namespace trie

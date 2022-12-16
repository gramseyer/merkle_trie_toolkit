#pragma once

#include "mtt/trie/bitvector.h"
#include "mtt/trie/debug_macros.h"
#include "mtt/trie/prefix.h"
#include "mtt/trie/types.h"
#include "mtt/trie/utils.h"

#include <array>
#include <atomic>
#include <cstdint>

#include <utils/threadlocal_cache.h>

#include <sodium.h>

namespace trie
{


template<typename prefix_t, typename value_t, uint32_t TLCACHE_SIZE>
class AtomicMerkleTrieNode;

// avoid ABA problem
template<typename prefix_t, typename value_t, uint32_t TLCACHE_SIZE>
class AtomicMerkleTrieGC
{
	using node_t = AtomicMerkleTrieNode<prefix_t, value_t, TLCACHE_SIZE>;

	struct LocalGC {
		std::vector<node_t*> nodes;
	};

	utils::ThreadlocalCache<LocalGC, TLCACHE_SIZE> cache;

public:

	void free(node_t* ptr)
	{
		cache.get().nodes.push_back(ptr);
	}

	void gc()
	{
		auto& locals = cache.get_objects();

		for (auto& l : locals)
		{
			if (l)
			{
				auto& ptrs = l -> nodes;
				for (auto* ptr : ptrs)
				{
					delete ptr;
				}
			}
		}

		cache.clear();
	}

	~AtomicMerkleTrieGC()
	{
		gc();
	}
};

template<typename prefix_t, typename value_t, uint32_t TLCACHE_SIZE>
class AtomicMerkleTrieNode
{
	using node_t = AtomicMerkleTrieNode<prefix_t, value_t, TLCACHE_SIZE>;

	using gc_t = AtomicMerkleTrieGC<prefix_t, value_t, TLCACHE_SIZE>;

	static_assert(std::atomic<node_t*>::is_always_lock_free, "ptr should be lockfree");

	union {
		std::array<std::atomic<node_t*>, 16> children;
		value_t value;
	};

	prefix_t prefix;
	PrefixLenBits prefix_len;

	std::atomic<bool> hash_valid;
	bool children_owned = false;

	std::atomic<int32_t> size;

	Hash hash;

	constexpr static uint16_t KEY_LEN_BYTES = prefix_t::size_bytes();

    constexpr static PrefixLenBits MAX_KEY_LEN_BITS
        = PrefixLenBits{ KEY_LEN_BYTES * 8 };

public:

	// value node
	AtomicMerkleTrieNode(prefix_t const& prefix, value_t&& value)
		: value(value)
		, prefix(prefix)
		, prefix_len(MAX_KEY_LEN_BITS)
		, hash_valid(false)
		, children_owned(false)
		, size(0)
		, hash()
		{}

	// map node
	AtomicMerkleTrieNode(prefix_t const& prefix, PrefixLenBits len)
		: children()
		, prefix(prefix)
		, prefix_len(len)
		, hash_valid(false)
		, children_owned(false)
		, size(0)
		, hash()
		{
			if (len == MAX_KEY_LEN_BITS)
			{
				throw std::runtime_error("wrong ctor used");
			}
		}

	void set_unique_child(uint8_t bb, node_t* ptr)
	{
		//possible memory leak -- won't be freed unless commit_ownership() also called
		children[bb] = ptr;
	}

	// root node
	AtomicMerkleTrieNode()
		: children()
		, prefix()
		, prefix_len(0)
		, hash_valid(false)
		, children_owned(true)
		, size(0)
		, hash()
	{}

	template<typename InsertFn, typename InsertedValueType>
	static value_t 
	create_new_value(typename std::enable_if<
            !std::is_same<value_t, InsertedValueType>::value,
            InsertedValueType&&>::type v)
	{
		return InsertFn::new_value(v);
	}

	template<typename InsertFn, typename InsertedValueType>
	static value_t 
	create_new_value(typename std::enable_if<
            std::is_same<value_t, InsertedValueType>::value,
            InsertedValueType&&>::type v)
	{
		return v;
	}

	void commit_ownership()
	{
		children_owned = true;
	}

	static void trie_assert(bool expr, const char* msg)
	{
		if (!expr)
		{
			throw std::runtime_error(msg);
		}
	}

	~AtomicMerkleTrieNode()
	{
		if (is_leaf())
		{
			value.~value_t();
		}
		else
		{
			if (children_owned)
			{
				for (uint8_t bb = 0; bb < 16; bb++)
				{
					node_t* ptr = children[bb].load(std::memory_order_relaxed);
					if (ptr != nullptr)
					{
						delete ptr;
					}
				}
			}
		}
	}

	bool is_leaf() const
	{
		return prefix_len == MAX_KEY_LEN_BITS;
	}

	template<typename InsertFn, typename InsertedValue>
    void
    insert(prefix_t const& new_prefix,
           InsertedValue&& value,
           gc_t& gc);

    int32_t __attribute__((warn_unused_result))
    compute_hash_and_normalize(gc_t& gc);

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

    prefix_t const& get_prefix() const {
    	return prefix;
    }

    PrefixLenBits get_prefix_len() const {
    	return prefix_len;
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

    bool try_add_child(uint8_t bb, node_t*& expect, node_t* new_ptr)
    {
    	return children[bb].compare_exchange_strong(expect, new_ptr, std::memory_order_acq_rel);
    }

    void invalidate_hash_to_node(const node_t* target);

    node_t* get_or_make_subnode_ref(const prefix_t& query_prefix, const PrefixLenBits query_len, gc_t& gc);

    void append_hash_to_vec(std::vector<uint8_t>& bytes)
    {
    	trie_assert(hash_valid.load(std::memory_order_acquire), "invalid hash appended");

    	bytes.insert(bytes.end(),
    		hash.begin(),
    		hash.end());
    }
};


template<typename prefix_t, typename value_t, uint32_t TLCACHE_SIZE>
class AtomicMerkleTrie
{
	using node_t = AtomicMerkleTrieNode<prefix_t, value_t, TLCACHE_SIZE>;
	using gc_t = AtomicMerkleTrieGC<prefix_t, value_t, TLCACHE_SIZE>;

	node_t* root;

	gc_t gc;

public:

	node_t* get_subnode_ref_and_invalidate_hash(const prefix_t& query_prefix, const PrefixLenBits query_len)
	{
		auto* out = root->get_or_make_subnode_ref(query_prefix, query_len, gc);
		root -> invalidate_hash_to_node(out);
		return out;
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

	~AtomicMerkleTrie()
	{
		gc.free(root);
		root = nullptr;
		gc.gc();
	}
};

#define AMTN_TEMPLATE template<typename prefix_t, typename value_t, uint32_t TLCACHE_SIZE>
#define AMTN_DECL AtomicMerkleTrieNode<prefix_t, value_t, TLCACHE_SIZE>

AMTN_TEMPLATE
template<typename InsertFn, typename InsertedValue>
void
AMTN_DECL::insert(
	prefix_t const& new_prefix,
	InsertedValue&& new_value,
	gc_t& gc)
{
	invalidate_hash();

	auto prefix_match_len = get_prefix_match_len(new_prefix);
	trie_assert(prefix_match_len >= prefix_len, "invalid insertion");

	if (is_leaf())
	{
		InsertFn::value_insert(value, std::move(new_value));
		return;
	}

	const uint8_t bb = prefix.get_branch_bits(prefix_match_len);

	node_t* child = get_child(bb);

	while(true)
	{

		if (child == nullptr)
		{
			// insert new node
			node_t* new_node = new node_t(new_prefix, create_new_value<InsertFn, InsertedValue>(std::move(new_value)));

			if (try_add_child(bb, child, new_node))
			{
				return;
			}
			gc.free(new_node);
		} 
		else
		{
			node_t* new_node = new node_t(new_prefix, prefix_match_len);
			new_node -> set_unique_child(bb, child);

			if (try_add_child(bb, child, new_node))
			{
				new_node -> commit_ownership();
				new_node -> template insert<InsertFn, InsertedValue>(new_prefix, std::move(new_value), gc);
				return;
			}
			gc.free(new_node);
		}
		__builtin_ia32_pause();
	}
}

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

	trie_assert(match_len >= prefix_len, "invalid invalidate");

	const uint8_t bb = target -> get_prefix().get_branch_bits(match_len);

	node_t* child = get_child(bb);
	trie_assert(child != nullptr, "found null child in invalidate_hash_to_node");

	child -> invalidate_hash_to_node(target);
}

AMTN_TEMPLATE
uint8_t 
AMTN_DECL :: get_num_children() const
{
	if (is_leaf())
	{
		return UINT8_MAX;
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
	std::abort();
}

AMTN_TEMPLATE
AMTN_DECL* 
AMTN_DECL :: get_or_make_subnode_ref(const prefix_t& query_prefix, const PrefixLenBits query_len, gc_t& gc)
{
	auto matchlen = get_prefix_match_len(query_prefix, query_len);

	trie_assert(matchlen >= prefix_len, "invalid get_or_make_subnode_ref");

	if (query_len == prefix_len)
	{
		return this;
	}

	trie_assert(prefix_len < MAX_KEY_LEN_BITS, "can't be value here");
	trie_assert(query_len < MAX_KEY_LEN_BITS, "can't ask for value here");

	const uint8_t bb = query_prefix.get_branch_bits(prefix_len);

	node_t* ptr = get_child(bb);

	while (true)
	{
		if (ptr == nullptr)
		{
			node_t* new_child = new node_t(query_prefix, query_len);
			if (try_add_child(bb, ptr, new_child))
			{
				new_child -> commit_ownership();
				return new_child;
			}
			gc.free(new_child);
		} else
		{

			auto child_match_len = ptr -> get_prefix_match_len(query_prefix, query_len);
			if (child_match_len == ptr -> get_prefix_len())
			{
				return ptr -> get_or_make_subnode_ref(query_prefix, query_len, gc);
			}

			node_t* intermediate = new node_t(query_prefix, query_len);
			intermediate -> set_unique_child(bb, ptr);

			if (try_add_child(bb, ptr, intermediate))
			{
				intermediate -> commit_ownership();
				return intermediate;
			}
			gc.free(intermediate);
		}
		__builtin_ia32_pause();
	}
}


AMTN_TEMPLATE
int32_t __attribute__((warn_unused_result))
AMTN_DECL :: compute_hash_and_normalize(gc_t& gc)
{
	if (hash_valid)
	{
		return 0;
	}

	std::vector<uint8_t> digest_bytes;

	if (is_leaf())
	{
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
    	uint32_t prev_size = size.exchange(1, std::memory_order_acq_rel);
    	return (1 - prev_size);
	}

	int32_t sz_delta = 0;

	int32_t num_children = 0;
	TrieBitVector bv;

	for (uint8_t bb = 0; bb < 16; bb++)
	{
		node_t* child = get_child(bb);
		if (child == nullptr) continue;

		sz_delta += child -> compute_hash_and_normalize(gc);

		uint8_t child_count = child -> get_num_children();
		if (child_count == 0)
		{
			erase_child(bb, gc);
		} 
		else if (child_count == 1)
		{
			node_t* new_child = child -> extract_singlechild();

			gc.free(child);

			trie_assert(try_set_child(bb, child, new_child), "concurrency fail");

			bv.add(bb);
			num_children++;
		}
		else
		{
			bv.add(bb);
			num_children ++;
		}
	}

	size.fetch_add(sz_delta, std::memory_order_acq_rel);
	if (num_children <= 1 && prefix_len.len != 0)
	{
		// don't bother hashing, except special casing the root node
		return sz_delta;
	}

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

	return sz_delta;
}




#undef AMTN_DECL
#undef AMTN_TEMPLATE

} // namespace trie

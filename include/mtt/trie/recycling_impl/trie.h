#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include <sodium.h>

#include <tbb/parallel_for.h>
#include <tbb/parallel_reduce.h>

#include "mtt/trie/prefix.h"
#include "mtt/trie/spinlock.h"

#include "mtt/trie/recycling_impl/allocator.h"
#include "mtt/trie/recycling_impl/ranges.h"
#include "mtt/trie/recycling_impl/children_map.h"
#include "mtt/trie/recycling_impl/metadata.h"

#include "mtt/utils/threadlocal_cache.h"
#include "mtt/utils/serialize_endian.h"

#include "mtt/trie/types.h"

/* TODO add metadata to this

 Turns out that for this particular trie setup,
 we don't need metadata to be atomic
 because every time we update it
 we have a lock (the spinlock) on it
*/

namespace trie {

template<typename ValueType, typename NodeType, typename MetadataT>
struct TrieNodeContents {
	using prefix_t = typename NodeType::prefix_t;
	using children_map_t = AccountChildrenMap<ValueType, NodeType>;
	using ptr_t = children_map_t::ptr_t;

	children_map_t children;
	prefix_t prefix;
	PrefixLenBits prefix_len;
	//int32_t size;
	MetadataT metadata;
};

struct PtrWrapper {
	uint32_t ptr;
	constexpr static uint32_t NULLPTR = UINT32_MAX;
	bool non_null() const {
		return ptr != NULLPTR;
	}
	uint32_t get() const {
		return ptr;
	}

	constexpr static PtrWrapper make_nullptr() {
		return PtrWrapper{NULLPTR};
	}
};

template<typename ValueType, typename prefix_t>
struct ApplyableSubnodeRef {
	uint32_t ptr;
	const AccountTrieNodeAllocator<ValueType>& allocator;

	template<typename ApplyFn>
	void apply(ApplyFn& fn) const {
		allocator.get_object(ptr).apply(fn, allocator);
	}

	template<typename ApplyFn>
	void apply_to_keys(ApplyFn& fn) const {
		allocator.get_object(ptr).apply_to_keys(fn, allocator);
	}

	prefix_t
	get_prefix() const {
		return allocator.get_object(ptr).get_prefix();
	}

	PrefixLenBits get_prefix_len() const {
		return allocator.get_object(ptr).get_prefix_len();
	}
};

template<typename ValueType, typename PrefixT, typename ExtraMetadata>
class RecyclingTrie;

template<typename ValueType, typename PrefixT, typename ExtraMetadata>
class alignas(64) RecyclingTrieNode {

public:
	using prefix_t = PrefixT;
	using node_t = RecyclingTrieNode<ValueType, prefix_t, ExtraMetadata>;
	using children_map_t = AccountChildrenMap<ValueType, node_t>;
	using ptr_t = children_map_t::ptr_t;
	using hash_t = Hash;
	using allocation_context_t = AllocationContext<node_t>;
	using metadata_t = RecyclingTrieNodeMetadata<ExtraMetadata>;
	using contents_t = TrieNodeContents<ValueType, node_t, metadata_t>;
	using allocator_t = AccountTrieNodeAllocator<node_t>;
	using value_t = ValueType;
	using main_trie_t = RecyclingTrie<ValueType, PrefixT, ExtraMetadata>;

	constexpr static uint8_t BRANCH_BITS = 4;
private:

	friend children_map_t;

	constexpr static uint8_t KEY_LEN_BYTES = PrefixT::size_bytes();
	//static_assert(KEY_LEN_BYTES == 8, "invalid keylen (bunch of stuff to fix if change)");

	constexpr static uint8_t MAX_BRANCH_VALUE = 0xF;

	constexpr static PrefixLenBits MAX_KEY_LEN_BITS = PrefixLenBits{KEY_LEN_BYTES * 8};

	// should all fit in 1 cache line

	hash_t hash; // 32

	children_map_t children; // 9 bytes

	std::atomic<bool> hash_valid = false; // 1
	SpinMutex mtx; // 1
	
	PrefixLenBits prefix_len; // 2, could be made 1

	metadata_t metadata;
	//std::atomic<int32_t> size_ = 0; // 4	

	prefix_t prefix; // 8


	void set_to(node_t& other, ptr_t this_ptr) {
		auto lock = other.lock();
		children = std::move(other.children);
		prefix = other.prefix;
		prefix_len = other.prefix_len;
		hash_valid.store(other.hash_valid.load(std::memory_order_relaxed), std::memory_order_relaxed);
		
		metadata = other.metadata;
		//size_.store(other.size_.load(std::memory_order_relaxed), std::memory_order_relaxed);

		if (other.get_hash_valid()) {
			hash = other.hash;
			validate_hash();
		} else {
			invalidate_hash();
		}
		other.children.set_stolen(this_ptr);
	}

	std::optional<ptr_t> check_stolen() {
		return children.check_stolen();
	}



	contents_t extract_contents() {
		return contents_t {
			.children = std::move(children),
			.prefix = prefix,
			.prefix_len = prefix_len,
			.metadata = metadata
			//.size = size()
		};
	}

	void set_from_contents(contents_t& contents) {
		children = std::move(contents.children);
		prefix = contents.prefix;
		prefix_len = contents.prefix_len;
		set_metadata(contents.metadata);
		//set_size(contents.size);
		invalidate_hash();
	}

public:

	void print_offsets() {
		std::printf("children: start %lu end %lu\n", offsetof(node_t, children), offsetof(node_t, children) + sizeof(children));
		std::printf("hash_valid: start %lu end %lu\n", offsetof(node_t, hash_valid), offsetof(node_t, hash_valid) + sizeof(hash_valid));
		std::printf("prefix_len: start %lu end %lu\n", offsetof(node_t, prefix_len), offsetof(node_t, prefix_len) + sizeof(prefix_len));
		std::printf("metadata: start %lu end %lu\n", offsetof(node_t, metadata), offsetof(node_t, metadata) + sizeof(metadata));
		std::printf("mtx: start %lu end %lu\n", offsetof(node_t, mtx), offsetof(node_t, mtx) + sizeof(mtx));
		std::printf("prefix: start %lu end %lu\n", offsetof(node_t, prefix), offsetof(node_t, prefix) + sizeof(prefix));
		std::printf("hash: start %lu end %lu\n", offsetof(node_t, hash), offsetof(node_t, hash) + sizeof(hash));
		children.print_offsets();
	}

	template<typename InsertFn, typename InsertedValueType>
	metadata_t
	__attribute__((warn_unused_result))
	set_as_value_leaf(
		const prefix_t key, 
		typename std::enable_if<std::is_same<ValueType, InsertedValueType>::value, InsertedValueType&&>::type value,
		allocation_context_t& allocator) {
		
		auto metadata = metadata_t::from_value(value);

		set_metadata(metadata);

		children.set_value(allocator, std::move(value));
		prefix = key;
		prefix_len = MAX_KEY_LEN_BITS;
		//set_size(1);
		invalidate_hash();
		return metadata;
	}

	template<typename InsertFn, typename InsertedValueType>
	metadata_t
	__attribute__((warn_unused_result))
	set_as_value_leaf(
		const prefix_t key, 
		typename std::enable_if<!std::is_same<ValueType, InsertedValueType>::value, InsertedValueType&&>::type value,
		allocation_context_t& allocator) {
		ValueType value_out = InsertFn::new_value(key);
		InsertFn::value_insert(value_out, std::move(value));

		auto metadata = metadata_t::from_value(value_out);

		set_metadata(metadata);

		children.set_value(allocator, std::move(value_out));
		prefix = key;
		prefix_len = MAX_KEY_LEN_BITS;
		//set_size(1);
		invalidate_hash();
		return metadata;
	}

	//for creating empty node
	RecyclingTrieNode() 
		: children()
		, prefix_len(0)
		, prefix()
		{
			set_metadata(metadata_t::zero());

			//set_size(0);
		}

	void set_as_empty_node() {
		children.clear();
		prefix_len = PrefixLenBits{0};
		prefix = prefix_t();
		set_metadata(metadata_t::zero());

		//set_size(0);
		invalidate_hash();
	}

	void steal_other_node_contents(
		children_map_t&& old_children,
		const prefix_t old_prefix,
		const PrefixLenBits old_prefix_len,
		metadata_t old_metadata) {

		children = std::move(old_children);
		prefix = old_prefix;
		prefix_len = old_prefix_len;
		set_metadata(old_metadata);
		//set_size(old_size);
		invalidate_hash();
	}

	int32_t size() const;

	metadata_t get_metadata() const
	{
		return metadata;
	}

	void set_metadata(metadata_t m)
	{
		metadata = m;
	}

	void alter_metadata(metadata_t delta)
	{
		metadata += delta;
	}

	/*void set_size(int32_t sz) {
		size_.store(sz, std::memory_order_relaxed);
	}
	void alter_size(int32_t delta) {
		size_.fetch_add(delta, std::memory_order_relaxed);
	} */

	const PrefixLenBits get_prefix_len() const {
		return prefix_len;
	}

	prefix_t get_prefix() const {
		return prefix;
	}

	PrefixLenBits get_prefix_match_len(const prefix_t other_key, const PrefixLenBits other_len = MAX_KEY_LEN_BITS) const {
		return prefix.get_prefix_match_len(prefix_len, other_key, other_len);
	}

	uint8_t get_branch_bits(const prefix_t other_key) const {
		return other_key.get_branch_bits(prefix_len);
	}

	void invalidate_hash() {
		hash_valid.store(false, std::memory_order_relaxed);
	}

	void validate_hash() {
		hash_valid.store(true, std::memory_order_relaxed);
	}

	bool get_hash_valid() const {
		return hash_valid.load(std::memory_order_relaxed);
	}

	//obj not threadsafe with mods to hash
	void append_hash_to_vec(std::vector<unsigned char>& buf) const {
		buf.insert(buf.end(), hash.begin(), hash.end());
	}

	//not threadsafe
	template<typename InsertFn, typename InsertedValueType>
	metadata_t insert(prefix_t const& key, InsertedValueType&& leaf_value, allocation_context_t& allocator);

	//not threadsafe
	template<typename... ApplyToValueBeforeHashFn>
	void compute_hash(const allocator_t& allocator, std::vector<unsigned char>& digest_bytes);

	//threadsafe
	template<typename MergeFn>
	metadata_t merge_in(ptr_t node, allocation_context_t& allocator);

	SpinLockGuard lock() const {
		return SpinLockGuard(mtx);
	}

	SpinUniqueLock unique_lock() const {
		return SpinUniqueLock(mtx);
	}

	bool is_leaf() const {
		return prefix_len == MAX_KEY_LEN_BITS;
	}

	template<typename allocator_or_context_t>
	void log(std::string padding, allocator_or_context_t& allocator) {
		LOG("%sprefix %s (len %u bits)", 
			padding.c_str(),
			prefix.to_string(prefix_len).c_str(),
			prefix_len.len);
		LOG("%ssz: %ld", padding.c_str(), size());
		children.log(padding);
		//LOG("%sthis_ptr: %x", padding.c_str(), this_ptr);
		for (auto iter = children.begin(); iter != children.end(); iter++) {
			LOG("%schild: child_bb %x, ptr 0x%x", padding.c_str(), (*iter).first, (*iter).second);
			allocator.get_object((*iter).second).log(padding + " |   ", allocator);
		}
	}

	void copy_hash_to_buf(uint8_t* buf) {
		memcpy(buf, hash.data(), hash.size());
	}

	//threadsafe
	std::vector<ptr_t> children_list() const {
		auto lock_ = lock();
		std::vector<ptr_t> output;
		for (auto iter = children.begin(); iter != children.end(); iter++) {
			output.push_back((*iter).second);
		}
		return output;
	}

	std::vector<ptr_t> children_list_nolock() const {
		std::vector<ptr_t> output;
		for (auto iter = children.begin(); iter != children.end(); iter++) {
			output.push_back((*iter).second);
		}
		return output;
	}

	//not threadsafe
	std::vector<std::pair<uint8_t, ptr_t>> children_list_with_branch_bits_nolock() {
		
		std::vector<std::pair<uint8_t, ptr_t>> output;
		//std::printf("listing children of node %p with prefix_len %d, num_children %lu\n", this, prefix_len, children.size());
		for (auto iter = children.begin(); iter != children.end(); iter++) {
			output.emplace_back((*iter).first, (*iter).second);
		}
		return output;
	}


	template<typename VectorType>
	void accumulate_values_parallel_worker(VectorType& output, size_t vector_offset, const allocator_t& allocator) const;

	template<typename VectorType>
	void accumulate_keys_parallel_worker(VectorType& output, size_t vector_offset, const allocator_t& allocator) const;


	std::tuple<bool, metadata_t, PtrWrapper>
	destructive_steal_child(const prefix_t& stealing_prefix, const PrefixLenBits stealing_prefix_len, allocation_context_t& allocator);

	void propagate_sz_delta(node_t* target, metadata_t delta, const allocator_t& allocator) {

		invalidate_hash();
		if (target == this) {
			return;
		}
		
		auto lk = lock();

		auto branch_bits = get_branch_bits(target -> get_prefix());

		auto iter = children.find(branch_bits);
		if (iter == children.end()) {
			throw std::runtime_error("can't propagate metadata to nonexistent node (recycling impl)");
		}

		alter_metadata(delta);
		//alter_size(delta);

		allocator.get_object((*iter).second).propagate_sz_delta(target, delta, allocator);
	}

	template <typename ApplyFn>
	void apply(ApplyFn& fn, const allocator_t& allocator) const {
		if (prefix_len == MAX_KEY_LEN_BITS) {
			fn(children.value(allocator));
			return;
		}
		for (auto iter = children.begin(); iter != children.end(); iter++) {
			auto& child = allocator.get_object((*iter).second);
			child.apply(fn, allocator);
		}
	}

	template<typename ApplyFn>
	void apply_to_keys(ApplyFn& fn, const allocator_t& allocator) const {
		if (prefix_len == MAX_KEY_LEN_BITS) {
			fn(prefix.uint64());
			return;
		}

		for (auto iter = children.begin(); iter != children.end(); iter++) {
			auto& child = allocator.get_object((*iter).second);
			child.apply_to_keys(fn, allocator);
		}
	}

	/* test */

	metadata_t
	test_metadata_integrity_check(const allocator_t& allocator) const
	{
		if (prefix_len == MAX_KEY_LEN_BITS)
		{
			return metadata;
		}
		metadata_t meta_acc = metadata_t::zero();
		for (auto iter = children.begin(); iter != children.end(); iter++)
		{
			meta_acc += allocator.get_object((*iter).second).get_metadata();
			allocator.get_object((*iter).second).test_metadata_integrity_check(allocator);
		}
		if (meta_acc != metadata)
		{
			throw std::runtime_error("metadata_mismatch");
		}
		return metadata;
	}
};

template<typename ValueType, typename PrefixT, typename ExtraMetadata>
class SerialRecyclingTrie {
	using node_t = RecyclingTrieNode<ValueType, PrefixT, ExtraMetadata>;
	AllocationContext<node_t> allocation_context;
	using ptr_t = node_t::ptr_t;
	ptr_t root;

	using main_trie_t = RecyclingTrie<ValueType, PrefixT, ExtraMetadata>;

	friend main_trie_t;

	//static_assert(sizeof(node_t) <= 64, "account trie node should be at most 1 cache line");


public:

	SerialRecyclingTrie(AccountTrieNodeAllocator<node_t>& allocator) 
		: allocation_context(allocator.get_new_allocator())
		, root(UINT32_MAX) {
			acquire_new_root();
	}

	SerialRecyclingTrie(main_trie_t& main_trie) 
		: SerialRecyclingTrie(main_trie.get_allocator()) {}

//	void clear() {
//		root = UINT32_MAX;
//		allocation_context.clear();
//	}

	size_t size() const {
		return allocation_context.get_object(root).size();
	}

	void acquire_new_root() {
		root = allocation_context.init_root_node();
	}

	void set_root(ptr_t new_root) {
		root = new_root;
	}

	ptr_t extract_root() {
		auto out = root;
		acquire_new_root();
		return out;
	}

	template<typename InsertFn = OverwriteInsertFn<ValueType>, typename InsertedValueType = ValueType>
	void insert(PrefixT const& key, InsertedValueType&& value) {
		auto& ref = allocation_context.get_object(root);
		ref.template insert<InsertFn, InsertedValueType>(key, std::move(value), allocation_context);
	}

	void log() {
		auto& ref = allocation_context.get_object(root);
		ref.log("", allocation_context);
	}

	void print_offsets() {
		auto& ref = allocation_context.get_object(root);
		ref.print_offsets();
		std::printf("sizeof: %lu\n", sizeof(node_t));
	}

	AllocationContext<node_t>& 
	get_allocation_context() {
		return allocation_context;
	}
};

template<typename MergeFn>
struct AccountBatchMergeReduction;
template<typename TrieT>
struct AccountBatchMergeRange;

template<typename ValueType, typename PrefixT = UInt64Prefix, typename ExtraMetadata = void>
class RecyclingTrie {


public:
	using node_t = RecyclingTrieNode<ValueType, PrefixT, ExtraMetadata>;
	using ptr_t = node_t::ptr_t;
	using serial_trie_t = SerialRecyclingTrie<ValueType, PrefixT, ExtraMetadata>;
	using metadata_t = RecyclingTrieNodeMetadata<ExtraMetadata>;
private:

	AccountTrieNodeAllocator<node_t> allocator;

	friend serial_trie_t;//class SerialRecyclingTrie<ValueType>;

	AccountTrieNodeAllocator<node_t>& get_allocator() {
		return allocator;
	}

	ptr_t root = UINT32_MAX; // null

	mutable std::mutex mtx;

	Hash root_hash;
	std::atomic<bool> hash_valid = false;

	void get_root_hash(Hash& out);
	void validate_hash() {
		hash_valid.store(true, std::memory_order_relaxed);
	}
	void invalidate_hash() {
		hash_valid.store(false, std::memory_order_relaxed);
	}

	bool check_hash_valid() {
		return hash_valid.load(std::memory_order_relaxed);
	}

	template<typename MergeFn = OverwriteMergeFn>
	void merge_in_nolock(serial_trie_t& trie) {

		if (trie.size() == 0) {
			return;
		}

		invalidate_hash();

		if (root == UINT32_MAX) {
			root = trie.root;
			trie.acquire_new_root();
			return;
		}

		auto& obj = allocator.get_object(root);
		obj.template merge_in<MergeFn>(trie.root, trie.allocation_context);
		trie.acquire_new_root();
	}

	size_t size_nolock() const {

		if (root == UINT32_MAX) {
			return 0;
		}
		return allocator.get_object(root).size();
	}

public:
	RecyclingTrie() {
		if (sodium_init() == -1) {
			throw std::runtime_error("Sodium init failed!!!");
		}
	}


	serial_trie_t open_serial_subsidiary() {
		return serial_trie_t(allocator);
	}

	void clear() {
		std::lock_guard lock(mtx);
		allocator.reset();
		root = UINT32_MAX;
		hash_valid = false;
	}

	size_t size() const {
		std::lock_guard lock(mtx);

		return size_nolock();
	}

	ExtraMetadata metadata() const
	{
		std::lock_guard lock(mtx);
		if (root == UINT32_MAX)
		{
			return ExtraMetadata::zero();
		}
		return allocator.get_object(root).get_metadata().metadata;
	}

	template<typename VectorType>
	VectorType accumulate_values_parallel() const;

	template<typename VectorType>
	void accumulate_values_parallel(VectorType& vec) const;

	template<typename VectorType>
	void accumulate_keys_parallel(VectorType& vec) const;

	template<typename MergeFn = OverwriteMergeFn>
	void merge_in(serial_trie_t& trie) {
		std::lock_guard lock(mtx);

		merge_in_nolock<MergeFn>(trie);
	}

	template<typename MergeFn>
	void batch_merge_in(utils::ThreadlocalCache<serial_trie_t>& tl_cache) {

		std::lock_guard lock(mtx);
		invalidate_hash();

		auto& serial_tries = tl_cache.get_objects();
		std::vector<ptr_t> ptrs;
		for (auto& serial : serial_tries) {
			if (serial) {
				std::printf("sz: %u\n", serial -> size());
				if (size_nolock() > 0) {
					ptrs.push_back(serial->extract_root());
				} else {
					merge_in_nolock<MergeFn>(*serial);
				}
			}
		}

		if (ptrs.size() == 0) {
			return;
		}

		AccountBatchMergeRange<node_t> range(root, ptrs, allocator, tl_cache);

		AccountBatchMergeReduction<MergeFn> reduction{};

		tbb::parallel_reduce(range, reduction);

		tl_cache.clear();
	}

	template<typename ValueModifyFn>
	void parallel_batch_value_modify(ValueModifyFn& fn) const {

		std::lock_guard lock(mtx);
		if (root == UINT32_MAX) {
			std::printf("trie is null, nothing to parallel_batch_value_modify\n");
			return;
		}

		AccountApplyRange<node_t> range(root, allocator);
		//guaranteed that range.work_list contains no overlaps

		//Fences are present because ValueModifyFn can modify various
		//memory locations in MemoryDatabase
		//std::atomic_thread_fence(std::memory_order_release);
		tbb::parallel_for(
			range,
			[&fn, this] (const auto& range) {
				for (unsigned int i = 0; i < range.work_list.size(); i++) {
					ApplyableSubnodeRef ref{range.work_list[i], allocator};
					fn(ref);
				}
			});
	}

	template<typename... ApplyFn>
	void hash(Hash& hash);

	void log() {
		std::lock_guard lock(mtx);
		auto& ref = allocator.get_object(root);
		ref.log("", allocator);
	}

	void test_metadata_integrity_check() const
	{
		std::lock_guard lock(mtx);
		if (root == UINT32_MAX)
		{
			return;
		}
		auto const& ref = allocator.get_object(root);
		ref.test_metadata_integrity_check(allocator);
	}

};

#define ATN_TEMPLATE template<typename ValueType, typename PrefixT, typename ExtraMetadata>
#define ATN_DECL RecyclingTrieNode<ValueType, PrefixT, ExtraMetadata>
#define RecyclingTrie_DECL RecyclingTrie<ValueType, PrefixT, ExtraMetadata>

ATN_TEMPLATE
int32_t 
ATN_DECL ::size() const {
	return metadata.size_;
	//return size_.load(std::memory_order_relaxed);
}

ATN_TEMPLATE
template<typename InsertFn, typename InsertedValueType>
ATN_DECL::metadata_t 
ATN_DECL::insert(prefix_t const& key, InsertedValueType&& leaf_value, allocation_context_t& allocator) {

	invalidate_hash();

	auto prefix_match_len = get_prefix_match_len(key);

	//log("start init: ", allocator);

	if (children.size() == 1) {
		log("bad node", allocator);
		std::fflush(stdout);
		throw std::runtime_error("children size should never be 1 (account insert)");
	}

	if (children.empty() && !(prefix_len == MAX_KEY_LEN_BITS || prefix_len.len == 0)) {
		std::printf("what the actual fuck, prefix_len=%d, num children = %lu, max len = %u\n", prefix_len.len, children.size(), MAX_KEY_LEN_BITS.len);
		throw std::runtime_error("invalid initialization somewhere (account insert)");
	}

	if (prefix_len.len == 0 && children.empty()) {
		// dealing with initial node case

		//std::printf("setting initial value leaf\n");
		auto new_meta = set_as_value_leaf<InsertFn, InsertedValueType>(key, std::move(leaf_value), allocator);
		//log("post init:", allocator);

		return new_meta;
	}

	if (prefix_match_len == MAX_KEY_LEN_BITS) {
		//std::printf("overwrite value");

		//TODO faster impl here
		auto old_meta = metadata_t::from_value(children.value(allocator));

		InsertFn::value_insert(children.value(allocator), std::move(leaf_value));

		auto new_meta = metadata_t::from_value(children.value(allocator));
		set_metadata(new_meta);

		return new_meta - old_meta; // return 0
	}

	if (prefix_match_len == prefix_len) {
		auto branch_bits = get_branch_bits(key);

		auto iter = children.find(branch_bits);

		if (iter != children.end()) {
			auto& child = allocator.get_object((*iter).second);
			auto meta_delta = child.template insert<InsertFn, InsertedValueType>(key, std::move(leaf_value), allocator);
			//alter_size(sz_delta);
			alter_metadata(meta_delta);
			return meta_delta;
		} else {

			//auto [new_child, new_child_ptr] = allocator.allocate_pair();
			//auto new_child_ptr = allocator.allocate();
			//auto& new_child = allocator.get_object(new_child_ptr);

			auto& new_child = children.init_new_child(branch_bits, allocator);
			
			auto new_meta = new_child.template set_as_value_leaf<InsertFn, InsertedValueType>(key, std::move(leaf_value), allocator);
			alter_metadata(new_meta);
			//alter_size(1);
			//children.emplace(branch_bits, new_child_ptr);
			return new_meta;
		}
	}

	auto original_contents = extract_contents();

	//children_map_t original_children = std::move(children);
	children.reset_map(allocator);

	//auto original_prefix_len = prefix_len;

	prefix_len = prefix_match_len;
	auto new_child_branch = get_branch_bits(key);
	auto old_child_branch = get_branch_bits(prefix);

	//auto original_child_ptr = allocator.allocate();
	//auto& original_child = allocator.get_object(original_child_ptr);

	auto& original_child = children.init_new_child(old_child_branch, allocator);

	original_child.set_from_contents(original_contents);//steal_other_node_contents(std::move(original_children), prefix, original_prefix_len, metadata /* size() */);

	//auto new_child_ptr = allocator.allocate();
	auto& new_child = children.init_new_child(new_child_branch, allocator);//d allocator.get_object(new_child_ptr);

	//auto new_child_meta = metadata_t::from_value(leaf_value);

	auto new_child_meta = new_child.template set_as_value_leaf<InsertFn, InsertedValueType>(key, std::move(leaf_value), allocator);



//	children.emplace(new_child_branch, new_child_ptr);
//	children.emplace(old_child_branch, original_child_ptr);

	prefix.truncate(prefix_len);
	alter_metadata(new_child_meta);
	//alter_size(1);
	return new_child_meta; // return 1;
}

constexpr static bool USE_DIGEST_BUFFER = true;

template <typename ValueType, typename prefix_t>
static void 
compute_hash_value_node_v2(
	Hash& hash_buf, 
	const prefix_t prefix,
	const PrefixLenBits prefix_len, 
	ValueType& value, 
	std::vector<unsigned char>& digest_bytes) {

	//std::vector<unsigned char> digest_bytes;
	if (!USE_DIGEST_BUFFER) {
		std::vector<unsigned char>().swap(digest_bytes); // clear mem
	} else {
		digest_bytes.clear();
	}

	write_node_header(digest_bytes, prefix, prefix_len);
	value.copy_data(digest_bytes);

	if (crypto_generichash(hash_buf.data(), hash_buf.size(), digest_bytes.data(), digest_bytes.size(), NULL, 0) != 0) {
		throw std::runtime_error("error from crypto_generichash");
	}


}

template<typename Map, typename prefix_t, uint8_t BRANCH_BITS, typename allocator_t, typename... ApplyToValueBeforeHashFn>
static void
compute_hash_branch_node_v2(
	Hash& hash_buf, 
	const prefix_t prefix, 
	const PrefixLenBits prefix_len, 
	const Map& children, 
	const allocator_t& allocator,
	std::vector<unsigned char>& digest_bytes) {
	
	//int num_header_bytes = get_header_bytes(prefix_len);
	using bv_t = typename Map::bv_t;

	bv_t bv;
	for (auto iter = children.begin(); iter != children.end(); iter++) {
		bv.add((*iter).first);
		if (!(*iter).second) {
			throw std::runtime_error("can't recurse hash down null ptr");
		}
		allocator.get_object((*iter).second).template compute_hash<ApplyToValueBeforeHashFn...>(allocator, digest_bytes);

	}
	//uint8_t num_children = children.size();

	if (!USE_DIGEST_BUFFER) {
		std::vector<unsigned char>().swap(digest_bytes); // clear mem
	} else {
		digest_bytes.clear();
	}

	write_node_header(digest_bytes, prefix, prefix_len);

	bv.write(digest_bytes);

	//iter goes in increasing order
	for (auto iter = children.begin(); iter != children.end(); iter++) {
		allocator.get_object((*iter).second).append_hash_to_vec(digest_bytes);
	}

	if (crypto_generichash(hash_buf.data(), hash_buf.size(), digest_bytes.data(), digest_bytes.size(), NULL, 0) != 0) {
		throw std::runtime_error("error from crypto_generichash");
	}
	
}

ATN_TEMPLATE
template<typename... ApplyToValueBeforeHashFn>
void 
ATN_DECL::compute_hash(const allocator_t& allocator, std::vector<unsigned char>& digest_bytes) {
	auto hash_is_valid = get_hash_valid();

	if (hash_is_valid) return;

	if (children.empty()) {
		auto& value = children.value(allocator);
		(ApplyToValueBeforeHashFn::apply_to_value(value),...);
		compute_hash_value_node_v2(hash, prefix, prefix_len, value, digest_bytes);
	} else {
		compute_hash_branch_node_v2<children_map_t, prefix_t, BRANCH_BITS, allocator_t, ApplyToValueBeforeHashFn...>(
			hash, prefix, prefix_len, children, allocator, digest_bytes); 
	}

	validate_hash();
}

ATN_TEMPLATE
template<typename MergeFn>
ATN_DECL::metadata_t 
ATN_DECL::merge_in(ptr_t node, allocation_context_t& allocator) {

	auto lock_guard = lock();
	invalidate_hash();

	if (allocator.get_object(node).check_stolen()) {
		std::printf("bad node: %x\n", node);
		std::fflush(stdout);
		throw std::runtime_error("thing being merged in can't have been stolen!");
	}

	auto stolen_check = children.check_stolen();
	if (stolen_check) {
		throw std::runtime_error("shoudln't have stolen check");
		auto& real_addr = allocator.get_object(*stolen_check);
		return real_addr.template merge_in<MergeFn>(node, allocator);
	}
	
	auto& other = allocator.get_object(node);

	auto prefix_match_len = get_prefix_match_len(other.prefix, other.prefix_len);

/*	std::printf("merge current %s (%lu) input %s (%lu) (match: %lu)\n", 
		prefix.to_string(prefix_len).c_str(),
		prefix_len.len,
		other.prefix.to_string(other.prefix_len).c_str(),
		other.prefix_len.len,
		prefix_match_len.len);
*/
	// case 0
	if (prefix_match_len == MAX_KEY_LEN_BITS) {
//		std::printf("case 0\n");
		//log("preval", allocator);
		MergeFn::value_merge(children.value(allocator), other.children.value(allocator));
		return metadata_t::zero();
	}

	//case 1
	if (prefix_len == other.prefix_len && prefix_len == prefix_match_len) {
		//int32_t sz_delta = 0;

		metadata_t meta_delta = metadata_t::zero();

//		std::printf("case 1\n");
		for (auto other_iter = other.children.begin(); other_iter != other.children.end(); other_iter++) {
			auto main_iter = children.find((*other_iter).first);

			auto other_ptr = other.children.extract((*other_iter).first);
			auto& other_ref = allocator.get_object(other_ptr);

			if (main_iter == children.end()) {

				meta_delta += other_ref.metadata;

				//sz_delta += other_ref.size();
				children.emplace((*other_iter).first, other_ptr, allocator);
			} else {

				auto& main_child = allocator.get_object((*main_iter).second);
				//sz_delta += main_child.template merge_in<MergeFn>(other_ptr, allocator);
				meta_delta += main_child.template merge_in<MergeFn>(other_ptr, allocator);


			}
		}
		//alter_size(sz_delta);
		alter_metadata(meta_delta);
		return meta_delta;
	}

	// case 2

	if (prefix_len == prefix_match_len /* thus other.prefix_len > prefix_match_len */ ) {
		auto bb = get_branch_bits(other.prefix);
//		std::printf("case 2\n");
		auto iter = children.find(bb);
		if (iter == children.end()) {
			//auto sz_delta = other.size();
			auto meta_delta = other.metadata;
			children.emplace(bb, node, allocator);
			//alter_size(sz_delta);
			alter_metadata(meta_delta);
			return meta_delta;
		}

		auto child_ptr = (*iter).second;
		auto& child = allocator.get_object(child_ptr);

		auto meta_delta = child.template merge_in<MergeFn>(node, allocator);
		alter_metadata(meta_delta);
		return meta_delta;
	}

	// case 3

	if (other.prefix_len == prefix_match_len /* thus prefix_len > prefix_match_len */ ) {
		//auto original_sz = size();
		//auto other_sz = other.size();

		auto original_metadata = metadata;
		auto other_metadata = other.metadata;

		auto original_contents = extract_contents();
		//auto original_children = std::move(children);
		//auto original_prefix_len = prefix_len;
		//auto original_prefix = prefix;



		children = std::move(other.children);
		other.children.clear();

		prefix_len = other.prefix_len;
		auto original_child_branch_bits = get_branch_bits(prefix);
		prefix = other.prefix;
		set_metadata(other_metadata);
		//set_size(other_sz);


		auto iter = children.find(original_child_branch_bits);

		if (iter == children.end()) {
			// case 3 no recursion
			auto& new_child = children.init_new_child(original_child_branch_bits, allocator);

			new_child.set_from_contents(original_contents);// steal_other_node_contents(std::move(original_children), original_prefix, original_prefix_len, original_sz);
			
			original_metadata += other_metadata;
			set_metadata(original_metadata);//other_metadata + original_metadata);
			//set_size(other_sz + original_sz);
			//alter_size(original_sz);
			// return other_sz;
			return other_metadata;
		} else {
			// case 3 recursion

			auto matching_subtree_of_other_ptr = children[original_child_branch_bits];
			auto& matching_subtree_of_other = allocator.get_object(matching_subtree_of_other_ptr);

			auto matching_subtree_meta = matching_subtree_of_other.metadata;
			//auto matching_subtree_sz = matching_subtree_of_other.size();

			auto matching_subtree_contents = matching_subtree_of_other.extract_contents();
			matching_subtree_of_other.set_from_contents(original_contents);

			auto temp_ptr = allocator.init_root_node();
			auto& temp_obj = allocator.get_object(temp_ptr);
			temp_obj.set_from_contents(matching_subtree_contents);

			matching_subtree_of_other.template merge_in<MergeFn>(temp_ptr, allocator);

			auto new_matching_subtree_meta = matching_subtree_of_other.metadata;
			//auto new_matching_subtree_sz = matching_subtree_of_other.size();
			auto meta_delta = new_matching_subtree_meta - matching_subtree_meta;
			//auto sz_delta = new_matching_subtree_sz - matching_subtree_sz;
			alter_metadata(meta_delta);
			//alter_size(sz_delta);
			return metadata - original_metadata;
		//	return (size() - original_sz);
		}
	} /* end case 3 */

	// case 4
//	std::printf("case 4\n");
	/* other.prefix_len > prefix_match_len and prefix_len > prefix_match_len */

	auto original_contents = extract_contents();
	children.reset_map(allocator);

	prefix_len = prefix_match_len;

	auto new_child_branch = get_branch_bits(other.prefix);
	auto old_child_branch = get_branch_bits(prefix);

	//auto original_child_ptr = allocator.allocate();
	//auto& original_child = allocator.get_object(original_child_ptr);

	auto& original_child = children.init_new_child(old_child_branch, allocator);

	original_child.set_from_contents(original_contents);



	children.emplace(new_child_branch, node, allocator);

	auto& new_child = allocator.get_object(children[new_child_branch]);
	auto meta_delta = new_child.metadata;
	//auto sz_delta = new_child.size();
	//alter_size(sz_delta);
	alter_metadata(meta_delta);
	prefix.truncate(prefix_len);
	//return sz_delta;
	return meta_delta;
}







//RecyclingTrie

ATN_TEMPLATE
template<typename... ApplyFn>
void 
RecyclingTrie_DECL::hash(Hash& output_hash) {
	std::lock_guard lock(mtx);

	constexpr static size_t default_digest_buffer_sz = 16 * 32 + 32; // actually its 16 * 32 + 14, but this rounds up just a bit in case its necessary

	if (check_hash_valid()) {
		output_hash = root_hash;
		return;
	}

	if (root != UINT32_MAX) {
	
		// It seems to perform substantially faster to just allocate a vector on the stack,
		// rather than fetching a vector from a threadlocal cache.
		tbb::parallel_for(
			AccountHashRange<node_t>(root, allocator),
			[this] (const auto& r) {
				std::vector<unsigned char> digest_buffer;
				digest_buffer.reserve(default_digest_buffer_sz);
				for (size_t i = 0; i < r.num_nodes(); i++) {
					r[i].template compute_hash<ApplyFn...>(allocator, digest_buffer);
				}
			});
		
		std::vector<unsigned char> digest_buffer;
		digest_buffer.reserve(default_digest_buffer_sz);

		allocator.get_object(root).template compute_hash<ApplyFn...>(allocator, digest_buffer);

		get_root_hash(root_hash);
	} else {
		root_hash = Hash{};
	}

	output_hash = root_hash;

	validate_hash();

}

ATN_TEMPLATE
void 
RecyclingTrie_DECL ::get_root_hash(Hash& out) {

	if (root == UINT32_MAX) {
		throw std::runtime_error("can't hash null root!");
	}

	auto& root_obj = allocator.get_object(root);
	// the one method where size() is called without a mutex held
	// in that same method.
	// only call site is within hash, which grabs a mutex on the whole thing
	uint32_t sz = root_obj.size();

	constexpr size_t buf_sz = 4 + 32;
	std::array<unsigned char, buf_sz> buf;
	buf.fill(0);

	utils::write_unsigned_big_endian(buf, sz);

	if (sz > 0) {
		root_obj.copy_hash_to_buf(buf.data() + 4);
	}

	if (crypto_generichash(
		root_hash.data(), root_hash.size(),
		buf.data(), buf.size(),
		NULL, 0) != 0) {
		throw std::runtime_error("crypto_generichash error");
	}

	validate_hash();

	out = root_hash;
}

ATN_TEMPLATE
template<typename VectorType>
VectorType
RecyclingTrie_DECL::accumulate_values_parallel() const {
	VectorType output;
	accumulate_values_parallel(output);
	return output;
} 

ATN_TEMPLATE
template<typename VectorType>
void  
RecyclingTrie_DECL ::accumulate_values_parallel(VectorType& output) const {

	std::lock_guard lock(mtx);

	if (size() == 0) return;

	AccountAccumulateValuesRange<node_t> range(root, allocator);

	output.resize(size());

	tbb::parallel_for(
		range,
		[&output, this] (const auto& range) {
			auto vector_offset = range.vector_offset;
			for (size_t i = 0; i < range.work_list.size(); i++) {
				auto& work_node = allocator.get_object(range.work_list[i]);
				work_node.accumulate_values_parallel_worker(output, vector_offset, allocator);
				vector_offset += work_node.size();
			}
		});
}
ATN_TEMPLATE
template<typename VectorType>
void  
RecyclingTrie_DECL::accumulate_keys_parallel(VectorType& output) const {

	std::lock_guard lock(mtx);

	if (size() == 0) return;

	AccountAccumulateValuesRange<node_t> range(root, allocator);

	output.resize(size());

	tbb::parallel_for(
		range,
		[&output, this] (const auto& range) {
			auto vector_offset = range.vector_offset;
			for (size_t i = 0; i < range.work_list.size(); i++) {
				auto& work_node = allocator.get_object(range.work_list[i]);
				work_node.accumulate_keys_parallel_worker(output, vector_offset, allocator);
				vector_offset += work_node.size();
			}
		});
}


ATN_TEMPLATE
template<typename VectorType>
void 
ATN_DECL ::accumulate_values_parallel_worker(VectorType& output, size_t vector_offset, const allocator_t& allocator) const {
	if (prefix_len == MAX_KEY_LEN_BITS) {
		output[vector_offset] = children.value(allocator);
		return;
	}

	for (auto iter = children.begin(); iter != children.end(); iter++) {
		auto& ref = allocator.get_object((*iter).second);
		ref.accumulate_values_parallel_worker(output, vector_offset, allocator);
		vector_offset += ref.size();
	}
}

ATN_TEMPLATE
template<typename VectorType>
void 
ATN_DECL ::accumulate_keys_parallel_worker(VectorType& output, size_t vector_offset, const allocator_t& allocator) const {
	if (prefix_len == MAX_KEY_LEN_BITS) {
		output[vector_offset] = prefix.uint64();
		return;
	}

	for (auto iter = children.begin(); iter != children.end(); iter++) {
		auto& ref = allocator.get_object((*iter).second);
		ref.accumulate_keys_parallel_worker(output, vector_offset, allocator);
		vector_offset += ref.size();
	}
}

ATN_TEMPLATE
std::tuple<bool, typename ATN_DECL::metadata_t, PtrWrapper>
ATN_DECL::destructive_steal_child(const prefix_t& stealing_prefix, const PrefixLenBits stealing_prefix_len, allocation_context_t& allocator) {
	auto lk = lock();

	auto prefix_match_len = get_prefix_match_len(stealing_prefix, stealing_prefix_len);
	if (prefix_match_len == stealing_prefix_len) {
		return std::tuple(true, metadata, PtrWrapper::make_nullptr());
	}

	if (prefix_match_len == prefix_len) {
		auto bb = get_branch_bits(stealing_prefix);

		auto iter = children.find(bb);
		if (iter == children.end()) {
			return {false, metadata_t::zero(), PtrWrapper::make_nullptr()};
		}

		auto [do_steal_entire_subtree, meta_delta, ptr] = allocator.get_object((*iter).second).destructive_steal_child(stealing_prefix, stealing_prefix_len, allocator);

		if (do_steal_entire_subtree) {
			alter_metadata(-meta_delta);

			auto new_ptr = allocator.allocate(1);
			auto& new_node = allocator.get_object(new_ptr);
			new_node.set_as_empty_node();
			auto old_ptr = children.extract(bb); // == (*iter).second
			auto& old_ptr_ref = allocator.get_object(old_ptr);
			auto old_contents = old_ptr_ref.extract_contents();
			new_node.set_from_contents(old_contents);

			return {false, meta_delta, PtrWrapper{new_ptr}};
		} else {
			if (ptr.non_null()) {
				alter_metadata(-meta_delta);
				//alter_size(-sz_delta);
				return {false, meta_delta, ptr};
			} else {
				return {false, metadata_t::zero(), PtrWrapper::make_nullptr()};
			}
		}
	}

	return {false, metadata_t::zero(), PtrWrapper::make_nullptr()};
}

#undef ATN_TEMPLATE
#undef ATN_DECL
#undef RecyclingTrie_DECL

} /* trie */

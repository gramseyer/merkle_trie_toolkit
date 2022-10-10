#pragma once

#include <cstdint>
#include <memory>
#include <shared_mutex>
#include <variant>
#include <vector>

/*! \file utils.h 

Miscellaneous classes used in trie management.

*/

namespace trie {

struct EmptyValue {

	constexpr static void copy_data(std::vector<uint8_t>& buf) {}
};

template<typename T>
static 
std::vector<uint8_t> no_serialization_fn(const T&)
{
	return {};
}

template<typename V, auto f>
struct PointerValue {
	// for values that can't be moved
	std::unique_ptr<V> v;

	PointerValue() : v(nullptr) {}

	PointerValue(std::unique_ptr<V>&& val)
		: v(std::move(val))
		{}

	void copy_data(std::vector<uint8_t>& buf) const {
		auto res = f(*v);
		buf.insert(buf.end(), res.begin(), res.end());
	}
};

template<typename V, auto serialize_fn>
struct SerializeWrapper : public V
{
	SerializeWrapper(const V& v)
		: V(v)
		{}

	SerializeWrapper(V&& v)
		: V(std::move(v))
		{}

	SerializeWrapper()
		: V()
		{}

	bool operator==(const SerializeWrapper& other) const = default;

	void copy_data(std::vector<uint8_t>& buf) const
	{
		auto serialization = serialize_fn(*this);
		buf.insert(buf.end(), serialization.begin(), serialization.end());
	}
};

template<typename xdr_type, auto serialize_fn>
struct XdrTypeWrapper : public xdr_type {

	XdrTypeWrapper() 
		: xdr_type()
		{}

	XdrTypeWrapper(const xdr_type& x) 
		: xdr_type(x)
       	{}

	XdrTypeWrapper& operator=(const XdrTypeWrapper& other) {
		xdr_type::operator=(other);
		return *this;
	}

	XdrTypeWrapper(const XdrTypeWrapper& other)
	: xdr_type()
	{
		xdr_type::operator=(other);
	}

	void copy_data(std::vector<uint8_t>& buf) const {
		auto serialization = serialize_fn(*this);//xdr::xdr_to_opaque(static_cast<xdr_type>(*this));
		buf.insert(buf.end(), serialization.begin(), serialization.end());
	}
};

//F is function to map prefix to KeyInterpretationType
template<typename MetadataOutputType, typename KeyInterpretationType, typename KeyMakerF>
struct IndexedMetadata {
	KeyInterpretationType key;
	MetadataOutputType metadata;

	IndexedMetadata(KeyInterpretationType key, MetadataOutputType metadata) :
			key(key),
			metadata (metadata) {}
};

//! Base functions for inserting values into a trie.  
//! Override to do nondefault things when inserting new values.
template<typename ValueType>
struct GenericInsertFn {
	template<typename MetadataType>
	static MetadataType new_metadata(const ValueType& value) {
		return MetadataType(value);
	}

	template<typename prefix_t>
	static ValueType new_value(const prefix_t& prefix) {
		return ValueType{};
	}
};

struct NoDuplicateKeysMergeFn
{
	template<typename ValueType>
	static void value_merge(ValueType& main_value, const ValueType& other_value) {
		throw std::runtime_error("no duplicate keys allowed");
	}

	template<typename AtomicMetadataType>
	static typename AtomicMetadataType::BaseT 
	metadata_merge(AtomicMetadataType& main_metadata, const AtomicMetadataType& other_metadata) {
		throw std::runtime_error("no duplicate keys allowed");
	}
};

//can call unsafe methods bc exclusive locks on metadata inputs in caller
struct OverwriteMergeFn {
	template<typename ValueType>
	static void value_merge(ValueType& main_value, const ValueType& other_value) {
		main_value = other_value;
	}

	template<typename MetadataType, typename ValueType>
	static
	MetadataType value_merge_recyclingimpl(ValueType& main_value, const ValueType& other_value) {
		main_value = other_value;
		return MetadataType::zero();
	}

	template<typename AtomicMetadataType>
	static typename AtomicMetadataType::BaseT 
	metadata_merge(AtomicMetadataType& main_metadata, const AtomicMetadataType& other_metadata) {

		//return other - main, set main <- delta
		auto other_metadata_loaded = other_metadata.unsafe_load();
		auto original_main_metadata = main_metadata.unsafe_load();
		main_metadata.unsafe_store(other_metadata_loaded);

		other_metadata_loaded -= original_main_metadata;
		return other_metadata_loaded;
	}
};

//can call unsafe methods bc excl locks on metadata inputs in caller
//! Overwrite previous value when inserting new value into a trie.
template<typename ValueType>
struct OverwriteInsertFn : public GenericInsertFn<ValueType> {

	static void 
	value_insert(ValueType& main_value, ValueType&& other_value) {
		main_value = std::move(other_value);
	}

	template<typename AtomicMetadataType>
	static typename AtomicMetadataType::BaseT 
	metadata_insert(AtomicMetadataType& original_metadata, const ValueType& new_value) {

		//return other - main, set main <- delta
		auto new_metadata = typename AtomicMetadataType::BaseT(new_value);
		auto metadata_delta = new_metadata;
		metadata_delta -= original_metadata.unsafe_substitute(new_metadata);
		return metadata_delta;
	}
};

template<typename ValueType>
struct RollbackInsertFn : public OverwriteInsertFn<ValueType> {
	template<typename MetadataType>
	static MetadataType new_metadata(const ValueType& value) {
		auto out = MetadataType(value);
		out.num_rollback_subnodes = 1;
		return out;
	}


	template<typename AtomicMetadataType>
	static typename AtomicMetadataType::BaseT 
	metadata_insert(AtomicMetadataType& original_metadata, const ValueType& new_value) {

		//return other - main, set main <- delta
		auto new_metadata = typename AtomicMetadataType::BaseT(new_value);
		new_metadata.num_rollback_subnodes = 1;
		
		auto metadata_delta = new_metadata;
		metadata_delta -= original_metadata.unsafe_substitute(new_metadata);
		return metadata_delta;
	}
};

struct NullOpDelSideEffectFn {
	template<typename ...Args>
	void operator() (const Args&... args) {}
};

struct
DefaultAccumulateValuesFn
{
	template<typename VectorType, typename ValueType>
	static void
	accumulate(VectorType& vector, size_t vector_offset, const ValueType& value)
	{
		vector[vector_offset] = value;
	}

	template<typename MetadataType>
	static size_t size_increment(const MetadataType& metadata)
	{
		return metadata.size_;
	}

	template<typename MetadataType>
	static size_t vector_size(const MetadataType& root_metadata)
	{
		return root_metadata.size_;
	}
};

/*! Template class that optionally wraps a mutex.
When SERIAL_MODE = true, class contains a rwlock.  
Methods that need shared locks
can be used (i.e. parallel_insert)
When SERIAL_MODE = false, class is empty.
*/
template<
	bool SERIAL_MODE>
class OptionalLock {
};

template<>
class OptionalLock<true> {

	mutable std::shared_mutex mtx;


public:
	OptionalLock() 
		: mtx() {}

	template<typename lock_type>
	lock_type lock() const {
		mtx.lock();
		return {mtx, std::adopt_lock};
	}

	std::unique_ptr<std::lock_guard<std::shared_mutex>>
	get_lock_ptr() const {
		return std::make_unique<std::lock_guard<std::shared_mutex>>(mtx);
	}

};

template<>
class OptionalLock<false> {

public:
	OptionalLock() {}

	template<typename lock_type>
	std::monostate lock() const {
		return std::monostate{};
	}

};

} /* trie */

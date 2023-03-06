#pragma once

namespace trie
{

//! Base functions for inserting values into a trie.  
//! Override to do nondefault things when inserting new values.
template<typename ValueType>
struct GenericInsertFn {

	template<typename prefix_t>
	static ValueType new_value(const prefix_t& prefix) {
		return ValueType{};
	}

	template<typename MetadataType>
	static MetadataType new_metadata(const ValueType& value) {
		return MetadataType(value);
	}
};

//! Overwrite previous value when inserting new value into a trie.
template<typename ValueType>
struct OverwriteInsertFn : public GenericInsertFn<ValueType> {

	static void 
	value_insert(ValueType& main_value, ValueType&& other_value) {
		main_value = std::move(other_value);
	}

	// relevant only for base trie implementation with metadata
	// can call unsafe methods bc excl locks on metadata inputs in caller
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

}

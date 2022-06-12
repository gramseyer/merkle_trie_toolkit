#pragma once

#include <cstdint>

namespace trie
{

/** Note for MergeFn:
 * It should be the case that if two values are 
 * merged together, the resulting metadata
 * is the sum of the metadatas of the original
 * two values.
 * 
 * If this is ever not the case,
 * then case 0 of merge_in
 * and insert (full prefix match case)
 * should be modified so that merge_values
 * returns the delta of adding adding metadata together
 * (and that result needs to get passed up through the rest of
 * merge_in).  Care would need to be taken to ensure
 * commutativity.
 */

template<typename ExtraMetadata>
struct RecyclingTrieNodeMetadata
{
	int32_t size_ = 0;
	ExtraMetadata metadata;

	bool operator==(const RecyclingTrieNodeMetadata& other) const = default;

	RecyclingTrieNodeMetadata& 
	operator+=(const RecyclingTrieNodeMetadata& other)
	{
		size_ += other.size_;
		metadata += other.metadata;
		return *this;
	}

	friend RecyclingTrieNodeMetadata operator-(
		RecyclingTrieNodeMetadata lhs, 
		RecyclingTrieNodeMetadata const& rhs)
	{
		lhs.size_ -= rhs.size_;
		lhs.metadata += (-rhs.metadata);
		return lhs;
	}

	RecyclingTrieNodeMetadata 
	operator-() const
	{
		return RecyclingTrieNodeMetadata
		{
			.size_ = -this->size_,
			.metadata = -this->metadata
		};
	}

	constexpr static RecyclingTrieNodeMetadata zero();

	template<typename ValueT>
	static RecyclingTrieNodeMetadata
	from_value(ValueT const& val);
};

template<typename ExtraMetadata>
constexpr RecyclingTrieNodeMetadata<ExtraMetadata>
RecyclingTrieNodeMetadata<ExtraMetadata>::zero()
{
	return RecyclingTrieNodeMetadata<ExtraMetadata>{
		.size_ = 0,
		.metadata = ExtraMetadata::zero()
	};
}

template<typename ExtraMetadata>
template<typename ValueT>
RecyclingTrieNodeMetadata<ExtraMetadata>
RecyclingTrieNodeMetadata<ExtraMetadata>::from_value(ValueT const& val)
{
	return RecyclingTrieNodeMetadata<ExtraMetadata> {
		.size_ = 1,
		.metadata = ExtraMetadata::from_value(val)
	};
}


template<>
struct RecyclingTrieNodeMetadata<void>
{
	int32_t size_ = 0;

	RecyclingTrieNodeMetadata& 
	operator+=(const RecyclingTrieNodeMetadata& other)
	{
		size_ += other.size_;
		return *this;
	}

	friend RecyclingTrieNodeMetadata operator-(
		RecyclingTrieNodeMetadata lhs, 
		RecyclingTrieNodeMetadata const& rhs)
	{
		lhs.size_ -= rhs.size_;
		return lhs;
	}

	RecyclingTrieNodeMetadata operator-()
	{
		return RecyclingTrieNodeMetadata
		{
			.size_ = -this->size_
		};
	}

	constexpr static RecyclingTrieNodeMetadata zero();

	template<typename ValueT>
	static RecyclingTrieNodeMetadata
	from_value(ValueT const& val);
};


constexpr RecyclingTrieNodeMetadata<void>
RecyclingTrieNodeMetadata<void>::zero()
{
	return RecyclingTrieNodeMetadata<void>{
		.size_ = 0
	};
}

template<typename ValueT>
RecyclingTrieNodeMetadata<void>
RecyclingTrieNodeMetadata<void>::from_value(ValueT const& [[maybe_unused]] val)
{
	return RecyclingTrieNodeMetadata<void> {
		.size_ = 1
	};
}


} /* trie */

#pragma once

#include <cstdint>

namespace trie {

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

/*
// from https://stackoverflow.com/questions/38797130/portable-way-to-check-if-expression-compiles
template<typename T>
struct HasVariableAccumulateSize
{
    template<typename U>
    static decltype(std::declval<U>().accumulator_size, std::true_type{}) func (std::remove_reference_t<U>*);
    template<typename U>
    static std::false_type func(...);

    using type = decltype(func<T>(nullptr));

    static constexpr bool value = type::value;
};

template<typename... Extensions>
struct CombinedExtraMetadata : public Extensions...
{
    bool operator==(const CombinedExtraMetadata& other) const = default;

    CombinedExtraMetadata& operator+=(
        const CombinedExtraMetadata& other)
    {
        (Extensions::operator+=(other)...);
    }

    friend CombinedExtraMetadata operator-(
        CombinedExtraMetadata lhs,
        CombinedExtraMetadata const& rhs)
    {
        lhs += (-rhs);
        return lhs;
    }

    CombinedExtraMetadata operator-() const
    {
        return (Extensions::operator-(*this)...);
    }

    constexpr static CombineExtraMetadata zero() 
    {
        return CombinedExtraMetadata();
    }

    template<typename ValueType>
    static CombinedExtraMetadata from_value(ValueType const& v)
    {
        return CombinedExtraMetadata(v);
    }

private:

    CombinedExtraMetadata()
        : Extensions...()
        {}

    template<typename ValueType>
    CombinedExtraMetadata(ValueType const& v)
        : Extensions...(v)
        {}
} */

template<typename ExtraMetadata>
struct RecyclingTrieNodeMetadata
{
    int32_t size_ = 0;
    ExtraMetadata metadata;

    bool operator==(const RecyclingTrieNodeMetadata& other) const = default;

    RecyclingTrieNodeMetadata& operator+=(
        const RecyclingTrieNodeMetadata& other)
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

    RecyclingTrieNodeMetadata operator-() const
    {
        return RecyclingTrieNodeMetadata{ .size_ = -this->size_,
                                          .metadata = -this->metadata };
    }

    constexpr static RecyclingTrieNodeMetadata zero();

    template<typename ValueT>
    static RecyclingTrieNodeMetadata from_value(ValueT const& val);

	std::string to_string() const
	{
		return std::string("size: ") + std::to_string(size_) + metadata.to_string();
	}
};

template<typename ExtraMetadata>
constexpr RecyclingTrieNodeMetadata<ExtraMetadata>
RecyclingTrieNodeMetadata<ExtraMetadata>::zero()
{
    return RecyclingTrieNodeMetadata<ExtraMetadata>{ .size_ = 0,
                                                     .metadata
                                                     = ExtraMetadata::zero() };
}

template<typename ExtraMetadata>
template<typename ValueT>
RecyclingTrieNodeMetadata<ExtraMetadata>
RecyclingTrieNodeMetadata<ExtraMetadata>::from_value(ValueT const& val)
{
    return RecyclingTrieNodeMetadata<ExtraMetadata>{
        .size_ = 1, .metadata = ExtraMetadata::from_value(val)
    };
}

template<>
struct RecyclingTrieNodeMetadata<void>
{
    int32_t size_ = 0;

    RecyclingTrieNodeMetadata& operator+=(
        const RecyclingTrieNodeMetadata& other)
    {
        size_ += other.size_;
        return *this;
    }

    bool operator==(const RecyclingTrieNodeMetadata& other) const = default;


    friend RecyclingTrieNodeMetadata operator-(
        RecyclingTrieNodeMetadata lhs,
        RecyclingTrieNodeMetadata const& rhs)
    {
        lhs.size_ -= rhs.size_;
        return lhs;
    }

    RecyclingTrieNodeMetadata operator-()
    {
        return RecyclingTrieNodeMetadata{ .size_ = -this->size_ };
    }

    constexpr static RecyclingTrieNodeMetadata zero();

    template<typename ValueT>
    static RecyclingTrieNodeMetadata from_value(ValueT const& val);

    std::string to_string() const
    {
    	return std::string("size: ") + std::to_string(size_);
    }
};

constexpr RecyclingTrieNodeMetadata<void>
RecyclingTrieNodeMetadata<void>::zero()
{
    return RecyclingTrieNodeMetadata<void>{ .size_ = 0 };
}

template<typename ValueT>
RecyclingTrieNodeMetadata<void>
RecyclingTrieNodeMetadata<void>::from_value(ValueT const&)
{
    return RecyclingTrieNodeMetadata<void>{ .size_ = 1 };
}

} // namespace trie

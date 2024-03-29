#pragma once

#include <cstdint>

namespace trie
{
namespace test
{

struct RecyclingMetadata
{
	int32_t value_acc = 0;

	bool operator==(const RecyclingMetadata& other) const = default;

	RecyclingMetadata& 
	operator+=(const RecyclingMetadata& other)
	{
		value_acc += other.value_acc;
		return *this;
	}

	friend RecyclingMetadata operator-(
		RecyclingMetadata lhs, 
		RecyclingMetadata const& rhs)
	{
		lhs.value_acc -= rhs.value_acc;
		return lhs;
	}

	RecyclingMetadata 
	operator-() const
	{
		return RecyclingMetadata
		{
			.value_acc = -this->value_acc
		};
	}

	constexpr static RecyclingMetadata zero()
	{
		return RecyclingMetadata{
			.value_acc = 0
		};
	}

	static 
	RecyclingMetadata
	from_value(int32_t const& val)
	{
		return RecyclingMetadata {
			.value_acc = val
		};
	}
	std::string to_string() const
	{
		return std::string("value_acc: ") + std::to_string(value_acc);
	}
};

} /* test */
} /* trie */

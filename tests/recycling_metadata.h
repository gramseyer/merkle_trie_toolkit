#pragma once

#include <cstdint>

namespace trie
{
namespace test
{

struct RecyclingMetadata
{
	int32_t value_acc = 0;

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
};

} /* test */
} /* trie */

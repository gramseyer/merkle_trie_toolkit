#pragma once

#include <cstdint>
#include <memory>
#include <shared_mutex>
#include <variant>
#include <vector>

/*! \file utils.h 

Miscellaneous classes for trie data structures.

*/

namespace trie {

struct EmptyValue {

	// used when hashing tries
	constexpr static void copy_data(std::vector<uint8_t>& buf) {}

	EmptyValue() = default;

	void from_bytes(std::vector<uint8_t> const& bytes) {}
};

template<typename V, auto serialize_fn>
struct SerializeWrapper : public V
{
	template<typename... args>
	SerializeWrapper(args... a) : V(a...) {}

	void copy_data(std::vector<uint8_t>& buf) const
	{
		auto serialization = serialize_fn(*this);
		buf.insert(buf.end(), serialization.begin(), serialization.end());
	}
};

template<typename V, auto serialize_fn>
struct BetterSerializeWrapper : public V
{
	template<typename... args>
	BetterSerializeWrapper(args... a) : V(a...) {}

	void copy_data(std::vector<uint8_t>& buf) const
	{
		serialize_fn(buf, *this);
	}
};

} 

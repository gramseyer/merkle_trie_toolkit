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

	template<typename... Args>
	EmptyValue(Args...) {}
};

template<typename V, auto serialize_fn>
struct SerializeWrapper : public V
{
	template<typename... args>
	SerializeWrapper(args... a) : V(a...) {}

	/*SerializeWrapper(const V& v)
		: V(v)
		{}

	SerializeWrapper(V&& v)
		: V(std::move(v))
		{}

	SerializeWrapper()
		: V()
		{} */

	void copy_data(std::vector<uint8_t>& buf) const
	{
		auto serialization = serialize_fn(*this);
		buf.insert(buf.end(), serialization.begin(), serialization.end());
	}
};

} 

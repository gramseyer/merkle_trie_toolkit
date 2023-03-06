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

	// used when hashing tries
	constexpr static void copy_data(std::vector<uint8_t>& buf) {}
};

} 
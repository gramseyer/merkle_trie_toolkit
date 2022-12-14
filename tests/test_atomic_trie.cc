#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "mtt/trie/debug_macros.h"
#include "mtt/trie/recycling_impl/atomic_trie.h"
#include "mtt/trie/utils.h"
#include "mtt/trie/types.h"

#include <utils/serialize_endian.h>
#include <utils/time.h>

#include <sodium.h>

#include <tbb/global_control.h>

#include "tests/recycling_metadata.h"

namespace trie
{

using namespace utils;

TEST_CASE("atomic trie emptyvalue small", "[atomic]")
{
	AtomicTrie<EmptyValue, UInt64Prefix> trie;

	auto alloc = trie.get_new_allocation_context();

	for (uint64_t i = 0; i < 1000; i++)
	{
		uint64_t query = (i * 17) % 6701;  //6701 is prime

		trie.insert(UInt64Prefix(query), EmptyValue{}, alloc);
	}

	REQUIRE(trie.deep_sizecheck() == 1000);

	for (uint64_t i = 0; i < 1000; i++)
	{
		uint64_t query = (i * 17) % 6701;  //6701 is prime

		trie.insert(UInt64Prefix(query), EmptyValue{}, alloc);
	}

	REQUIRE(trie.deep_sizecheck() == 1000);
}

} // namespace trie

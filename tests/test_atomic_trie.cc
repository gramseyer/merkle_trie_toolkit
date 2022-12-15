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
#include <utils/threadlocal_cache.h>

#include <tbb/global_control.h>
#include <tbb/parallel_for.h>

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
		uint64_t query = (i * 17) % 6701;

		trie.insert(UInt64Prefix(query), EmptyValue{}, alloc);
	}

	REQUIRE(trie.deep_sizecheck() == 1000);
}

TEST_CASE("parallel atomic trie insert", "[atomic]")
{
	using cache_t = utils::ThreadlocalCache<AtomicTrieReference<EmptyValue, UInt64Prefix>>;

	cache_t cache;

	AtomicTrie<EmptyValue, UInt64Prefix> trie;

	tbb::parallel_for(
		tbb::blocked_range<uint64_t>(0, 1000000),
		[&] (auto r) {
			auto& serial = cache.get(trie);

			for (auto i = r.begin(); i < r.end(); i++)
			{
				serial.insert(UInt64Prefix(i), EmptyValue{});
			}
			for (auto i = r.begin(); i < r.end(); i++)
			{
				serial.insert(UInt64Prefix(i), EmptyValue{});
			}

		});

	REQUIRE(trie.deep_sizecheck() == 1000000);
}

} // namespace trie

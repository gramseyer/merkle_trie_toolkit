#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "mtt/common/debug_macros.h"
#include "mtt/ephemeral_trie/atomic_ephemeral_trie.h"

#include "mtt/common/utils.h"
#include "mtt/trie/types.h"

#include <utils/serialize_endian.h>
#include <utils/time.h>
#include <utils/threadlocal_cache.h>

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

	using trie_t = AtomicTrie<EmptyValue, UInt64Prefix>;
	using cache_t = utils::ThreadlocalCache<AtomicTrieReference<trie_t>>;

	cache_t cache;

	trie_t trie;

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

TEST_CASE("hash", "[atomic]")
{
	AtomicTrie<EmptyValue, UInt64Prefix> trie;
	auto alloc = trie.get_new_allocation_context();

	for (uint64_t i = 0; i < 1000; i++)
	{
		uint64_t query = (i * 17) % 6701;  //6701 is prime

		trie.insert(UInt64Prefix(query), EmptyValue{}, alloc);
	}

	AtomicTrie<EmptyValue, UInt64Prefix> trie2;
	auto alloc2 = trie2.get_new_allocation_context();

	for (uint64_t i = 1000; i != 0; i--)
	{
		uint64_t query = ((i-1) * 17) % 6701;  //6701 is prime

		trie2.insert(UInt64Prefix(query), EmptyValue{}, alloc2);
	}
	SECTION("same")
	{
		REQUIRE(trie.hash_serial() == trie2.hash());
	}
	SECTION("different")
	{
		trie2.insert(UInt64Prefix((1000 * 17) % 6701), EmptyValue{}, alloc2);
		REQUIRE(trie.hash_serial() != trie2.hash());
	}
}

TEST_CASE("apply keys", "[atomic]")
{
	using trie_t = AtomicTrie<EmptyValue, UInt64Prefix>;
	trie_t trie;
	auto alloc = trie.get_new_allocation_context();

	trie.insert(UInt64Prefix(0x0000'0000'0000'0000), EmptyValue{}, alloc);
	trie.insert(UInt64Prefix(0x0000'0000'0000'0001), EmptyValue{}, alloc);
	trie.insert(UInt64Prefix(0x0000'0000'0000'0010), EmptyValue{}, alloc);
	trie.insert(UInt64Prefix(0x0000'0000'0000'0100), EmptyValue{}, alloc);
	trie.insert(UInt64Prefix(0x0000'0000'0000'1000), EmptyValue{}, alloc);

	uint64_t x = 0;
	auto lambda = [&] (trie_t::prefix_t const& prefix) {
		x++;
	};

	auto ref = trie.get_applyable_ref();

	ref.apply_to_keys(lambda, 64);
	REQUIRE(x == 5);

	x = 0;
	ref.apply_to_keys(lambda, 60);
	REQUIRE(x == 4);

	x = 0;
	ref.apply_to_keys(lambda, 56);
	REQUIRE(x == 3);

	x = 0;
	ref.apply_to_keys(lambda, 32);
	REQUIRE(x == 1);

	x = 0;
	ref.apply_to_keys(lambda, 0);
	REQUIRE(x == 1);
}

} // namespace trie

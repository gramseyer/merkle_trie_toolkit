#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "mtt/common/debug_macros.h"

#include "mtt/trie/recycling_impl/trie.h"
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

TEST_CASE("recycling trie emptyhash", "[recycling_trie]")
{
	RecyclingTrie<EmptyValue> trie;
	Hash hash;

	trie.hash(hash);

	RecyclingTrie<XdrTypeWrapper<Hash, &trie::hash_serialize_fn>> trie2;

	Hash hash2;
	trie2.hash(hash2);

	REQUIRE(hash == hash2);
}

TEST_CASE("recycling trie emptyhash2", "[recycling_trie]")
{
	RecyclingTrie<EmptyValue> trie;

	Hash h1;
	trie.hash(h1);

	auto serial_trie = trie.open_serial_subsidiary();

	trie.merge_in(serial_trie);

	Hash h2;
	trie.hash(h2);

	REQUIRE(h1 == h2);
}

TEST_CASE("recycling trie with metadata : insert metadata ok", "[recycling_trie]")
{
	RecyclingTrie<int32_t, UInt64Prefix, test::RecyclingMetadata> trie;

	auto serial_trie = trie.open_serial_subsidiary();

	for (int32_t i = 0; i < 1'000; i++)
	{
		int32_t val = i;
		serial_trie.insert(static_cast<uint64_t>((i * 1057) % 10000), std::move(val));
	}

	trie.merge_in(serial_trie);

	auto meta = trie.metadata();

	REQUIRE(meta.value_acc == (999 * 1000) / 2);

	trie.test_metadata_integrity_check();

}

TEST_CASE("recycling trie with metadata : merge metadata ok", "[recycling_trie]")
{
	RecyclingTrie<int32_t, UInt64Prefix, test::RecyclingMetadata> trie;


	for (int32_t batch = 0; batch < 5; batch++)
	{
		auto serial_trie = trie.open_serial_subsidiary();

		for (int32_t i = 0; i < 1'000; i++)
		{
			int32_t val = i;
			// test requires there's no collisions on this formula
			serial_trie.insert(static_cast<uint64_t>((i + (batch * 1000)) * 1057 % 100000), std::move(val));
		}

		trie.merge_in(serial_trie);

		auto meta = trie.metadata();

		REQUIRE(meta.value_acc == (batch + 1) * (999 * 1000) / 2);

		trie.test_metadata_integrity_check();
	}
}

TEST_CASE("batch merge", "[.perf]")
{		
	using trie_t = RecyclingTrie<EmptyValue>;

	using serial_trie_t = trie_t::serial_trie_t;
	using serial_cache_t = utils::ThreadlocalCache<serial_trie_t>;

	std::vector<size_t> cnts = {1,2,4,8,16};

	for (auto cnt : cnts)
	{
		tbb::global_control control(
			tbb::global_control::max_allowed_parallelism, cnt);

		serial_cache_t cache;

		trie_t trie;

		uint64_t experiment_sz = 5'000'000;

		auto ts = utils::init_time_measurement();

		tbb::parallel_for(
			tbb::blocked_range<uint64_t>(0, experiment_sz),
			[&cache, &trie] (auto r) {
				auto& local = cache.get(trie);
				for (auto i = r.begin(); i < r.end(); i++) {
					local.insert(i * 7, EmptyValue());
				}
			});
		auto inittime = utils::measure_time(ts);

		trie.template batch_merge_in<OverwriteMergeFn>(cache);

		auto runtime = utils::measure_time(ts);

		TRIE_LOG("%u threads init=%f merge=%f", cnt, inittime, runtime);

		REQUIRE (trie.size() == experiment_sz);
	}
}

TEST_CASE("batch merge bad initial scaffold", "[recycling_trie]")
{
	using trie_t = RecyclingTrie<EmptyValue>;
	using serial_trie_t = trie_t::serial_trie_t;
	using serial_cache_t = utils::ThreadlocalCache<serial_trie_t>;

	serial_cache_t cache;
	trie_t trie;

	auto scaffold = trie.open_serial_subsidiary();

	for (size_t i = 0; i < 256; i++)
	{
		scaffold.insert(i, {});
	}

	trie.merge_in(scaffold);

	auto& merged = cache.get(trie);
	for (size_t i = 0; i < 5000; i++)
	{
		merged.insert(i + 0xFFFF'FFFF'FFFF'0000, {});
	}

	trie.batch_merge_in<OverwriteMergeFn>(cache);

	REQUIRE(trie.size() == 5256);
}

}; /* utils */

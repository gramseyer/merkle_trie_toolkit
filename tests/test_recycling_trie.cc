#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "mtt/trie/debug_macros.h"
#include "mtt/trie/recycling_impl/trie.h"
#include "mtt/trie/utils.h"
#include "mtt/trie/types.h"

#include "mtt/utils/serialize_endian.h"
#include "mtt/utils/time.h"

#include <sodium.h>

#include <tbb/global_control.h>

namespace trie
{

using namespace utils;

TEST_CASE("recycling trie emptyhash", "[recycling_trie]")
{
	AccountTrie<EmptyValue> trie;
	Hash hash;

	trie.hash(hash);

	AccountTrie<XdrTypeWrapper<Hash, &trie::hash_serialize_fn>> trie2;

	Hash hash2;
	trie2.hash(hash2);

	REQUIRE(hash == hash2);
}

TEST_CASE("recycling trie emptyhash2", "[recycling_trie]")
{
	AccountTrie<EmptyValue> trie;

	Hash h1;
	trie.hash(h1);

	SerialAccountTrie<EmptyValue> serial_trie = trie.open_serial_subsidiary();

	trie.merge_in(serial_trie);

	Hash h2;
	trie.hash(h2);

	REQUIRE(h1 == h2);
}

TEST_CASE("batch merge", "[.perf]")
{		
	using trie_t = AccountTrie<EmptyValue>;

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

		LOG("%u threads init=%f merge=%f", cnt, inittime, runtime);

		REQUIRE (trie.size() == experiment_sz);
	}
}

}; /* utils */

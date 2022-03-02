#include <cxxtest/TestSuite.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "trie/debug_macros.h"
#include "trie/recycling_impl/trie.h"
#include "trie/utils.h"
#include "trie/xdr/types.h"

#include "utils/serialize_big_endian.h"
#include "utils/time.h"

#include <sodium.h>

#include <tbb/global_control.h>

using namespace trie;

using xdr::operator==;

class RecyclingImplTestSuite : public CxxTest::TestSuite {
public:

	void test_empty_hash() {
		TEST_START();
		AccountTrie<EmptyValue> trie;
		Hash hash;

		trie.hash(hash);

		AccountTrie<XdrTypeWrapper<Hash>> trie2;

		Hash hash2;
		trie2.hash(hash2);

		TS_ASSERT_EQUALS(hash, hash2);
	}

	void test_empty_hash2() {
		TEST_START();
		AccountTrie<EmptyValue> trie;

		Hash h1;
		trie.hash(h1);

		SerialAccountTrie<EmptyValue> serial_trie = trie.open_serial_subsidiary();

		trie.merge_in(serial_trie);

		Hash h2;
		trie.hash(h2);

		TS_ASSERT_EQUALS(h1, h2);
	}

	void test_batch_merge() {
		TEST_START();
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

			uint64_t experiment_sz = 10'000'000;

			auto ts = utils::init_time_measurement();

			tbb::parallel_for(
				tbb::blocked_range<uint64_t>(0, experiment_sz),
				[&cache, &trie] (auto r) {
					auto& local = cache.get(trie);
					EmptyValue v;
					for (auto i = r.begin(); i < r.end(); i++) {
						local.insert(i * 7, v);
					}
				});
			auto inittime = utils::measure_time(ts);

			trie.template batch_merge_in<OverwriteMergeFn>(cache);

			auto runtime = utils::measure_time(ts);

			LOG("%u threads init=%f merge=%f", cnt, inittime, runtime);

			TS_ASSERT_EQUALS(trie.size(), experiment_sz);
		}


	}
};

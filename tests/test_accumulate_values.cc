#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "mtt/trie/recycling_impl/trie.h"
#include "mtt/trie/utils.h"

#include "tests/recycling_metadata.h"

#include "mtt/ephemeral_trie/atomic_ephemeral_trie.h"

namespace trie
{

struct
DoubleAccumulateValuesFn
{
	template<typename VectorType, typename ValueType>
	static void
	accumulate(VectorType& vector, size_t vector_offset, const ValueType& value)
	{
		vector[vector_offset] = value;
		vector[vector_offset + 1] = value;
	}

	template<typename MetadataType>
	static size_t size_increment(const MetadataType& metadata)
	{
		return metadata.size_ * 2;
	}

	template<typename MetadataType>
	static size_t vector_size(const MetadataType& root_metadata)
	{
		return root_metadata.size_ * 2;
	}
};


TEST_CASE("default value acc recycling", "[accumulate]")
{
	RecyclingTrie<int32_t, UInt64Prefix, test::RecyclingMetadata> trie;

	auto serial_trie = trie.open_serial_subsidiary();

	for (int32_t i = 0; i < 1'000; i++)
	{
		int32_t val = i;
		serial_trie.insert(static_cast<uint64_t>((i * 1057) % 10000), std::move(val));
	}

	trie.merge_in(serial_trie);

	auto res = trie.template accumulate_values_parallel<std::vector<int32_t>>();
	auto res2 = trie.template accumulate_values_parallel<std::vector<int32_t>, DoubleAccumulateValuesFn>();


	REQUIRE(res.size() == 1000);
	REQUIRE(res2.size() == 2000);

	for (size_t i = 0; i < 1000; i++)
	{
		REQUIRE(res[i] == res2[2*i]);
		REQUIRE(res[i] == res2[2*i+1]);
	}
}

// todo make sure this catches error case in earlier ephemeraltrie
TEST_CASE("default value acc ephemeraltrie", "[accumulate]")
{
	AtomicTrie<int32_t, UInt64Prefix> trie;

	AtomicTrieReference<decltype(trie)> ref(trie);

	std::vector<uint64_t> keys;

	auto key_formula = [] (int32_t i) -> uint64_t {
		return static_cast<uint64_t>((i * 1057) % 10000);
	};

	for (int32_t i = 0; i < 1'000; i++)
	{
		int32_t val = i;
		uint64_t key = key_formula(i);
		ref.insert(key, std::move(val));
		keys.push_back(key);
	}

	std::sort(keys.begin(), keys.end());

	std::vector<int32_t> res;

	auto get_fn = [] (int32_t val) {
		return val;
	};

	trie.template accumulate_values_parallel<std::vector<int32_t>, get_fn>(res, 10);

	REQUIRE(res.size() == 1000);

	for (int32_t i = 0; i < 1000; i++)
	{
		auto idx = std::find(keys.begin(), keys.end(), key_formula(i));
		REQUIRE(idx != keys.end());
		int32_t offset = idx - keys.begin();

		REQUIRE(res[offset] == i);
	}
}

}
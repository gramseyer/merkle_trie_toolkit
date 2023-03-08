#include <catch2/catch_test_macros.hpp>

#include "mtt/layered_trie/layered_trie.h"

namespace trie
{

namespace test
{
	struct TestValue : public EmptyValue
	{
		bool is_active() const
		{
			return true;
		}
	};

	struct CounterValue 
	{
		uint32_t counter = 0;

		bool is_active() const {
			return true;
		}
	};
}


TEST_CASE("basic insert, one layer", "[layered]")
{
	using prefix_t = UInt64Prefix;
	using value_t = test::TestValue;
	LayeredTrie<prefix_t, value_t> trie;

	auto lambda = [] (test::TestValue& val)
	{
		return 1;
	};

	auto& layer1 = trie.bump_active_layer();

	auto access_ref = layer1.open_access_reference();

	REQUIRE(access_ref.is_active());

	REQUIRE(access_ref.insert(UInt64Prefix{0xFFFF0000FFFF0000}, lambda) == 1);
}

TEST_CASE("insert many one layer", "[layered]")
{
	using prefix_t = UInt64Prefix;
	using value_t = test::CounterValue;
	LayeredTrie<prefix_t, value_t> trie;

	auto lambda = [] (test::CounterValue& val)
	{
		val.counter++;
		return val.counter;
	};

	auto& layer1 = trie.bump_active_layer();

	auto access_ref = layer1.open_access_reference();

	REQUIRE(access_ref.is_active());

	for (uint64_t i = 0; i < 1000; i++)
	{
		uint64_t query = (i * 17) % 6701;  //6701 is prime

		REQUIRE(access_ref.insert(UInt64Prefix{query}, lambda) == 1);
	}

	for (uint64_t i = 0; i < 1000; i++)
	{
		uint64_t query = (i * 17) % 6701;  //6701 is prime

		REQUIRE(access_ref.insert(UInt64Prefix{query}, lambda) == 2);
	}
}

TEST_CASE("insert many two layers", "[layered]")
{
	using prefix_t = UInt64Prefix;
	using value_t = test::CounterValue;
	LayeredTrie<prefix_t, value_t> trie;

	auto lambda = [] (test::CounterValue& val)
	{
		val.counter++;
		return val.counter;
	};

	{
		auto& layer1 = trie.bump_active_layer();

		auto access_ref = layer1.open_access_reference();

		REQUIRE(access_ref.is_active());

		for (uint64_t i = 0; i < 1000; i++)
		{
			uint64_t query = (i * 17) % 6701;  //6701 is prime

			REQUIRE(access_ref.insert(UInt64Prefix{query}, lambda) == 1);
		}
	}

	{
		auto& layer2 = trie.bump_active_layer();

		auto access_ref = layer2.open_access_reference();

		REQUIRE(access_ref.is_active());

		for (uint64_t i = 0; i < 1000; i++)
		{
			uint64_t query = (i * 17) % 6701;  //6701 is prime

			REQUIRE(access_ref.insert(UInt64Prefix{query}, lambda) == 2);
		}

		for (uint64_t i = 1000; i < 2000; i++)
		{
			uint64_t query = (i * 17) % 6701;  //6701 is prime

			REQUIRE(access_ref.insert(UInt64Prefix{query}, lambda) == 1);
		}

	}

}


}
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

	struct ActivateableValue
	{
		bool active = false;

		bool is_active() const {
			return active;
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


// TODO check that gc on an active node does nothing
// (other than maybe bump node to a new layer)
TEST_CASE("deleted_nodes", "[layered]")
{
	using prefix_t = UInt64Prefix;
	using value_t = test::ActivateableValue;
	LayeredTrie<prefix_t, value_t> trie;

	auto activated = [] (test::ActivateableValue& val)
	{
		val.active = true;
		return;
	};

	auto inactivated = [] (test::ActivateableValue& val)
	{
		val.active = false;
		return;
	};


	{
		auto& layer1 = trie.bump_active_layer();

		auto access_ref = layer1.open_access_reference();

		REQUIRE(access_ref.is_active());

		access_ref.insert(UInt64Prefix{0x0000'0000'0000'0000}, activated);

		access_ref.insert(UInt64Prefix{0x0000'0000'0000'000F}, inactivated);
		access_ref.insert(UInt64Prefix{0x0000'0000'0000'00FF}, inactivated);
		access_ref.insert(UInt64Prefix{0x0000'0000'0000'0FFF}, inactivated);
		access_ref.insert(UInt64Prefix{0x0000'0000'0000'FFFF}, inactivated);
		access_ref.insert(UInt64Prefix{0x0000'0000'000F'FFFF}, inactivated);

		REQUIRE(!access_ref.in_normal_form());
	}

	{
		auto& layer2 = trie.bump_active_layer();

		auto access_ref = layer2.open_access_reference();
		REQUIRE(access_ref.is_active());

		access_ref.gc_inactive_leaf(UInt64Prefix{0x0000'0000'0000'000F});
		access_ref.gc_inactive_leaf(UInt64Prefix{0x0000'0000'0000'00FF});
		access_ref.gc_inactive_leaf(UInt64Prefix{0x0000'0000'0000'0FFF});
		access_ref.gc_inactive_leaf(UInt64Prefix{0x0000'0000'0000'FFFF});
		access_ref.gc_inactive_leaf(UInt64Prefix{0x0000'0000'000F'FFFF});

		REQUIRE(!access_ref.in_normal_form());
	}
	{

		auto& layer3 = trie.bump_active_layer();

		auto access_ref = layer3.open_access_reference();
		REQUIRE(access_ref.is_active());

		access_ref.insert(UInt64Prefix{0x0000'0000'0000'0000}, activated);

		REQUIRE(access_ref.in_normal_form());

		access_ref.insert(UInt64Prefix{0x0000'0000'0000'000F}, activated);

		// gc nodes that don't exist shouldn't cause non-normal forms
		REQUIRE(access_ref.in_normal_form());
		access_ref.gc_inactive_leaf(UInt64Prefix{0x0000'FFFF'0000'0000});

		REQUIRE(access_ref.in_normal_form());
		access_ref.gc_inactive_leaf(UInt64Prefix{0x0000'0000'0000'0001});


		access_ref.insert(UInt64Prefix{0x0000'0000'0000'0000}, inactivated);

		REQUIRE(!access_ref.in_normal_form());
	}
}


}
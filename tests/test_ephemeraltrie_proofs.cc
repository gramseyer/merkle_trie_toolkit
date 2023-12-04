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

TEST_CASE("atomic trie emptyvalue small", "[proof]")
{
	using trie_t = AtomicTrie<EmptyValue, UInt64Prefix>;
	trie_t trie;
	auto alloc = trie.get_new_allocation_context();

	trie.insert(UInt64Prefix(0x0000'0000'0000'0000), EmptyValue{}, alloc);
	trie.insert(UInt64Prefix(0x0000'0000'0000'0001), EmptyValue{}, alloc);
	trie.insert(UInt64Prefix(0x0000'0000'0000'0010), EmptyValue{}, alloc);
	trie.insert(UInt64Prefix(0x0000'0000'0000'0100), EmptyValue{}, alloc);
	trie.insert(UInt64Prefix(0x0000'0000'0000'1000), EmptyValue{}, alloc);

	auto roothash = trie.hash_serial();

	SECTION("leaf proof 1")
	{
		auto p = trie.make_proof(UInt64Prefix(0x0000'0000'0000'0000), PrefixLenBits{64});

		REQUIRE(trie_t::verify_proof(p, roothash));
		REQUIRE(p.proof_stack.size() == 6);
	}

	SECTION("leaf proof 2")
	{
		auto p = trie.make_proof(UInt64Prefix(0x0000'0000'0000'0001), PrefixLenBits{64});

		REQUIRE(trie_t::verify_proof(p, roothash));
	}
	SECTION("leaf proof 3")
	{
		auto p = trie.make_proof(UInt64Prefix(0x0000'0000'0000'1000), PrefixLenBits{64});

		REQUIRE(trie_t::verify_proof(p, roothash));
	}

	SECTION("leaf proof nexist 1")
	{
		auto p = trie.make_proof(UInt64Prefix(0x0000'0000'0000'0002), PrefixLenBits{64});

		REQUIRE(trie_t::verify_proof(p, roothash));
		REQUIRE(p.proof_stack.size() == 5);
	}
	SECTION("leaf proof nexist extreme")
	{
		auto p = trie.make_proof(UInt64Prefix(0x1000'0000'0000'0002), PrefixLenBits{64});

		REQUIRE(trie_t::verify_proof(p, roothash));
		REQUIRE(p.proof_stack.size() == 1);
	}
}

struct test_uint64_value
{
	uint64_t value;

	void copy_data(std::vector<uint8_t>& buf) const
	{
		utils::append_unsigned_big_endian(buf, value);
	}

	void from_bytes(std::vector<uint8_t> const& bytes)
	{
		utils::read_unsigned_big_endian(bytes, value);
	}
};

TEST_CASE("atomic trie with value small", "[proof]")
{
	using trie_t = AtomicTrie<test_uint64_value, UInt64Prefix>;
	trie_t trie, trie2;
	auto alloc = trie.get_new_allocation_context();
	auto alloc2 = trie2.get_new_allocation_context();

	trie.insert(UInt64Prefix(0x0000'0000'0000'0000), test_uint64_value{0}, alloc);
	trie.insert(UInt64Prefix(0x0000'0000'0000'0001), test_uint64_value{1}, alloc);

	trie2.insert(UInt64Prefix(0x0000'0000'0000'0000), test_uint64_value{1}, alloc2);
	trie2.insert(UInt64Prefix(0x0000'0000'0000'0001), test_uint64_value{1}, alloc2);

	auto roothash = trie.hash_serial();
	auto roothash2 = trie2.hash_serial();

	auto p = trie.make_proof(UInt64Prefix(0x0000'0000'0000'0000), PrefixLenBits{64});
	auto p2 = trie2.make_proof(UInt64Prefix(0x0000'0000'0000'0000), PrefixLenBits{64});

	REQUIRE(trie_t::verify_proof(p, roothash));
	REQUIRE(trie_t::verify_proof(p2, roothash2));
	REQUIRE(!trie_t::verify_proof(p, roothash2));
	REQUIRE(!trie_t::verify_proof(p2, roothash));
}

}

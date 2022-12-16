#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "mtt/trie/debug_macros.h"
#include "mtt/trie/atomic_merkle_trie.h"
#include "mtt/trie/utils.h"
#include "mtt/trie/types.h"

#include <utils/serialize_endian.h>
#include <utils/time.h>
#include <utils/threadlocal_cache.h>

#include <tbb/parallel_for.h>

namespace trie
{


TEST_CASE("basic get subnode ref and normalize", "[amt]")
{

	using mt = AtomicMerkleTrie<UInt64Prefix, EmptyValue, 256>;

	mt m;

	REQUIRE(m.get_subnode_ref_and_invalidate_hash(UInt64Prefix(0x0000'0000'0000'0000), PrefixLenBits(32)) != nullptr);
	REQUIRE(m.get_subnode_ref_and_invalidate_hash(UInt64Prefix(0xFFFF'FFFF'0000'0000), PrefixLenBits(32)) != nullptr);
	auto* p0 = m.get_subnode_ref_and_invalidate_hash(UInt64Prefix(0xFFFF'0000'0000'0000), PrefixLenBits(16));

	auto* p1 = m.get_subnode_ref_and_invalidate_hash(UInt64Prefix(0xFFFF'AAAA'0000'0000), PrefixLenBits(32));
	auto* p2 = m.get_subnode_ref_and_invalidate_hash(UInt64Prefix(0xFFFF'AAAA'0000'0000), PrefixLenBits(32));

	REQUIRE(p1 == p2);

	REQUIRE(p0 -> get_child(0xA) == p1);





}




}
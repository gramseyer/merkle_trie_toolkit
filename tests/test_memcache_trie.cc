#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "mtt/common/debug_macros.h"

#include "mtt/memcached_snapshot_trie/in_memory_interface.h"
#include "mtt/memcached_snapshot_trie/memcache_trie.h"
#include "mtt/trie/types.h"
#include "mtt/trie/utils.h"

namespace trie {

TEST_CASE("basic memcache trie get subnode ref and normalize", "[memcache]")
{
    using mt
        = MemcacheTrie<UInt64Prefix, EmptyValue, 256, InMemoryInterface<8>>;

    mt m(0);

    REQUIRE(m.get_subnode_ref_and_invalidate_hash(
                UInt64Prefix(0x0000'0000'0000'0000), PrefixLenBits(32), 0)
            != nullptr);
    REQUIRE(m.get_subnode_ref_and_invalidate_hash(
                UInt64Prefix(0xFFFF'FFFF'0000'0000), PrefixLenBits(32), 0)
            != nullptr);
    auto* p0 = m.get_subnode_ref_and_invalidate_hash(
        UInt64Prefix(0xFFFF'0000'0000'0000), PrefixLenBits(16), 0);

    auto* p1 = m.get_subnode_ref_and_invalidate_hash(
        UInt64Prefix(0xFFFF'AAAA'0000'0000), PrefixLenBits(32), 0);
    auto* p2 = m.get_subnode_ref_and_invalidate_hash(
        UInt64Prefix(0xFFFF'AAAA'0000'0000), PrefixLenBits(32), 0);

    REQUIRE(p1 == p2);

    REQUIRE(p0->get_child(0xA) == p1);
}

} // namespace trie

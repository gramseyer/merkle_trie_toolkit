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

void test_log_committed_value(std::vector<uint8_t> const& raw, std::vector<uint8_t> const& committed_value)
{
    REQUIRE(raw.size() == 1 + committed_value.size());
    REQUIRE(memcmp(raw.data() + 1, committed_value.data(), committed_value.size()) == 0);
}

void test_log_value(std::vector<uint8_t> const &raw, std::vector<uint8_t> const& committed_value)
{
    REQUIRE(raw.size() >= 1);
    REQUIRE(raw[0] == 1);

    test_log_committed_value(raw, committed_value);
}

void test_log_map(std::vector<uint8_t> const &raw, std::vector<uint8_t> const& committed_value)
{
    REQUIRE(raw.size() >= 1);
    REQUIRE(raw[0] == 0);

    test_log_committed_value(raw, committed_value);
}


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

void
overwrite_merge_fn_memcache(EmptyValue& a, const EmptyValue& b)
{}

TEST_CASE("basic memcache check log insert", "[memcache]")
{
     using mt
        = MemcacheTrie<UInt64Prefix, EmptyValue, 256, InMemoryInterface<8>>;

    mt m(0);

    auto* root = m.get_subnode_ref_and_invalidate_hash(
        UInt64Prefix(0), PrefixLenBits(0), 1);

    root -> template insert<&overwrite_merge_fn_memcache>(UInt64Prefix(0xAAAA'BBBB'CCCC'DDDD), m.get_gc(), 1, m.get_storage(), EmptyValue{});

    auto* obj_ptr = m.get_subnode_ref_and_invalidate_hash(UInt64Prefix(0xAAAA'BBBB'CCCC'DDDD), PrefixLenBits{64}, 1);
    auto* root_ptr = m.get_subnode_ref_and_invalidate_hash(UInt64Prefix(0xAAAA'BBBB'CCCC'DDDD), PrefixLenBits{0}, 1);

    m.hash_and_normalize(0);

    std::vector<uint8_t> expect = {0xAA,0xAA,0xBB,0xBB,0xCC,0xCC,0xDD,0xDD};
    auto h = obj_ptr -> get_metadata().hash;
    expect.insert(expect.end(), h.begin(), h.end());
    
    auto add_expect = [&expect]<typename T>(T const& t)
    {
        expect.insert(expect.end(), reinterpret_cast<const uint8_t*>(&t), reinterpret_cast<const uint8_t*>(&t) + sizeof(T));
    };

    // value len is 32
    //uint32_t value_len = 0;
    add_expect(static_cast<uint32_t>(0));
    test_log_value(m.get_storage().get_raw(obj_ptr->get_ts_ptr()),
        expect);

    expect = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    h = root_ptr -> get_metadata().hash;
    expect.insert(expect.end(), h.begin(), h.end());

    add_expect(static_cast<uint16_t>(0));
    add_expect(static_cast<uint16_t>(1<<10)); // A
    add_expect(static_cast<uint32_t>(1));
    add_expect(obj_ptr);

    test_log_map(m.get_storage().get_raw(root_ptr -> get_ts_ptr()), expect);

}

} // namespace trie

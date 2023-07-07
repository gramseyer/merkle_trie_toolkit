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

void
test_log_committed_value(std::vector<uint8_t> const& raw,
                         std::vector<uint8_t> const& committed_value)
{
    uint8_t res = (raw.size() != 1 + committed_value.size());
    if (res != 0) {
        std::printf(
            "raw %s\nexp %s\n",
            utils::array_to_str(raw.data() + 1, raw.size() - 1).c_str(),
            utils::array_to_str(committed_value.data(), committed_value.size())
                .c_str());
    }

    REQUIRE(res == 0);

    res = memcmp(
        raw.data() + 1, committed_value.data(), committed_value.size());

    if (res != 0) {
        std::printf(
            "raw %s\nexp %s\n",
            utils::array_to_str(raw.data() + 1, committed_value.size()).c_str(),
            utils::array_to_str(committed_value.data(), committed_value.size())
                .c_str());
    }
    REQUIRE(res == 0);
}

void
test_log_value(std::vector<uint8_t> const& raw,
               std::vector<uint8_t> const& committed_value)
{
    REQUIRE(raw.size() >= 1);
    REQUIRE(raw[0] == 1);

    test_log_committed_value(raw, committed_value);
}

void
test_log_map(std::vector<uint8_t> const& raw,
             std::vector<uint8_t> const& committed_value)
{
    REQUIRE(raw.size() >= 1);
    REQUIRE(raw[0] == 0);

    test_log_committed_value(raw, committed_value);
}

void
test_log_delete(std::vector<uint8_t> const& raw,
                TimestampPointerPair const& tsp)
{
    REQUIRE(raw.size() == 1 + sizeof(TimestampPointerPair));
    REQUIRE(raw[0] == 2);

    REQUIRE(memcmp(raw.data() + 1,
                   reinterpret_cast<const uint8_t*>(&tsp),
                   sizeof(TimestampPointerPair))
            == 0);
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

    root->template insert<&overwrite_merge_fn_memcache>(
        UInt64Prefix(0xAAAA'BBBB'CCCC'DDDD),
        m.get_gc(),
        1,
        m.get_storage(),
        EmptyValue{});

    auto* obj_ptr = m.get_subnode_ref_and_invalidate_hash(
        UInt64Prefix(0xAAAA'BBBB'CCCC'DDDD), PrefixLenBits{ 64 }, 1);
    auto* root_ptr = m.get_subnode_ref_and_invalidate_hash(
        UInt64Prefix(0xAAAA'BBBB'CCCC'DDDD), PrefixLenBits{ 0 }, 1);

    auto obj_tsp = obj_ptr->get_previous_ts_ptr();
    auto root_tsp = root_ptr->get_previous_ts_ptr();

    m.hash_and_normalize(0);

    std::vector<uint8_t> expect
        = { 0xAA, 0xAA, 0xBB, 0xBB, 0xCC, 0xCC, 0xDD, 0xDD };

    auto add_expect = [&expect]<typename T>(T const& t) {
        expect.insert(expect.end(),
                      reinterpret_cast<const uint8_t*>(&t),
                      reinterpret_cast<const uint8_t*>(&t) + sizeof(T));
    };

    add_expect(obj_ptr->get_metadata());

    add_expect(obj_tsp);
    // value len is 32
    add_expect(static_cast<uint32_t>(0));
    test_log_value(m.get_storage().get_raw(obj_ptr->get_ts_ptr()), expect);

    expect = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    add_expect(root_ptr->get_metadata());
    add_expect(static_cast<uint16_t>(0));
    add_expect(static_cast<uint16_t>(1 << 10)); // A
    add_expect(root_tsp);
    // child ptr
    add_expect(static_cast<uint32_t>(1));
    add_expect(obj_ptr);

    test_log_map(m.get_storage().get_raw(root_ptr->get_ts_ptr()), expect);
}

TEST_CASE("basic memcache check deletions", "[memcache]")
{
    using mt
        = MemcacheTrie<UInt64Prefix, EmptyValue, 256, InMemoryInterface<8>>;

    mt m(0);

    auto* root = m.get_subnode_ref_and_invalidate_hash(
        UInt64Prefix(0), PrefixLenBits(0), 1);

    root->template insert<&overwrite_merge_fn_memcache>(
        UInt64Prefix(0xAAAA'BBBB'CCCC'0000),
        m.get_gc(),
        1,
        m.get_storage(),
        EmptyValue{});
    auto* p1 = m.get_subnode_ref_and_invalidate_hash(
        UInt64Prefix(0xAAAA'BBBB'CCCC'0000), PrefixLenBits{ 64 }, 1);
    root->template insert<&overwrite_merge_fn_memcache>(
        UInt64Prefix(0xAAAA'BBBB'CCCC'000F),
        m.get_gc(),
        1,
        m.get_storage(),
        EmptyValue{});
    auto* p2 = m.get_subnode_ref_and_invalidate_hash(
        UInt64Prefix(0xAAAA'BBBB'CCCC'000F), PrefixLenBits{ 64 }, 1);
    root->template insert<&overwrite_merge_fn_memcache>(
        UInt64Prefix(0xAAAA'BBBB'CCCC'00FF),
        m.get_gc(),
        1,
        m.get_storage(),
        EmptyValue{});

    auto* intermediate = m.get_subnode_ref_and_invalidate_hash(
        UInt64Prefix(0xAAAA'BBBB'CCCC'000F), PrefixLenBits{ 60 }, 1);

    auto tsp1 = p1->get_ts_ptr();
    auto tsp2 = p2->get_ts_ptr();
    auto tsint = intermediate->get_ts_ptr();

    m.hash_and_normalize(0);

    // check delete from above

    root->delete_value(
        UInt64Prefix(0xAAAA'BBBB'CCCC'0000), 2, m.get_gc(), m.get_storage());

    p2->delete_value(
        UInt64Prefix(0xAAAA'BBBB'CCCC'000F), 2, m.get_gc(), m.get_storage());
    // have to re-invalidate the hash to the deleted object
    root->invalidate_hash_to_node(p2, 2);

    m.hash_and_normalize(0);

    auto tsp11 = tsp1;
    tsp11.timestamp = 2;

    test_log_delete(m.get_storage().get_raw(tsp11), tsp1);

    auto tsp21 = tsp2;
    tsp21.timestamp = 2;

    test_log_delete(m.get_storage().get_raw(tsp21), tsp2);

    auto tsint1 = tsint;
    tsint1.timestamp = 2;

    test_log_delete(m.get_storage().get_raw(tsint1), tsint);
}

struct TestSerializeUInt64 {

    uint64_t value;

    void copy_data(std::vector<uint8_t>& buf) const {
        utils::append_unsigned_little_endian(buf, value);
    }

    TestSerializeUInt64(uint64_t value) : value(value) {}

    TestSerializeUInt64(DurableValueSlice const& slice) : value(0)
    {
        value = *reinterpret_cast<const uint64_t*>(slice.ptr);
    }
};

void
overwrite_merge_fn_memcache_uint64(TestSerializeUInt64& a, const TestSerializeUInt64& b)
{
    a = b;
}

TEST_CASE("memcache reload", "[memcache]")
{
    {
        // test obj check
        TestSerializeUInt64 v(1234);
        std::vector<uint8_t> bytes;
        v.copy_data(bytes);

        DurableValueSlice slice(bytes.data(), bytes.size());

        REQUIRE(slice.len == 8);

        TestSerializeUInt64 v2 (slice);

        REQUIRE(v.value == v2.value);
    }

    using mt
        = MemcacheTrie<UInt64Prefix, TestSerializeUInt64, 256, InMemoryInterface<8>>;

    mt m(0);

    auto* root = m.get_subnode_ref_and_invalidate_hash(
        UInt64Prefix(0), PrefixLenBits(0), 1);

    root->template insert<&overwrite_merge_fn_memcache_uint64>(
        UInt64Prefix(0xAAAA'BBBB'CCCC'0000),
        m.get_gc(),
        1,
        m.get_storage(),
        1);

    root->template insert<&overwrite_merge_fn_memcache_uint64>(
        UInt64Prefix(0xAAAA'BBBB'CCCC'000F),
        m.get_gc(),
        1,
        m.get_storage(),
        2);

    root->template insert<&overwrite_merge_fn_memcache_uint64>(
        UInt64Prefix(0xAAAA'BBBB'CCCC'FFFF),
        m.get_gc(),
        1,
        m.get_storage(),
        3);

    /**
     *  trie consists of AAAABBBBCCCC | - 000 | - 0
     *                                |       | - F
     *                                |
     *                                | - FFFF
     */
    
    auto check_exist = [&] (uint64_t expect, uint64_t key)
    {
        const auto* ptr = m.get_value(UInt64Prefix(key));

        REQUIRE(!!ptr);

        REQUIRE(ptr -> value == expect);
    };

    auto check_nexist = [&] (uint64_t key)
    {
        REQUIRE(!m.get_value(UInt64Prefix(key)));
    };

    SECTION("everything evicted")
    {
        m.hash_and_normalize(2);

        REQUIRE(m.get_storage().get_store_count() == 6);

        check_exist(3, 0xAAAA'BBBB'CCCC'FFFF);

        REQUIRE(m.get_storage().get_load_count() == 4);
        check_nexist(0);
        REQUIRE(m.get_storage().get_load_count() == 4);

        check_nexist(0xAAAA'BBBB'CCCC'0111);

        // this loads in 0xAAAA'BBBB'CCCC'000,
        // as get_value() never recurses onto an evicted node
        // and does not check children for prefix partial maches
        // (unlike insert, which checks prefix match prior to recursion)
        REQUIRE(m.get_storage().get_load_count() == 7);

        check_nexist(0xAAAA'BBBB'CCCC'0001);

        REQUIRE(m.get_storage().get_load_count() == 7);

        check_exist(2, 0xAAAA'BBBB'CCCC'000F);
        REQUIRE(m.get_storage().get_load_count() == 8);


        check_exist(1, 0xAAAA'BBBB'CCCC'0000);
        REQUIRE(m.get_storage().get_load_count() == 9);
    }
}

} // namespace trie

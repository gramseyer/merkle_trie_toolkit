#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "mtt/common/debug_macros.h"

#include "mtt/snapshot_trie/atomic_merkle_trie.h"
#include "mtt/trie/types.h"
#include "mtt/trie/utils.h"

#include "mtt/memcached_snapshot_trie/memcache_trie.h"
#include "mtt/memcached_snapshot_trie/null_interface.h"

#include <utils/serialize_endian.h>
#include <utils/threadlocal_cache.h>
#include <utils/time.h>

#include <tbb/parallel_for.h>

namespace trie {

TEST_CASE("basic get subnode ref and normalize", "[amt]")
{
    using mt = AtomicMerkleTrie<UInt64Prefix, EmptyValue, 256>;

    mt m;

    REQUIRE(m.get_subnode_ref_and_invalidate_hash(
                UInt64Prefix(0x0000'0000'0000'0000), PrefixLenBits(32))
            != nullptr);
    REQUIRE(m.get_subnode_ref_and_invalidate_hash(
                UInt64Prefix(0xFFFF'FFFF'0000'0000), PrefixLenBits(32))
            != nullptr);
    auto* p0 = m.get_subnode_ref_and_invalidate_hash(
        UInt64Prefix(0xFFFF'0000'0000'0000), PrefixLenBits(16));

    auto* p1 = m.get_subnode_ref_and_invalidate_hash(
        UInt64Prefix(0xFFFF'AAAA'0000'0000), PrefixLenBits(32));
    auto* p2 = m.get_subnode_ref_and_invalidate_hash(
        UInt64Prefix(0xFFFF'AAAA'0000'0000), PrefixLenBits(32));

    REQUIRE(p1 == p2);

    REQUIRE(p0->get_child(0xA) == p1);
}

TEST_CASE("normalize cleans up in case of no inserts", "[amt]")
{
    using mt = AtomicMerkleTrie<UInt64Prefix, EmptyValue, 256>;

    mt m;

    REQUIRE(m.get_subnode_ref_and_invalidate_hash(
                UInt64Prefix(0x0000'0000'0000'0000), PrefixLenBits(32))
            != nullptr);
    REQUIRE(m.get_subnode_ref_and_invalidate_hash(
                UInt64Prefix(0xFFFF'FFFF'0000'0000), PrefixLenBits(32))
            != nullptr);
    REQUIRE(m.get_subnode_ref_and_invalidate_hash(
                UInt64Prefix(0xFFFF'0000'0000'0000), PrefixLenBits(24))
            != nullptr);
    REQUIRE(m.get_subnode_ref_and_invalidate_hash(
                UInt64Prefix(0xFF00'FF00'0000'0000), PrefixLenBits(16))
            != nullptr);

    auto h1 = m.hash_and_normalize();

    mt m2;
    auto h2 = m2.hash_and_normalize();

    REQUIRE(h1 == h2);
}

struct Uint8Wrapper
{
    uint8_t value;

    Uint8Wrapper(uint8_t const& v)
        : value(v)
    {}

    void copy_data(std::vector<uint8_t>& bytes) { bytes.push_back(value); }
};

void
overwrite_merge_fn(EmptyValue& a, const EmptyValue& b)
{}
void
overwrite_merge_fn_uint8(Uint8Wrapper& a, const Uint8Wrapper& b)
{
    a = b;
}

TEST_CASE("check insert after getsubnode on value", "[amt]")
{
    using mt = AtomicMerkleTrie<UInt64Prefix, Uint8Wrapper, 256>;

    mt m;

    auto* ptr = m.get_subnode_ref_and_invalidate_hash(
        UInt64Prefix(0x0000'0000'0000'0000), PrefixLenBits(64));

    REQUIRE(ptr != nullptr);

    ptr->template insert<&overwrite_merge_fn_uint8>(
        UInt64Prefix(0x0000'0000'0000'0000), m.get_gc(), 1);
    ptr->template insert<&overwrite_merge_fn_uint8>(
        UInt64Prefix(0x0000'0000'0000'0000), m.get_gc(), 2);

    auto h1 = m.hash_and_normalize();

    mt m2;

    m2.get_subnode_ref_and_invalidate_hash(UInt64Prefix(0), PrefixLenBits(0))
        ->template insert<&overwrite_merge_fn_uint8>(
            UInt64Prefix(0x0000'0000'0000'0000), m.get_gc(), 2);

    auto h2 = m2.hash_and_normalize();

    REQUIRE(h1 == h2);
}

TEST_CASE("check delete after getsubnode on value", "[amt]")
{
    using mt = AtomicMerkleTrie<UInt64Prefix, Uint8Wrapper, 256>;

    mt m;

    auto* ptr = m.get_subnode_ref_and_invalidate_hash(
        UInt64Prefix(0x0000'0000'0000'0000), PrefixLenBits(64));

    REQUIRE(ptr != nullptr);

    ptr->template insert<&overwrite_merge_fn_uint8>(
        UInt64Prefix(0x0000'0000'0000'0000), m.get_gc(), 1);

    auto h1 = m.hash_and_normalize();
    // WARNING -- reusing pointers from get_subnode_ref doesn't invalidate hashes again

	ptr = m.get_subnode_ref_and_invalidate_hash(
        UInt64Prefix(0x0000'0000'0000'0000), PrefixLenBits(64));
	REQUIRE(ptr != nullptr);
	
    ptr -> delete_value(UInt64Prefix(0x0000'0000'0000'0000), m.get_gc());

    auto h11 = m.hash_and_normalize();

    mt m2;

    auto h2 = m2.hash_and_normalize();

    REQUIRE(h1 != h2);
    REQUIRE(h11 == h2);
}

TEST_CASE("check cleanup after get_subnode on value", "[amt]")
{
	using mt = AtomicMerkleTrie<UInt64Prefix, Uint8Wrapper, 256>;

    mt m;

    auto* ptr = m.get_subnode_ref_and_invalidate_hash(
        UInt64Prefix(0x0000'0000'0000'0000), PrefixLenBits(64));

    REQUIRE(ptr != nullptr);

    auto h1 = m.hash_and_normalize();

    mt m2;

    auto h2 = m2.hash_and_normalize();

    REQUIRE(h1 == h2);
}

TEST_CASE("check inserts", "[amt]")
{
    using mt = AtomicMerkleTrie<UInt64Prefix, EmptyValue, 256>;

    mt m;

    auto* root = m.get_subnode_ref_and_invalidate_hash(UInt64Prefix(0),
                                                       PrefixLenBits(0));

    for (uint64_t i = 0; i < 1000; i++) {
        uint64_t query = (i * 17) % 6701; // 6701 is prime

        root->template insert<&overwrite_merge_fn>(
            UInt64Prefix(query), m.get_gc(), EmptyValue{});
    }

    auto h1 = m.hash_and_normalize();

    for (uint64_t i = 0; i < 1000; i++) {
        uint64_t query = ((i + 1000) * 17) % 6701; // 6701 is prime

        m.get_subnode_ref_and_invalidate_hash(UInt64Prefix(query),
                                              PrefixLenBits(56));
    }

    auto h2 = m.hash_and_normalize();

    REQUIRE(h1 == h2);
}
TEST_CASE("force recompute", "[amt]")
{
    using mt = AtomicMerkleTrie<UInt64Prefix, EmptyValue, 256>;

    mt m;

    auto h1 = m.hash_and_normalize();

    auto* base = m.get_subnode_ref_and_invalidate_hash(UInt64Prefix(0),
                                                       PrefixLenBits(60));

    base->template insert<&overwrite_merge_fn>(
        UInt64Prefix(0x0), m.get_gc(), EmptyValue{});

    auto h2 = m.hash_and_normalize();

    REQUIRE(h1 != h2);

    base->template insert<&overwrite_merge_fn>(
        UInt64Prefix(0x0), m.get_gc(), EmptyValue{});

    REQUIRE(h2 == m.hash_and_normalize());
}

TEST_CASE("ensure full length key", "[amt]")
{
    using mt = AtomicMerkleTrie<UInt64Prefix, EmptyValue, 256>;

    mt m;

    auto h = m.hash_and_normalize();

    auto* base = m.get_subnode_ref_and_invalidate_hash(UInt64Prefix(0),
                                                       PrefixLenBits(64));

    base->template insert<&overwrite_merge_fn>(
        UInt64Prefix(0), m.get_gc(), EmptyValue{});

    auto h2 = m.hash_and_normalize();

    REQUIRE(h != h2);
}

TEST_CASE("get proper length subnode", "[amt]")
{
    using mt = AtomicMerkleTrie<UInt64Prefix, EmptyValue, 256>;
    mt m;

    using prefix_t = UInt64Prefix;

    SECTION("from empty")
    {
        auto* b = m.get_subnode_ref_and_invalidate_hash(prefix_t(0),
                                                        PrefixLenBits(0));
        REQUIRE(b->get_prefix_len().len == 0);

        b = m.get_subnode_ref_and_invalidate_hash(prefix_t(0),
                                                  PrefixLenBits(28));

        REQUIRE(b->get_prefix_len().len == 28);

        b = m.get_subnode_ref_and_invalidate_hash(prefix_t(0),
                                                  PrefixLenBits(64));

        REQUIRE(b->get_prefix_len().len == 64);
    }
    SECTION("from singlechild")
    {
        {
            auto* b = m.get_subnode_ref_and_invalidate_hash(prefix_t(0),
                                                            PrefixLenBits(0));
            b->template insert<&overwrite_merge_fn>(
                prefix_t(0x0000'0000'0000'0000), m.get_gc(), EmptyValue{});
            b->template insert<&overwrite_merge_fn>(
                prefix_t(0x1000'0000'0000'0000), m.get_gc(), EmptyValue{});
        }

        auto h1 = m.hash_and_normalize();

        auto* b = m.get_subnode_ref_and_invalidate_hash(prefix_t(0),
                                                        PrefixLenBits(0));
        REQUIRE(b->get_prefix_len().len == 0);

        b = m.get_subnode_ref_and_invalidate_hash(
            prefix_t(0x1000'0000'0000'0000), PrefixLenBits(4));
        REQUIRE(b->get_prefix_len().len == 4);

        b = m.get_subnode_ref_and_invalidate_hash(
            prefix_t(0x1000'0000'0000'0000), PrefixLenBits(56));
        REQUIRE(b->get_prefix_len().len == 56);

        b = m.get_subnode_ref_and_invalidate_hash(
            prefix_t(0x2000'0000'0000'0000), PrefixLenBits(56));
        REQUIRE(b->get_prefix_len().len == 56);

        b = m.get_subnode_ref_and_invalidate_hash(
            prefix_t(0x1100'0000'0000'0000), PrefixLenBits(56));
        REQUIRE(b->get_prefix_len().len == 56);

        REQUIRE(m.hash_and_normalize() == h1);
    }

    SECTION("from middle")
    {
        {
            auto* b = m.get_subnode_ref_and_invalidate_hash(prefix_t(0),
                                                            PrefixLenBits(0));
            b->template insert<&overwrite_merge_fn>(
                prefix_t(0xFFFF'0000'0000'FFFF), m.get_gc(), EmptyValue{});
            b->template insert<&overwrite_merge_fn>(
                prefix_t(0xFFFF'0000'0000'0000), m.get_gc(), EmptyValue{});
        }

        auto h1 = m.hash_and_normalize();

        auto* b = m.get_subnode_ref_and_invalidate_hash(
            prefix_t(0x1000'0000'0000'0000), PrefixLenBits(4));
        REQUIRE(b->get_prefix_len().len == 4);

        SECTION("extend common point")
        {
            b = m.get_subnode_ref_and_invalidate_hash(
                prefix_t(0xFFFF'FFFF'0000'0000), PrefixLenBits(32));
            REQUIRE(b->get_prefix_len().len == 32);
            REQUIRE(m.hash_and_normalize() == h1);
        }
        SECTION("at common point")
        {
            b = m.get_subnode_ref_and_invalidate_hash(
                prefix_t(0xFFFF'0000'0000'0000), PrefixLenBits(16));
            REQUIRE(b->get_prefix_len().len == 16);
            REQUIRE(m.hash_and_normalize() == h1);
        }
    }
}

TEST_CASE("deletions", "[amt]")
{
    using mt = AtomicMerkleTrie<UInt64Prefix, EmptyValue, 256>;

    mt m;

    auto h = m.hash_and_normalize();

    auto* root = m.get_subnode_ref_and_invalidate_hash(UInt64Prefix(0),
                                                       PrefixLenBits(32));

    SECTION("single elt")
    {

        root->template insert<&overwrite_merge_fn>(
            UInt64Prefix(0x0000'0000'0000'0000), m.get_gc(), EmptyValue{});

        root->delete_value(UInt64Prefix(0x0000'0000'0000'0000), m.get_gc());

        REQUIRE(m.hash_and_normalize() == h);
    }

    SECTION("several elt")
    {
        root->template insert<&overwrite_merge_fn>(
            UInt64Prefix(0x0000'0000'0000'0000), m.get_gc(), EmptyValue{});
        root->template insert<&overwrite_merge_fn>(
            UInt64Prefix(0x0000'0000'0000'1111), m.get_gc(), EmptyValue{});

        h = m.hash_and_normalize();
        root = m.get_subnode_ref_and_invalidate_hash(UInt64Prefix(0),
                                                     PrefixLenBits(32));

        root->template insert<&overwrite_merge_fn>(
            UInt64Prefix(0x0000'0000'0000'2222), m.get_gc(), EmptyValue{});

        root->delete_value(UInt64Prefix(0x0000'0000'0000'2222), m.get_gc());

        REQUIRE(m.hash_and_normalize() == h);
    }

    SECTION("cleanup chain")
    {
        m.get_subnode_ref_and_invalidate_hash(UInt64Prefix(0),
                                              PrefixLenBits(32));
        m.get_subnode_ref_and_invalidate_hash(UInt64Prefix(0),
                                              PrefixLenBits(40));
        m.get_subnode_ref_and_invalidate_hash(UInt64Prefix(0),
                                              PrefixLenBits(44));
        m.get_subnode_ref_and_invalidate_hash(UInt64Prefix(0),
                                              PrefixLenBits(48));

        root->template insert<&overwrite_merge_fn>(
            UInt64Prefix(0x0000'0000'0000'2222), m.get_gc(), EmptyValue{});
        root->template insert<&overwrite_merge_fn>(
            UInt64Prefix(0x0000'0000'0000'1111), m.get_gc(), EmptyValue{});

        root->delete_value(UInt64Prefix(0x0000'0000'0000'2222), m.get_gc());
        root->delete_value(UInt64Prefix(0x0000'0000'0000'1111), m.get_gc());

        REQUIRE(m.hash_and_normalize() == h);
    }
}

namespace detail {
    struct invalidateable_logical_value {
        bool valid;
        uint64_t uid;

        void copy_data(std::vector<uint8_t>& buf) const
        {
            if (!valid) {
                throw std::runtime_error("should not write here");
            }
            utils::write_unsigned_little_endian(buf, uid);
        }

        invalidateable_logical_value(trie::DurableValueSlice const& slice)
            : valid(true)
            , uid(0)
        {
            if (slice.len != 8) {
                throw std::runtime_error("invalid slice");
            }
            uid = *reinterpret_cast<const uint64_t*>(slice.ptr);
        }

        invalidateable_logical_value(bool valid, uint64_t uid)
            : valid(valid)
            , uid(uid)
            {}
    };

    static bool validation_lambda(const invalidateable_logical_value& v)
    {
        return v.valid;
    }

    static void lv_serialize(std::vector<uint8_t>& buf, const invalidateable_logical_value& v)
    {
        utils::write_unsigned_little_endian(buf, v.uid);
    }

    void
    no_merge_fn(invalidateable_logical_value& a, const invalidateable_logical_value& b)
    {
        throw std::runtime_error("should not happen");
    }
}

TEST_CASE("no logical value", "[amt]")
{
    using value_t = BetterSerializeWrapper<detail::invalidateable_logical_value, &detail::lv_serialize>;

    using metadata_t = SnapshotTrieMetadataBase;
    using prefix_t = UInt64Prefix;

    using mt = AtomicMerkleTrie<prefix_t, value_t, 64, metadata_t, &detail::validation_lambda>;

    mt m;

    auto h = m.hash_and_normalize();

    auto make_lv = [](bool valid, uint64_t id) {
        return detail::invalidateable_logical_value (valid, id);
       //     .valid = valid,
       //     .uid = id
       // };
    };

    SECTION("only empty values")
    {
        auto root = m.get_root_and_invalidate_hash();

        root -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'0001), m.get_gc(), make_lv(false, 0));
        root -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'0002), m.get_gc(), make_lv(false, 1));
        root -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'0010), m.get_gc(), make_lv(false, 2));
        root -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'0100), m.get_gc(), make_lv(false, 3));
        root -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'1000), m.get_gc(), make_lv(false, 4));

        REQUIRE(m.hash_and_normalize() == h);

        //nodes should not even exist in the tree
        root -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'0001), m.get_gc(), make_lv(false, 0));
    }

    SECTION("some values")
    {
        auto root = m.get_root_and_invalidate_hash();

        mt m2, m3;

        auto root2 = m2.get_root_and_invalidate_hash();
        auto root3 = m3.get_root_and_invalidate_hash();

        root -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'0001), m.get_gc(), make_lv(true, 0));
        root2 -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'0001), m.get_gc(), make_lv(true, 0));

        root -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'0002), m.get_gc(), make_lv(false, 1));
        root -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'0010), m.get_gc(), make_lv(false, 2));
        root -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'0100), m.get_gc(), make_lv(false, 3));

        root -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'1000), m.get_gc(), make_lv(true, 4));
        root2 -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'1000), m.get_gc(), make_lv(true, 4));
        root3 -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'1000), m.get_gc(), make_lv(true, 4));

        REQUIRE(m.hash_and_normalize() == m2.hash_and_normalize());

        auto* n1 = m.get_subnode_ref_and_invalidate_hash(UInt64Prefix(0x0000'0000'0000'0001),
                                              PrefixLenBits(64));

        auto* v = n1->get_value(UInt64Prefix(0x0000'0000'0000'0001));
        v -> valid = false;

        REQUIRE(m.hash_and_normalize() == m3.hash_and_normalize());
        REQUIRE(m2.hash_and_normalize() != m3.hash_and_normalize());
    }
}


/* Copy of AMT test case for memcache trie */
TEST_CASE("no logical value memcache", "[memcache]")
{
    using value_t = detail::invalidateable_logical_value;

    using metadata_t = SnapshotTrieMetadataBase;
    using prefix_t = UInt64Prefix;

    using mt
        = MemcacheTrie<prefix_t, value_t, 256, NullInterface<8>, metadata_t, &detail::validation_lambda>;

    mt m(0);

    auto h = m.hash_and_normalize(0);

    auto make_lv = [](bool valid, uint64_t id) {
        return detail::invalidateable_logical_value (valid, id);
    };

    SECTION("only empty values")
    {
        auto root = m.get_root_and_invalidate_hash(1);

        root -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'0001), m.get_gc(), 1, m.get_storage(), make_lv(false, 0));
        root -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'0002), m.get_gc(), 1, m.get_storage(), make_lv(false, 1));
        root -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'0010), m.get_gc(), 1, m.get_storage(), make_lv(false, 2));
        root -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'0100), m.get_gc(), 1, m.get_storage(), make_lv(false, 3));
        root -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'1000), m.get_gc(), 1, m.get_storage(), make_lv(false, 4));

        REQUIRE(m.hash_and_normalize(1) == h);

        //nodes should not even exist in the tree
        root -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'0001), m.get_gc(), 1, m.get_storage(), make_lv(false, 0));
    }

    SECTION("some values")
    {
        auto root = m.get_root_and_invalidate_hash(1);

        mt m2(0), m3(0);

        auto root2 = m2.get_root_and_invalidate_hash(1);
        auto root3 = m3.get_root_and_invalidate_hash(1);

        root -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'0001), m.get_gc(), 1, m.get_storage(), make_lv(true, 0));
        root2 -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'0001), m2.get_gc(), 1, m.get_storage(), make_lv(true, 0));

        root -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'0002), m.get_gc(), 1, m.get_storage(), make_lv(false, 1));
        root -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'0010), m.get_gc(), 1, m.get_storage(), make_lv(false, 2));
        root -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'0100), m.get_gc(), 1, m.get_storage(), make_lv(false, 3));

        root -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'1000), m.get_gc(), 1, m.get_storage(), make_lv(true, 4));
        root2 -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'1000), m2.get_gc(), 1, m2.get_storage(), make_lv(true, 4));
        root3 -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'1000), m3.get_gc(), 1, m3.get_storage(), make_lv(true, 4));

        REQUIRE(m.hash_and_normalize(1) == m2.hash_and_normalize(1));

        auto* n1 = m.get_subnode_ref_and_invalidate_hash(UInt64Prefix(0x0000'0000'0000'0001),
                                              PrefixLenBits(64), 2);

        auto* v = n1->get_value(UInt64Prefix(0x0000'0000'0000'0001), m.get_storage(), false);
        REQUIRE(!!v);
        v -> valid = false;

        REQUIRE(m.hash_and_normalize(2) == m3.hash_and_normalize(2));

        REQUIRE(m2.hash_and_normalize(2) != m3.hash_and_normalize(2));
    }

    SECTION("get value queries")
    {
        auto root = m.get_root_and_invalidate_hash(0);

        root -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'0001), m.get_gc(), 0, m.get_storage(), make_lv(true, 0));

        root -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'0002), m.get_gc(), 0, m.get_storage(), make_lv(false, 1));
        root -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'0010), m.get_gc(), 0, m.get_storage(), make_lv(false, 2));
        root -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'0100), m.get_gc(), 0, m.get_storage(), make_lv(false, 3));

        root -> template insert<&detail::no_merge_fn>(UInt64Prefix(0x0000'0000'0000'1000), m.get_gc(), 0, m.get_storage(), make_lv(true, 4));


        REQUIRE(m.get_value(UInt64Prefix(0x0000'0000'0000'0001)) != nullptr);
        REQUIRE(m.get_value(UInt64Prefix(0x0000'0000'0000'0002)) == nullptr);


        auto* n1 = m.get_subnode_ref_and_invalidate_hash(UInt64Prefix(0x0000'0000'0000'0001),
                                              PrefixLenBits(64), 0);

        auto* v = n1->get_value(UInt64Prefix(0x0000'0000'0000'0001), m.get_storage(), false);
        REQUIRE(!!v);
        v -> valid = false;

        v = n1->get_value(UInt64Prefix(0x0000'0000'0000'0001), m.get_storage(), false);

        REQUIRE(!v);

        v = n1->get_value(UInt64Prefix(0x0000'0000'0000'0001), m.get_storage(), true);

        REQUIRE(!!v);
    }
}

} // namespace trie

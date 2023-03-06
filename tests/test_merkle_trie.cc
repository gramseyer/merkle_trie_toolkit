#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "mtt/common/debug_macros.h"

#include "mtt/trie/merkle_trie.h"

#include <utils/serialize_endian.h>

#include "tests/offer_metadata.h"
#include "tests/test_types.h"

#include <sodium.h>

#include <iostream>

using namespace trie;
using namespace trie::test;

TEST_CASE("insert" , "[trie]")
{
	using mt = MerkleTrie<ByteArrayPrefix<32>>;

	mt trie;
	mt :: prefix_t key_buf;

	for (unsigned char i = 0; i < 10; i++) {
		std::array<unsigned char, 32> buf;
		crypto_generichash(buf.data(), buf.size(), &i, 1, NULL, 0);

		key_buf = mt :: prefix_t(buf);
		trie.insert(key_buf);
	}

	REQUIRE(10 == trie.uncached_size());
}

TEST_CASE("short key", "[trie]")
{
	using mt = MerkleTrie<ByteArrayPrefix<1>>;
	mt trie;
	mt :: prefix_t key_buf;
	for (unsigned char i = 0; i < 100; i += 10) {
		utils::write_unsigned_big_endian(key_buf, i);
		trie.insert(key_buf);
	}
	REQUIRE(10 == trie.uncached_size());
	for (unsigned char i = 0; i < 100; i += 10) {
		utils::write_unsigned_big_endian(key_buf, i);
		trie.insert(key_buf);
	}
	REQUIRE(10 == trie.uncached_size());
}

TEST_CASE("hash trie", "[trie]")
{

	using mt = MerkleTrie<ByteArrayPrefix<2>>;
	mt trie;
	mt :: prefix_t key_buf;

	Hash hash1, hash2;

	for (uint16_t i = 0; i < 1000; i+= 20) {
		utils::write_unsigned_big_endian(key_buf, i);
		trie.insert(key_buf);
	}
	REQUIRE(50 == trie.uncached_size());

	trie.hash(hash1);
	
	for (uint16_t i = 0; i < 1000; i+= 20) {
		utils::write_unsigned_big_endian(key_buf, i);
		trie.insert(key_buf);
	}
	REQUIRE(50 == trie.uncached_size());
	trie.hash(hash2);

	REQUIRE(hash1 == hash2);

	uint16_t k = 125;
	utils::write_unsigned_big_endian(key_buf, k);
	trie.insert(key_buf);
	trie.hash(hash2);
	REQUIRE(hash1 != hash2);
}

TEST_CASE("merge novalue simple case", "[trie]")
{
	using mt = MerkleTrie<ByteArrayPrefix<2>>;
	mt trie;
	mt trie2;
	mt :: prefix_t key_buf;
	Hash hash1, hash2;

	for (uint16_t i = 0; i < 100; i+= 20) {
		utils::write_unsigned_big_endian(key_buf, i);
		trie.insert(key_buf);
		trie2.insert(key_buf);
	}
	REQUIRE(5 == trie.uncached_size());
	REQUIRE(5 == trie2.uncached_size());

	trie.hash(hash1);
	trie2.hash(hash2);
	REQUIRE(hash1 == hash2);

	trie.merge_in(std::move(trie2));

	trie.hash(hash2);
	REQUIRE(hash1 == hash2);
}

TEST_CASE("merge value simple case", "[trie]")
{

	using mt = MerkleTrie<ByteArrayPrefix<2>, EmptyValue, CombinedMetadata<SizeMixin>>;

	mt trie;
	mt trie2;
	mt :: prefix_t key_buf;

	Hash hash1, hash2;

	for (uint16_t i = 0; i < 100; i+= 20) {
		utils::write_unsigned_big_endian(key_buf, i);
		trie.insert(key_buf);
		trie2.insert(key_buf);
	}
	REQUIRE(5 == trie.uncached_size());
	REQUIRE(5 == trie2.uncached_size());

	trie.hash(hash1);
	trie2.hash(hash2);
	REQUIRE(hash1 == hash2);

	trie.merge_in(std::move(trie2));

	trie.hash(hash2);
	REQUIRE(hash1 == hash2);

	REQUIRE(trie.metadata_integrity_check());
}



void check_equality(MerkleTrie<ByteArrayPrefix<2>>& t1, MerkleTrie<ByteArrayPrefix<2>>& t2) {
	Hash hash1, hash2;

	t1.hash(hash1);
	t2.hash(hash2);
	REQUIRE(hash1 ==hash2);
	//REQUIRE(0, memcmp(hash1.data(), hash2.data(), 32));
	REQUIRE(t1.uncached_size() == t2.uncached_size());
}


TEST_CASE("merge some shared keys", "[trie]")
{
	using mt = MerkleTrie<ByteArrayPrefix<2>>;
	mt trie;
	mt mergein;
	mt expect;
	mt :: prefix_t key;



	key[0] = 0xFF;
	key[1] = 0;
	trie.insert(key);
	mergein.insert(key);
	expect.insert(key);		

	//Full match (case 0)
	trie.merge_in(std::move(mergein));
	check_equality(trie, expect);

	// a branch (case 4)
	key[0] = 0xF0;
	mergein.clear();
	mergein.insert(key);
	expect.insert(key);

	trie.merge_in(std::move(mergein));

	check_equality(trie, expect);

	//trie._log(std::string("TRIE:  "));
	//expect._log(std::string("EXPC:  "));
	// case 2
	key[0] = 0xF1;
	mergein.clear();
	mergein.insert(key);
	expect.insert(key);

	trie.merge_in(std::move(mergein));
	check_equality(trie, expect);

	//trie._log(std::string("TRIE:  "));
	//expect._log(std::string("EXPC:  "));
	// case 3
	key[0] = 0xA0;
	mergein.clear();
	mergein.insert(key);
	expect.insert(key);
	key[0] = 0xA1;
	mergein.insert(key);
	expect.insert(key);
	key[0] = 0xA2;
	trie.insert(key);
	expect.insert(key);

	trie.merge_in(std::move(mergein));
	check_equality(trie, expect);

	//trie._log(std::string("TRIE:  "));
	//expect._log(std::string("EXPC:  "));
	//case 1
	key[0] = 0xA1;
	mergein.clear();
	mergein.insert(key);
	expect.insert(key);

	key[0] = 0xA3;
	mergein.insert(key);
	expect.insert(key);

	trie.merge_in(std::move(mergein));
	check_equality(trie, expect);
}

TEST_CASE("perform delete", "[trie]")
{
	using mt = MerkleTrie<ByteArrayPrefix<2>>;
	mt trie;
	mt :: prefix_t key_buf;
	for (uint16_t i = 0; i < 1000; i+=20) {
		utils::write_unsigned_big_endian(key_buf, i);
		trie.insert(key_buf);
	}

	REQUIRE(50 == trie.uncached_size());

	for (uint16_t i = 0; i < 1000; i += 40) {
		utils::write_unsigned_big_endian(key_buf, i);
		REQUIRE(trie.perform_deletion(key_buf));
	}

	REQUIRE(25 == trie.uncached_size());
}

TEST_CASE("split", "[trie]")
{
	using OfferWrapper = XdrTypeWrapper<Offer, &offer_serialize_fn>;

	using TrieT = MerkleTrie<ByteArrayPrefix<2>, OfferWrapper, CombinedMetadata<OrderbookMetadata>>;

	TrieT trie;
	TrieT::prefix_t key_buf;

	Offer offer;
	offer.amount = 10;
	offer.minPrice = 1;

	for (uint16_t i = 0; i < 1000; i+=20) {
		utils::write_unsigned_big_endian(key_buf, i);
		trie.insert(key_buf, OfferWrapper(offer));
	}
	REQUIRE(50 == trie.size());

	auto split = trie.endow_split(5);//trie.metadata_split<EndowmentPredicate>(5);

	REQUIRE(split.size() == 0);

	auto split2 = trie.endow_split(10);//metadata_split<EndowmentPredicate>(10);
	
	REQUIRE(split2.size() == 1);
	REQUIRE(trie.size() == 49);


	auto split3 = trie.endow_split(15);//metadata_split<EndowmentPredicate>(15);
	REQUIRE(split3.size() == 1);
	REQUIRE(trie.size() == 48);

	auto split4 = trie.endow_split(252);//metadata_split<EndowmentPredicate>(252);

	REQUIRE(split4.size() == 25);
	REQUIRE(trie.size() == 23);

	REQUIRE(trie.metadata_integrity_check());
}

TEST_CASE("endow below threshold", "[trie]")
{
	using ValueT = XdrTypeWrapper<Offer, &offer_serialize_fn>;

	using TrieT = MerkleTrie<ByteArrayPrefix<2>, ValueT, CombinedMetadata<OrderbookMetadata>>;

	TrieT trie;
	TrieT::prefix_t buf;

	ValueT offer;
	offer.amount = 10;
	offer.minPrice = 1;

	for (uint16_t i = 0; i < 1000; i+=20) {
		utils::write_unsigned_big_endian(buf, i);
		trie.insert(buf, XdrTypeWrapper<Offer, &offer_serialize_fn>(offer));
	}
	REQUIRE(50 == trie.size());

	uint16_t threshold = 35;
	utils::write_unsigned_big_endian(buf, threshold);

	REQUIRE(trie.endow_lt_key(buf) == 20);

	threshold = 20;
	utils::write_unsigned_big_endian(buf, threshold);

	REQUIRE(trie.endow_lt_key(buf) == 10);

	threshold = 21;
	utils::write_unsigned_big_endian(buf, threshold);
	REQUIRE(trie.endow_lt_key(buf) == 20);

	threshold = 500;
	utils::write_unsigned_big_endian(buf, threshold);

	REQUIRE(trie.endow_lt_key(buf) == 250);


	threshold = 2000;
	utils::write_unsigned_big_endian(buf, threshold);
	REQUIRE(trie.endow_lt_key(buf) == 500);
}

TEST_CASE("empty hash", "[trie]")
{
	using ValueT = XdrTypeWrapper<Offer, &offer_serialize_fn>;
	using TrieT = MerkleTrie<ByteArrayPrefix<2>, ValueT, CombinedMetadata<OrderbookMetadata>>;


	TrieT trie;
	Hash hash;

	trie.hash(hash);

	MerkleTrie<ByteArrayPrefix<2>, EmptyValue, CombinedMetadata<OrderbookMetadata>> trie2;

	Hash hash2;
	trie2.hash(hash2);

	REQUIRE(hash == hash2);
}

TEST_CASE("get value from nonempty", "[trie]")
{
	using ValueT = XdrTypeWrapper<Offer, &offer_serialize_fn>;
	using TrieT = MerkleTrie<ByteArrayPrefix<2>, ValueT, CombinedMetadata<OrderbookMetadata>>;

	ValueT offer;
	offer.amount = 10;
	offer.minPrice = 1;

	TrieT trie;
	TrieT::prefix_t buf;

	uint16_t i = 0x00FF;

	utils::write_unsigned_big_endian(buf, i);
	trie.insert(buf, ValueT(offer));

	auto query = [&] (uint16_t val) -> ValueT const*
	{
		utils::write_unsigned_big_endian(buf, val);
		return trie.get_value(buf);
	};

	REQUIRE(query(0x0000) == nullptr);
	REQUIRE(query(0xFF00) == nullptr);
	REQUIRE(query(0xFFFF) == nullptr);
}


TEST_CASE("get value from empty", "[trie]")
{
	using ValueT = XdrTypeWrapper<Offer, &offer_serialize_fn>;
	using TrieT = MerkleTrie<ByteArrayPrefix<2>, ValueT, CombinedMetadata<OrderbookMetadata>>;

	ValueT offer;
	offer.amount = 10;
	offer.minPrice = 1;

	TrieT trie;
	TrieT::prefix_t buf;

	auto query = [&] (uint16_t val) -> ValueT const*
	{
		utils::write_unsigned_big_endian(buf, val);
		return trie.get_value(buf);
	};

	REQUIRE(query(0x0000) == nullptr);
	REQUIRE(query(0xFF00) == nullptr);
	REQUIRE(query(0xFFFF) == nullptr);
}

TEST_CASE("hash empty trie", "[trie]")
{
	using prefix_t = trie::ByteArrayPrefix<2>;
    using metadata_t
        = trie::CombinedMetadata<trie::SizeMixin>;
    using value_t = trie::PointerValue<Offer, &offer_serialize_fn>;

    using trie_t = trie::MerkleTrie<prefix_t, value_t, metadata_t>;

    trie_t trie;

    SECTION("no elts")
    {
    	Hash h;
    	trie.hash(h);
    }

    SECTION("some elts")
    {
    	value_t offer(std::make_unique<Offer>());
		offer.v->amount = 10;
		offer.v->minPrice = 1;

		trie_t trie;
		trie_t::prefix_t buf;

    	trie.insert(buf, std::move(offer));

    	Hash h;
    	trie.hash(h);
    }
}

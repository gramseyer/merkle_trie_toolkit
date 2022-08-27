#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "mtt/trie/debug_macros.h"
#include "mtt/trie/merkle_trie.h"
#include "mtt/trie/types.h"

#include "mtt/utils/serialize_endian.h"

using namespace trie;

TEST_CASE("size insert", "[trie]")
{
	using mt = MerkleTrie<ByteArrayPrefix<2>, EmptyValue, CombinedMetadata<SizeMixin>>;
	mt trie;
	mt :: prefix_t key_buf;
	for (uint16_t i = 0; i < 1000; i+= 20) {
		utils::write_unsigned_big_endian(key_buf, i);
		trie.insert(key_buf);
	}

	REQUIRE(50 == trie.uncached_size());
	REQUIRE(50 == trie.size());

	REQUIRE(trie.metadata_integrity_check());
}

TEST_CASE("size merge", "[trie]")
{
	using mt = MerkleTrie<ByteArrayPrefix<2>, EmptyValue, CombinedMetadata<SizeMixin>>;

	mt trie;
	mt :: prefix_t key_buf;
	for (uint16_t i = 0; i < 80; i+=40) {
		utils::write_unsigned_big_endian(key_buf, i);
		trie.insert(key_buf);
	}
	mt trie2;
	for (uint16_t i = 0; i < 80; i+=20) {
		utils::write_unsigned_big_endian(key_buf, i);
		trie2.insert(key_buf);
	}
	REQUIRE(2 == trie.size());

	trie.merge_in(std::move(trie2));

	REQUIRE(4 == trie.uncached_size());
	REQUIRE(4 == trie.size());

	REQUIRE(trie.metadata_integrity_check());
}

TEST_CASE("size merge larger", "[trie]")
{
	using mt = MerkleTrie<ByteArrayPrefix<2>, EmptyValue, CombinedMetadata<SizeMixin>>;

	mt trie;
	mt :: prefix_t key_buf;
	for (uint16_t i = 0; i < 1000; i+=40) {
		utils::write_unsigned_big_endian(key_buf, i);
		trie.insert(key_buf);
	}

	mt trie2;
	
	for (uint16_t i = 0; i < 1000; i+=20) {
		utils::write_unsigned_big_endian(key_buf, i);
		trie2.insert(key_buf);
	}
	REQUIRE(25 == trie.size());

	trie.merge_in(std::move(trie2));

	REQUIRE(50 == trie.uncached_size());
	REQUIRE(50 == trie.size());

	REQUIRE(trie.metadata_integrity_check());
}


TEST_CASE("size delete direct", "[trie]")
{
	using mt = MerkleTrie<ByteArrayPrefix<2>, EmptyValue, CombinedMetadata<SizeMixin>>;

	mt trie;
	mt :: prefix_t key_buf;
	for (uint16_t i = 0; i < 1000; i+=20) {
		utils::write_unsigned_big_endian(key_buf, i);
		trie.insert(key_buf);
	}

	REQUIRE(50 == trie.size());
	REQUIRE(50 == trie.uncached_size());

	for (uint16_t i = 0; i < 1000; i += 40) {
		utils::write_unsigned_big_endian(key_buf, i);
		REQUIRE(trie.perform_deletion(key_buf));
	}

	REQUIRE(25 == trie.uncached_size());
	REQUIRE(25 == trie.size());

	REQUIRE(trie.metadata_integrity_check());
}


TEST_CASE("size delete marked", "[trie]")
{

	using mt = MerkleTrie<ByteArrayPrefix<2>, EmptyValue, CombinedMetadata<SizeMixin, DeletableMixin>>;

	mt trie;
	mt :: prefix_t key_buf;

	for (uint16_t i = 0; i < 1000; i+=20) {
		utils::write_unsigned_big_endian(key_buf, i);
		trie.insert(key_buf);
	}

	REQUIRE(50 == trie.size());
	REQUIRE(50 == trie.uncached_size());

	for (uint16_t i = 0; i < 1000; i += 40) {
		utils::write_unsigned_big_endian(key_buf, i);
		REQUIRE(trie.mark_for_deletion(key_buf));
	}
	REQUIRE(50 == trie.size());

	trie.perform_marked_deletions();
	REQUIRE(25 == trie.size());

	REQUIRE(trie.metadata_integrity_check());
}

TEST_CASE("ignore deletions during hashing", "[trie]")
{
	using mt = MerkleTrie<ByteArrayPrefix<2>, EmptyValue, CombinedMetadata<SizeMixin, DeletableMixin>>;

	mt trie;
	mt :: prefix_t key_buf;

	for (uint16_t i = 0; i < 1000; i+=20) {
		utils::write_unsigned_big_endian(key_buf, i);
		trie.insert(key_buf);
	}

	REQUIRE(50 == trie.size());
	REQUIRE(50 == trie.uncached_size());
	
	Hash hash_buf_1, hash_buf_2, hash_buf_3;

	trie.hash(hash_buf_1);

	for (uint16_t i = 0; i < 1000; i += 40) {
		utils::write_unsigned_big_endian(key_buf, i);
		REQUIRE(trie.mark_for_deletion(key_buf));
	}
	trie.hash(hash_buf_2);

	trie.perform_marked_deletions();

	trie.hash(hash_buf_3);

	REQUIRE(hash_buf_1 != hash_buf_2);
	REQUIRE(hash_buf_2 == hash_buf_3);
}

TEST_CASE("size delete mark and unmark", "[trie]")
{

	using mt = MerkleTrie<ByteArrayPrefix<2>, EmptyValue, CombinedMetadata<SizeMixin, DeletableMixin>>;

	mt trie;
	mt :: prefix_t key_buf;
	
	for (uint16_t i = 0; i < 1000; i+=20) {
		utils::write_unsigned_big_endian(key_buf, i);
		trie.insert(key_buf);
	}

	for (uint16_t i = 0; i < 1000; i+=40) {
		utils::write_unsigned_big_endian(key_buf, i);
		trie.mark_for_deletion(key_buf);
		uint16_t j = i + 20;
		utils::write_unsigned_big_endian(key_buf, j);
		trie.unmark_for_deletion(key_buf);
	}

	for (uint16_t i = 0; i < 1000; i+=80) {
		utils::write_unsigned_big_endian(key_buf, i);
		trie.unmark_for_deletion(key_buf);
	}

	REQUIRE(50 == trie.size());
	trie.perform_marked_deletions();
	REQUIRE(38 == trie.size());

	REQUIRE(trie.metadata_integrity_check());

}

/*	void _test_delete_lt_key() {
		TEST_START();

		using mt = MerkleTrie<ByteArrayPrefix<2>, EmptyValue, CombinedMetadata<SizeMixin, DeletableMixin>>;

		mt trie;
		mt :: prefix_t key_buf;
		
		for (uint16_t i = 0; i < 1000; i+=20) {
			write_unsigned_big_endian(key_buf, i);
			trie.insert(key_buf);
		}

		REQUIRE(50, trie.size());

		uint16_t threshold = 0;

		write_unsigned_big_endian(key_buf, threshold);
		trie.mark_subtree_lt_key_for_deletion(key_buf);

		REQUIRE(trie.num_deleted_subnodes(), 0);

		threshold = 200;

		write_unsigned_big_endian(key_buf, threshold);

		trie.mark_subtree_lt_key_for_deletion(key_buf);
		REQUIRE(trie.num_deleted_subnodes(), 10);
	}

	void _test_delete_lt_key_long() {
		TEST_START();
		using mt = MerkleTrie<ByteArrayPrefix<8>, EmptyValue, CombinedMetadata<SizeMixin, DeletableMixin>>;

		mt trie;
		mt :: prefix_t buf;

		uint64_t i = 0xFF00FF00;
		write_unsigned_big_endian(buf, i);
		trie.insert(buf);

		i = 0xFF00FF10;
		write_unsigned_big_endian(buf, i);
		trie.insert(buf);

		i = 0xFF00FF30;
		write_unsigned_big_endian(buf, i);
		trie.insert(buf);


		uint64_t threshold = 0xFF00FF10;
		write_unsigned_big_endian(buf, threshold);
		trie.mark_subtree_lt_key_for_deletion(buf);
		REQUIRE(trie.num_deleted_subnodes(), 1);


		i = 0xF0000000;
		write_unsigned_big_endian(buf, i);
		trie.insert(buf);


		i = 0xF0000001;
		write_unsigned_big_endian(buf, i);
		trie.insert(buf);

		i = 0xFE000000;
		write_unsigned_big_endian(buf, i);
		trie.insert(buf);

		i = 0xFE000001;
		write_unsigned_big_endian(buf, i);
		trie.insert(buf);



		trie.clear_marked_deletions();

		threshold = 0xFD000000;
		write_unsigned_big_endian(buf, threshold);
		trie.mark_subtree_lt_key_for_deletion(buf);

		REQUIRE(trie.num_deleted_subnodes(), 2);
	}

	void _test_delete_lt_key_long_weirdcase() {
		TEST_START();
		//proves that "the impossible happened" case actually can happen reasonably simply.

		using mt = MerkleTrie<ByteArrayPrefix<8>, EmptyValue, CombinedMetadata<SizeMixin, DeletableMixin>>;

		mt trie;
		mt :: prefix_t buf;

		uint64_t i = 0xFF000001;
		write_unsigned_big_endian(buf, i);
		trie.insert(buf);

		i = 0xFF000000;
		write_unsigned_big_endian(buf, i);
		trie.insert(buf);
		i = 0xFF000002;
		write_unsigned_big_endian(buf, i);
		trie.insert(buf);

		uint64_t threshold = 0x0000F000;
		write_unsigned_big_endian(buf, threshold);
		trie.mark_subtree_lt_key_for_deletion(buf);
		REQUIRE(trie.num_deleted_subnodes(), 0);
	} */


TEST_CASE("rollback disjoint", "[trie]")
{
	using mt = MerkleTrie<ByteArrayPrefix<2>, EmptyValue, CombinedMetadata<SizeMixin, DeletableMixin, RollbackMixin>>;

	mt trie;
	mt :: prefix_t key_buf;

	for (uint16_t i = 0; i < 1000; i+=20) {
		utils::write_unsigned_big_endian(key_buf, i);
		trie.insert(key_buf);
	}

	for (uint16_t i = 10; i < 1010; i += 20) {
		utils::write_unsigned_big_endian(key_buf, i);
		trie.template insert<RollbackInsertFn<EmptyValue>>(key_buf);
	}

	REQUIRE(100 == trie.size());

	trie.do_rollback();

	REQUIRE(50 == trie.uncached_size());
	REQUIRE(50 == trie.size());

}

TEST_CASE("clear rollback", "[trie]")
{
	using mt = MerkleTrie<ByteArrayPrefix<4>, EmptyValue, CombinedMetadata<SizeMixin, DeletableMixin, RollbackMixin>>;

	mt trie;
	mt :: prefix_t key_buf;
	
	for (uint32_t i = 0; i < 10000; i+=207) {
		utils::write_unsigned_big_endian(key_buf, i);
		trie.insert(key_buf);
	}


	for (uint16_t i = 10; i < 10100; i += 207) {
		utils::write_unsigned_big_endian(key_buf, i);
		trie.template insert<RollbackInsertFn<EmptyValue>>(key_buf);
	}
	
	REQUIRE(98 == trie.size());

	trie.clear_rollback();

	REQUIRE(98 == trie.size());
	REQUIRE(98 == trie.uncached_size());
	REQUIRE(trie.metadata_integrity_check());
}

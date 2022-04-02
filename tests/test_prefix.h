#include <cxxtest/TestSuite.h>

#include <cstdint>
#include <cstring>

#include "mtt/trie/prefix.h"
#include "mtt/trie/build_endian.h"

using namespace trie;
using namespace utils;

class PrefixTestSuite : public CxxTest::TestSuite {
public:

	void test_byte_prefix_branch_bits() {
		uint32_t query = 0x12345678;

		ByteArrayPrefix<4> key_buf;

		write_unsigned_big_endian(key_buf, query);

		TS_ASSERT_EQUALS(key_buf.get_branch_bits(PrefixLenBits{0}), 0x1);
		TS_ASSERT_EQUALS(key_buf.get_branch_bits(PrefixLenBits{4}), 0x2);
		TS_ASSERT_EQUALS(key_buf.get_branch_bits(PrefixLenBits{8}), 0x3);
		TS_ASSERT_EQUALS(key_buf.get_branch_bits(PrefixLenBits{12}), 0x4);
		TS_ASSERT_EQUALS(key_buf.get_branch_bits(PrefixLenBits{16}), 0x5);
		TS_ASSERT_EQUALS(key_buf.get_branch_bits(PrefixLenBits{20}), 0x6);
		TS_ASSERT_EQUALS(key_buf.get_branch_bits(PrefixLenBits{24}), 0x7);
		TS_ASSERT_EQUALS(key_buf.get_branch_bits(PrefixLenBits{28}), 0x8);
	}

	void test_uint64_prefix_branch_bits() {
		uint64_t query = 0x12345678'0000'0000;

		UInt64Prefix key_buf{query};

		TS_ASSERT_EQUALS(key_buf.get_branch_bits(PrefixLenBits{0}), 0x1);
		TS_ASSERT_EQUALS(key_buf.get_branch_bits(PrefixLenBits{4}), 0x2);
		TS_ASSERT_EQUALS(key_buf.get_branch_bits(PrefixLenBits{8}), 0x3);
		TS_ASSERT_EQUALS(key_buf.get_branch_bits(PrefixLenBits{12}), 0x4);
		TS_ASSERT_EQUALS(key_buf.get_branch_bits(PrefixLenBits{16}), 0x5);
		TS_ASSERT_EQUALS(key_buf.get_branch_bits(PrefixLenBits{20}), 0x6);
		TS_ASSERT_EQUALS(key_buf.get_branch_bits(PrefixLenBits{24}), 0x7);
		TS_ASSERT_EQUALS(key_buf.get_branch_bits(PrefixLenBits{28}), 0x8);
	}


	void test_byte_prefix_match_len() {
		uint64_t query = 0xF000'0000;

		ByteArrayPrefix<8> key_buf;

		write_unsigned_big_endian(key_buf, query);

		uint64_t query2 = 0xFF00'0000;
		ByteArrayPrefix<8> key_buf2;
		write_unsigned_big_endian(key_buf2, query2);

		TS_ASSERT_EQUALS(key_buf.get_prefix_match_len(PrefixLenBits{64}, key_buf2, PrefixLenBits{64}), PrefixLenBits{36});
	}


	void test_uint64_prefix_match_len() {
		uint64_t query = 0x0000'0000'F000'0000;

		UInt64Prefix key_buf{query};

		uint64_t query2 = 0x0000'0000'FF00'0000;
		UInt64Prefix key_buf2 {query2};

		TS_ASSERT_EQUALS(key_buf.get_prefix_match_len(PrefixLenBits{64}, key_buf2, PrefixLenBits{64}), PrefixLenBits{36});
	}

	void test_byte_truncate() {
		uint32_t query = 0x12345678;

		ByteArrayPrefix<4> key_buf;

		write_unsigned_big_endian(key_buf, query);

		ByteArrayPrefix<4>  key_buf2;


		uint32_t truncated = 0x12340000;

		write_unsigned_big_endian(key_buf2, truncated);

		key_buf.truncate(PrefixLenBits{16});

		TS_ASSERT_EQUALS(key_buf, key_buf2);

		truncated = 0x12300000;
		write_unsigned_big_endian(key_buf2, truncated);
		
		key_buf.truncate(PrefixLenBits{12});
		TS_ASSERT_EQUALS(key_buf, key_buf2);
	}

	void test_uint64_truncate() {
		uint64_t query = 0x12345678'0000'0000;

		UInt64Prefix key_buf{query};

		uint64_t truncated = 0x12340000'0000'0000;

		UInt64Prefix key_buf2{truncated};

		key_buf.truncate(PrefixLenBits{16});

		TS_ASSERT_EQUALS(key_buf, key_buf2);

		truncated = 0x12300000'0000'0000;
		key_buf2 = UInt64Prefix{truncated};
		key_buf.truncate(PrefixLenBits{12});
		TS_ASSERT_EQUALS(key_buf, key_buf2);
	}
};

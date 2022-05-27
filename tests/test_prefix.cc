#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstring>

#include "mtt/trie/prefix.h"
#include "mtt/trie/build_endian.h"

#include "mtt/utils/serialize_endian.h"

using namespace trie;
using namespace utils;

TEST_CASE("byte_prefix_branch_bits", "[prefix]")
{
	uint32_t query = 0x12345678;

	ByteArrayPrefix<4> key_buf;

	write_unsigned_big_endian(key_buf, query);

	REQUIRE(key_buf.get_branch_bits(PrefixLenBits{0}) == 0x1);
	REQUIRE(key_buf.get_branch_bits(PrefixLenBits{4}) == 0x2);
	REQUIRE(key_buf.get_branch_bits(PrefixLenBits{8}) == 0x3);
	REQUIRE(key_buf.get_branch_bits(PrefixLenBits{12}) == 0x4);
	REQUIRE(key_buf.get_branch_bits(PrefixLenBits{16}) == 0x5);
	REQUIRE(key_buf.get_branch_bits(PrefixLenBits{20}) == 0x6);
	REQUIRE(key_buf.get_branch_bits(PrefixLenBits{24}) == 0x7);
	REQUIRE(key_buf.get_branch_bits(PrefixLenBits{28}) == 0x8);
}

TEST_CASE("uint64_prefix_branch_bits", "[prefix]")
{
	uint64_t query = 0x12345678'0000'0000;

	UInt64Prefix key_buf{query};

	REQUIRE(key_buf.get_branch_bits(PrefixLenBits{0}) == 0x1);
	REQUIRE(key_buf.get_branch_bits(PrefixLenBits{4}) == 0x2);
	REQUIRE(key_buf.get_branch_bits(PrefixLenBits{8}) == 0x3);
	REQUIRE(key_buf.get_branch_bits(PrefixLenBits{12}) == 0x4);
	REQUIRE(key_buf.get_branch_bits(PrefixLenBits{16}) == 0x5);
	REQUIRE(key_buf.get_branch_bits(PrefixLenBits{20}) == 0x6);
	REQUIRE(key_buf.get_branch_bits(PrefixLenBits{24}) == 0x7);
	REQUIRE(key_buf.get_branch_bits(PrefixLenBits{28}) == 0x8);
}

TEST_CASE("byte_prefix_match_len" , "[prefix]")
{
	uint64_t query = 0xF000'0000;

	ByteArrayPrefix<8> key_buf;

	write_unsigned_big_endian(key_buf, query);

	uint64_t query2 = 0xFF00'0000;
	ByteArrayPrefix<8> key_buf2;
	write_unsigned_big_endian(key_buf2, query2);

	REQUIRE(key_buf.get_prefix_match_len(PrefixLenBits{64}, key_buf2, PrefixLenBits{64}) == PrefixLenBits{36});
}


TEST_CASE("uint64_prefix_match_len", "[prefix]")
{
	uint64_t query = 0x0000'0000'F000'0000;

	UInt64Prefix key_buf{query};

	uint64_t query2 = 0x0000'0000'FF00'0000;
	UInt64Prefix key_buf2 {query2};

	REQUIRE(key_buf.get_prefix_match_len(PrefixLenBits{64}, key_buf2, PrefixLenBits{64}) == PrefixLenBits{36});
}

TEST_CASE("test_byte_truncate", "[prefix]")
{
	uint32_t query = 0x12345678;

	ByteArrayPrefix<4> key_buf;

	write_unsigned_big_endian(key_buf, query);

	ByteArrayPrefix<4>  key_buf2;

	uint32_t truncated = 0x12340000;

	write_unsigned_big_endian(key_buf2, truncated);

	key_buf.truncate(PrefixLenBits{16});

	REQUIRE(key_buf == key_buf2);

	truncated = 0x12300000;
	write_unsigned_big_endian(key_buf2, truncated);
	
	key_buf.truncate(PrefixLenBits{12});
	REQUIRE(key_buf == key_buf2);
}

TEST_CASE("uint64_truncate", "[prefix]")
{
	uint64_t query = 0x12345678'0000'0000;

	UInt64Prefix key_buf{query};

	uint64_t truncated = 0x12340000'0000'0000;

	UInt64Prefix key_buf2{truncated};

	key_buf.truncate(PrefixLenBits{16});

	REQUIRE(key_buf == key_buf2);

	truncated = 0x12300000'0000'0000;
	key_buf2 = UInt64Prefix{truncated};
	key_buf.truncate(PrefixLenBits{12});
	REQUIRE(key_buf == key_buf2);
}

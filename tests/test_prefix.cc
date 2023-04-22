#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstring>

#include "mtt/common/prefix.h"

#include <utils/serialize_endian.h>

using namespace trie;
using namespace utils;

TEST_CASE("uint64 prefix to string", "[prefix]")
{
	UInt64Prefix prefix{0x1111'2222'3333'4444};

	REQUIRE(prefix.to_string(PrefixLenBits{0}) == "");
	REQUIRE(prefix.to_string(PrefixLenBits{64}) == "1111222233334444");
	REQUIRE(prefix.to_string(PrefixLenBits{4}) == "1");
	REQUIRE(prefix.to_string(PrefixLenBits{60}) == "111122223333444");
}

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

TEST_CASE("uint64 byte at", "[prefix]")
{
	UInt64Prefix key_buf{0};

	key_buf.at(0) = 0xAA;
	key_buf.at(5) = 0xBB;
	key_buf.at(7) = 0xCC;

	REQUIRE_THROWS(key_buf.at(8));

	REQUIRE(key_buf.uint64() == 0xCC00BB00'000000AA);

	UInt64Prefix key2{0};

	write_unsigned_little_endian(key2, 0xCC00BB00'000000AA);

	REQUIRE(key2 == key_buf);

	UInt64Prefix key3{0};

	write_unsigned_big_endian(key3, 0xAA000000'00BB00CC);

	REQUIRE(key3 == key_buf);

}

TEST_CASE("byteprefix byte at", "[prefix]")
{
	ByteArrayPrefix<8> key_buf;

	key_buf.at(0) = 0xAA;
	key_buf.at(5) = 0xBB;
	key_buf.at(7) = 0xCC;

	REQUIRE_THROWS(key_buf.at(8));

	uint64_t expect = 0xCC00BB00'000000AA;

	ByteArrayPrefix<8> key_buf2;
	write_unsigned_little_endian(key_buf2, expect);

	REQUIRE(key_buf == key_buf2);
}

TEST_CASE("uint64 from_bytes_array", "[prefix]")
{
	UInt64Prefix key;

	uint64_t value = 0xAABBCCDDEEFF0011;

	write_unsigned_big_endian(key, value);

	auto res = key.template get_bytes_array<std::array<uint8_t, 8>>();

	std::vector<uint8_t> input(res.begin(), res.end());

	REQUIRE(input.size() == 8);

	UInt64Prefix key2;
	key2.from_bytes_array(input);
	REQUIRE(key == key2);

	uint64_t query;
	read_unsigned_big_endian(key, query);
	REQUIRE(query == value);
	query = 0;
	read_unsigned_big_endian(key2, query);
	REQUIRE(query == value);
}

TEST_CASE("uint64 write_node_header", "[prefix]")
{
	UInt64Prefix key(0xABCDEF01'23456789);

	auto check = [&](std::vector<uint8_t> expect, PrefixLenBits len) 
	{
		std::vector<uint8_t> out;
		write_node_header(out, key, len);
		REQUIRE(out == expect);
	};

	check({0x00, 0x00}, PrefixLenBits{0});
	check({0x00, 0x04, 0xA0}, PrefixLenBits{4});
	check({0x00, 0x08, 0xAB}, PrefixLenBits{8});
	check({0x00, 0x0C, 0xAB, 0xC0}, PrefixLenBits{12});

	check({0x00, 0x3C, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x80}, PrefixLenBits{60});
	check({0x00, 0x40, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89}, PrefixLenBits{64});
}

TEST_CASE("bytearray write_node_header", "[prefix]")
{
	ByteArrayPrefix<16> key({0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89});

	auto check = [&](std::vector<uint8_t> expect, PrefixLenBits len) 
	{
		std::vector<uint8_t> out;
		write_node_header(out, key, len);
		REQUIRE(out == expect);
	};

	check({0x00, 0x00}, PrefixLenBits{0});
	check({0x00, 0x04, 0xA0}, PrefixLenBits{4});
	check({0x00, 0x08, 0xAB}, PrefixLenBits{8});
	check({0x00, 0x0C, 0xAB, 0xC0}, PrefixLenBits{12});

	check({0x00, 0x3C, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x80}, PrefixLenBits{60});
	check({0x00, 0x40, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89}, PrefixLenBits{64});
	check({0x00, 0x44, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xA0}, PrefixLenBits{68});
}


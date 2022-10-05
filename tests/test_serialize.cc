#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstdio>

#include <utils/serialize_endian.h>

namespace utils
{

TEST_CASE("write big endian", "[utils]")
{
	uint8_t buf[4];
	uint32_t val = 0x01020304;

	write_unsigned_big_endian(buf, val);

	REQUIRE(buf[0] == 0x01);
	REQUIRE(buf[1] == 0x02);
	REQUIRE(buf[2] == 0x03);
	REQUIRE(buf[3] == 0x04);
}

TEST_CASE("write little endian", "[utils]")
{
	uint8_t buf[4];
	uint32_t val = 0x01020304;

	write_unsigned_little_endian(buf, val);

	REQUIRE(buf[0] == 0x04);
	REQUIRE(buf[1] == 0x03);
	REQUIRE(buf[2] == 0x02);
	REQUIRE(buf[3] == 0x01);
}

} /* utils */

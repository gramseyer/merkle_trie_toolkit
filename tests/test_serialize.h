#include <cxxtest/TestSuite.h>

#include <cstdint>
#include <cstdio>

#include "utils/serialize_endian.h"

using namespace utils;

class SerializeTestSuite : public CxxTest::TestSuite {

public:

	void test_write_big_endian()
	{
		uint8_t buf[4];
		uint32_t val = 0x01020304;

		write_unsigned_big_endian(buf, val);

		TS_ASSERT_EQUALS(buf[0], 0x01);
		TS_ASSERT_EQUALS(buf[1], 0x02);
		TS_ASSERT_EQUALS(buf[2], 0x03);
		TS_ASSERT_EQUALS(buf[3], 0x04);
	}

	void test_write_little_endian()
	{
		uint8_t buf[4];
		uint32_t val = 0x01020304;

		write_unsigned_little_endian(buf, val);

		TS_ASSERT_EQUALS(buf[0], 0x04);
		TS_ASSERT_EQUALS(buf[1], 0x03);
		TS_ASSERT_EQUALS(buf[2], 0x02);
		TS_ASSERT_EQUALS(buf[3], 0x01);
	}
};

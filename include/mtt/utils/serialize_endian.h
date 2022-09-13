#pragma once

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

/*! \file serialize_endian.h Utility functions for reading and writing
    quantities in {big,little}-endian format
*/

namespace utils {

//! Reads contents of \a buf into \a value, starting from \a buf[offset],
//! interpreted big endian
template<typename array, std::unsigned_integral T>
static void
write_unsigned_big_endian(array& buf, const T& value, const size_t offset = 0)
{
    constexpr size_t sz = sizeof(T);
    constexpr size_t buf_sz = sizeof(buf);

    static_assert(
        (sz - 1) * 8 <= UINT8_MAX,
        "if this happens we need to account for overflows on mask shift");
    static_assert(sz <= buf_sz, "insufficient buffer size!");

    for (uint8_t loc = 0; loc < sz; loc++) {
        uint8_t shift = ((sz - loc - 1) * 8);
        uint8_t byte = (((value >> shift) & 0xFF));
        buf.at(loc + offset) = byte;
    }
}

//! Appends \a value to \a buf, written in big endian
template<std::unsigned_integral T>
static void
append_unsigned_big_endian(std::vector<uint8_t>& buf, const T& value)
{
    constexpr size_t sz = sizeof(T);

    static_assert(
        (sz - 1) * 8 <= UINT8_MAX,
        "if this happens we need to account for overflows on mask shift");
    for (uint8_t loc = 0; loc < sz; loc++) {
        uint8_t offset = ((sz - loc - 1) * 8);
        buf.push_back(((value >> offset) & 0xFF));
    }
}

//! Serialize \a value in big-endian and write to \a buf (and subsequent bytes)
template<std::unsigned_integral T>
static void
write_unsigned_big_endian(unsigned char* buf, const T& value)
{
    constexpr size_t sz = sizeof(T);

    static_assert(
        (sz - 1) * 8 <= UINT8_MAX,
        "if this happens we need to account for overflows on mask shift");
    for (uint8_t loc = 0; loc < sz; loc++) {
        uint8_t offset = ((sz - loc - 1) * 8);
        buf[loc] = (unsigned char)((value >> offset) & 0xFF);
    }
}

//! Reads contents of \a buf into \a output.
template<std::unsigned_integral T>
static void
read_unsigned_big_endian(const unsigned char* buf, T& output)
{
    constexpr size_t sz = sizeof(T);
    output = 0;
    for (uint8_t loc = 0; loc < sz; loc++) {
        output <<= 8;
        output += buf[loc];
    }
}

//! read into \a output from \a buf.  Assumes buf holds a value written in big
//! endian.
template<typename T, size_t ARRAY_LEN>
static void
read_unsigned_big_endian(const std::array<unsigned char, ARRAY_LEN>& buf,
                         T& output)
{
    static_assert(sizeof(T) <= ARRAY_LEN, "not enough bytes to read");
    read_unsigned_big_endian(buf.data(), output);
}

//! Reads value from \a buf into \a output.  Any \a buf with a [] operator
//! returning a uint8_t works.
template<typename ArrayLike, std::unsigned_integral T>
static void
read_unsigned_big_endian(const ArrayLike& buf, T& output)
{
    constexpr size_t sz = sizeof(T);
    output = 0;
    for (uint8_t loc = 0; loc < sz; loc++) {
        output <<= 8;
        output += buf.at(loc);
    }
}

//! Reads contents of \a buf into \a value, starting from \a buf[offset],
//! interpreted little endian
template<typename array, std::unsigned_integral T>
static void
write_unsigned_little_endian(array& buf,
                             const T& value,
                             const size_t offset = 0)
{
    constexpr size_t sz = sizeof(T);
    constexpr size_t buf_sz = sizeof(buf);

    static_assert(
        (sz - 1) * 8 <= UINT8_MAX,
        "if this happens we need to account for overflows on mask shift");
    static_assert(sz <= buf_sz, "insufficient buffer size!");

    for (uint8_t loc = 0; loc < sz; loc++) {
        uint8_t shift = (loc * 8);
        uint8_t byte = (((value >> shift) & 0xFF));
        buf.at(loc + offset) = byte;
    }
}

//! Serialize \a value in little-endian and write to \a buf (and subsequent
//! bytes)
template<std::unsigned_integral T>
static void
write_unsigned_little_endian(uint8_t* buf, const T& value)
{
    constexpr size_t sz = sizeof(T);

    static_assert(
        (sz - 1) * 8 <= UINT8_MAX,
        "if this happens we need to account for overflows on mask shift");
    for (uint8_t loc = 0; loc < sz; loc++) {
        uint8_t offset = (loc * 8);
        buf[loc] = (unsigned char)((value >> offset) & 0xFF);
    }
}

//! Reads contents of \a buf, in little endian, and returns result.
template<std::unsigned_integral T>
static T
read_unsigned_little_endian(const unsigned char* buf)
{
    constexpr size_t sz = sizeof(T);
    T output = 0;
    for (uint8_t loc = sz; loc != 0; loc--) {
        output <<= 8;
        output += buf[loc - 1];
    }
    return output;
}

template<std::unsigned_integral T>
static T
read_unsigned_little_endian_fixed_size(const uint8_t* buf, size_t to_read)
{
    if (to_read >= sizeof(T)) {
        throw std::runtime_error("invalid read");
    }

    T output = 0;
    for (uint8_t loc = to_read; loc != 0; loc--) {
        output <<= 8;
        output += buf[loc - 1];
    }
    return output;
}

} // namespace utils

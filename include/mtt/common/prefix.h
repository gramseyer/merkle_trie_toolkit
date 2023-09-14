#pragma once

/*! \file prefix.h

Two implementations of a trie prefix.  One is an arbitrary-length
byte array, and one is specialized for uint64 keys.
*/
#include <algorithm>
#include <atomic>
#include <bit>
#include <compare>
#include <concepts>
#include <cstdint>
#include <cstring>
#include <mutex>

#include <utils/serialize_endian.h>

#include <utils/debug_utils.h> // for array_to_str

namespace trie {

namespace detail {
inline static size_t num_prefix_bytes_(const unsigned int x){ 
	return ((x/8) + (x % 8 == 0?0:1));
} 

} /* detail */

/*! Typesafe way of storing the length of a key in bits.
Too many bugs were caused by accidentaly bits/bytes unit conversions.
*/
struct PrefixLenBits {

	uint16_t len;

	//! Number of bytes needed to store len bits of a prefix.
	size_t num_prefix_bytes() const{
		return detail::num_prefix_bytes_(len);
	}

	uint8_t get_truncate_mask() const {
		return 0xFF << (len % 8);
	}

	//! Number of bytes that are fully used by len bits.
	size_t num_fully_covered_bytes() const {
		return len / 8;
	}

	constexpr std::strong_ordering operator<=>(const PrefixLenBits& other) const {
		return len <=> other.len;
	}

	constexpr bool operator==(const PrefixLenBits& other) const = default;

	constexpr PrefixLenBits operator+(const uint16_t other_bits) const {
		return PrefixLenBits { static_cast<uint16_t>(len + other_bits) };
	} 

	constexpr static unsigned int bytes_to_write_len() {
		return 2;
	}

	constexpr PrefixLenBits(uint16_t len) : len(len) {}
	constexpr PrefixLenBits() : len(0) {}
};

namespace detail {
template<class T>
concept TriePrefix_get_prefix_match_len 
	= requires(
		const T self, 
		const PrefixLenBits& a, 
		const T& b,
		const PrefixLenBits& c) 
	{
		requires std::same_as<PrefixLenBits, decltype(
			self.get_prefix_match_len(a, b, c))>;
	};

template<class T>
concept TriePrefix_get_branch_bits
	= requires(
		T self,
		const PrefixLenBits& a) {

		requires std::same_as<uint8_t, decltype(self.get_branch_bits(a))>;
	};

template<class T>
concept TriePrefix_truncate
	= requires(
		T self,
		const PrefixLenBits& a) {

		self.truncate(a);
	};
template<class T>
concept TriePrefix_spaceship
	= 	requires(const T a, const T b) {
		a <=> b;
		a == b;
	};
} /* detail */

//! Concept describing required methods for trie prefixes.
template <class T>
concept TriePrefix = detail::TriePrefix_get_prefix_match_len<T>
	&& detail::TriePrefix_get_branch_bits<T>
	&& detail::TriePrefix_truncate<T>
	&& detail::TriePrefix_spaceship<T>
	&& requires {
	{ T() };

	requires std::same_as<size_t, decltype(T::size_bytes())>;
};

struct slice_ctor_t {};

/*! Generic prefix of arbitrary length.
Prefix is broken into pieces of width BRANCH_BITS, although
in practice we always use BRANCH_BITS=4.
*/
template<uint16_t MAX_LEN_BYTES, uint8_t BRANCH_BITS = 4>
class ByteArrayPrefix {

	static_assert(std::endian::native == std::endian::little, "big endian unimplemented");
	static_assert(BRANCH_BITS == 4, "unimplemented otherwise");

	constexpr static uint16_t WORDS 
		= (MAX_LEN_BYTES / 8) + (MAX_LEN_BYTES % 8 == 0?0:1); //round up
	
	std::array<uint64_t, WORDS> data;

	constexpr static uint16_t MAX_LEN_BITS = 8 * MAX_LEN_BYTES;

	constexpr static uint64_t BRANCH_MASK 
		= (static_cast<uint64_t>(1) << (BRANCH_BITS)) - 1;

	template<uint16_t len, uint8_t b>
	friend class ByteArrayPrefix;

public:

	ByteArrayPrefix()
		: data() {
			data.fill(0);
		}

	// this method in particular requires little endianness
	template<typename ArrayLike = std::array<uint8_t, MAX_LEN_BYTES>>
	ByteArrayPrefix(const ArrayLike& input)
		: data() {
			
			static_assert(sizeof(ArrayLike) == MAX_LEN_BYTES, "size mismatch");

			auto* ptr = reinterpret_cast<unsigned char*>(data.data());
			std::memcpy(ptr, input.data(), MAX_LEN_BYTES);
	}

	template<uint16_t other_len>
	ByteArrayPrefix(const ByteArrayPrefix<other_len>& other)
		: data()
		{
			static_assert(other_len >= MAX_LEN_BYTES, "other too short");
			std::memcpy(
				reinterpret_cast<uint8_t*>(data.data()),
				reinterpret_cast<const uint8_t*>(other.data.data()),
				MAX_LEN_BYTES);
		}

	ByteArrayPrefix(const uint8_t* ptr, slice_ctor_t)
		: data()
	{
		std::memcpy(
			reinterpret_cast<uint8_t*>(data.data()),
			ptr, 
			MAX_LEN_BYTES);
	}

	//! Returns the number of bits that match between this and \a other,
	//! rounded down to the nearest multiple of BRANCH_BITS.
	template<uint16_t OTHER_MAX_LEN_BYTES> 
	PrefixLenBits get_prefix_match_len(
		const PrefixLenBits& self_len, 
		const ByteArrayPrefix<OTHER_MAX_LEN_BYTES>& other, 
		const PrefixLenBits& other_len) const
	{
		static_assert(MAX_LEN_BYTES <= OTHER_MAX_LEN_BYTES, "other too short");

		// length in bits
		size_t res = MAX_LEN_BYTES * 8;

		for (size_t i = 0; i < WORDS; i++) {
			uint64_t local = data[i] ^ other.data[i];
			if (local) {

				size_t word_offset = __builtin_ctzll(local);
				word_offset -= word_offset % 8;

				if ((((local >> word_offset) & 0xF0) == 0)
				 && (((local >> word_offset) & 0x0F) != 0)){
					word_offset += 4;
				}
				res = std::min((i * 64) + word_offset, res);
				break;
			}
		}
		uint16_t res_final = res - res % BRANCH_BITS;
		return std::min<PrefixLenBits>( { res_final, self_len, other_len} );
	}

	//! get the BRANCH_BITS bits that follow a specific length point.
	//! I.e. if prefix is 0xABCD, get_branch_bits(4) = B
	uint8_t get_branch_bits(const PrefixLenBits& branch_point) const {
		if (branch_point.len >= MAX_LEN_BITS) {
			throw std::runtime_error("can't branch beyond end");
		}

		uint16_t word_idx = branch_point.len / 64;

		uint16_t byte_offset = branch_point.len & 0x0038;//0b0000'0000'0011'1000;

		//uint16_t byte_offset = (branch_point.len % 64) / 8;

		uint8_t byte = (data[word_idx] >> byte_offset /*(8 * byte_offset) */) & 0xFF;

		return (branch_point.len % 8 == 0 ? byte >> 4 : byte) & 0x0F;
	}

	//! Truncate a prefix to a specific length.  Bits beyond truncate_point
	//! are set to 0.
	void truncate(const PrefixLenBits& truncate_point) {
		if (truncate_point.len >= MAX_LEN_BITS) {
			throw std::runtime_error("can't truncate beyond end");
		}

		uint16_t word_idx = truncate_point.len / 64;
		//uint16_t byte_offset = (truncate_point.len % 64) / 8;
		//uint16_t word_offset = 8 * byte_offset;
		uint16_t word_offset = truncate_point.len & 0x0038;

/*		constexpr uint64_t truncate_base = 0xFFFF'FFFF'FFFF'FF0F;
		uint64_t truncate_mask3 = truncate_base >> (((truncate_point.len & 0x4) == 0 )? 8 : 0);
		truncate_mask3 = ~(truncate_mask3 << (word_offset));
*/

		uint64_t truncate_mask = (static_cast<uint64_t>(1) << word_offset) - 1;
		if (truncate_point.len % 8 != 0) {
			truncate_mask |= (static_cast<uint64_t>(0xF0) << word_offset);
		}

		data[word_idx] &= truncate_mask;
		for (size_t i = word_idx + 1; i < WORDS; i++) {
			data[i] = 0;
		}
	}

	//! Get byte at position i.
	//! Primary use is when writing the prefix.
	uint8_t& operator[](size_t i) {
		uint8_t* data_ptr 
			= reinterpret_cast<uint8_t*>(data.data());
		return data_ptr[i];
	}

	//! const access to byte at position i.
	uint8_t operator[](size_t i) const {
		const uint8_t* data_ptr 
			= reinterpret_cast<const uint8_t*>(data.data());
		return data_ptr[i];
	}

	//! Set the byte at a particular index.
	void set_byte(size_t i, uint8_t byte) {
		if (i >= MAX_LEN_BYTES) {
			throw std::runtime_error("invalid prefix array access!");
		}

		uint8_t* data_ptr = reinterpret_cast<uint8_t*>(data.data());
		data_ptr[i] = byte;
	}

	//! Bounds checked byte access.
	uint8_t& at(size_t i) {
		if (i >= MAX_LEN_BYTES) {
			throw std::runtime_error("invalid prefix array access!");
		}

		uint8_t* data_ptr = reinterpret_cast<uint8_t*>(data.data());
		return data_ptr[i];
	}

	//! Set prefix to be the maximum possible prefix.
	void set_max() {
		data.fill(UINT64_MAX);
	}

	//! Set prefix to empty (all zeros).
	void clear() {
		data.fill(0);
	}

	//! Return an array of bytes representing the prefix's contents.
	template<typename array_t = std::array<uint8_t, MAX_LEN_BYTES>>
	array_t get_bytes_array() const {
		array_t out;

		static_assert(out.size() == MAX_LEN_BYTES, "invalid array type");

		const uint8_t* ptr 
			= reinterpret_cast<const uint8_t*>(data.data());

		std::memcpy(out.data(), ptr, MAX_LEN_BYTES);
		return out;
	}

	void write_bytes_to(std::vector<uint8_t>& out, PrefixLenBits const& prefix_len) const
	{
		const uint8_t bytes_to_write = prefix_len.num_prefix_bytes();

		const uint8_t* ptr 
			= reinterpret_cast<const uint8_t*>(data.data());

		out.insert(out.end(), ptr, ptr + bytes_to_write);
		out.back() &= prefix_len.get_truncate_mask();
	}

	constexpr static size_t size_bytes() {
		return MAX_LEN_BYTES;
	}

	constexpr static PrefixLenBits len() {
		return PrefixLenBits{MAX_LEN_BITS};
	}

	std::strong_ordering operator<=>(const ByteArrayPrefix& other) const {

		if (&other == this) return std::strong_ordering::equal;

		//TODO try the other candidate(compare word by word, in loop);

		auto res = memcmp(
			reinterpret_cast<const uint8_t*>(data.data()),
			reinterpret_cast<const uint8_t*>(other.data.data()),
			MAX_LEN_BYTES);
		if (res < 0) {
			return std::strong_ordering::less;
		}
		if (res > 0) {
			return std::strong_ordering::greater;
		}
		return std::strong_ordering::equal;
	}

	bool operator==(const ByteArrayPrefix& other) const = default;

	std::string to_string(const PrefixLenBits& len) const {
		
		auto bytes = get_bytes_array<std::array<uint8_t, MAX_LEN_BYTES>>();
		auto str = utils::array_to_str(bytes.data(), len.num_prefix_bytes());
		if (len.len % 8 == 4)
		{
			str = str.substr(0, str.size() - 1);
		}
		return str;
	}

	//! Sets the bits immediately following the first fixed_len_bits bits
	//! to branch_bits (which should be a valid branch value)
	void
	set_next_branch_bits(
		const PrefixLenBits fixed_len_bits, const unsigned char branch_bits) {
		
		unsigned int byte_index = fixed_len_bits.len / 8;
		uint8_t remaining_bits = fixed_len_bits.len % 8;

		if (byte_index >= MAX_LEN_BYTES) {
			throw std::runtime_error("invalid set_next_branch_bits access");
		}

		uint8_t next_byte = at(byte_index);

		next_byte &= (0xFF << (8-remaining_bits));

		uint8_t branch_bits_offset = 8-remaining_bits-BRANCH_BITS;
		next_byte |= (branch_bits << (branch_bits_offset));

		set_byte(byte_index, next_byte);
	}

	uint8_t* underlying_data_ptr() {
		return reinterpret_cast<uint8_t*>(data.data());
	}
};

//! Prefix specialized to case where key is a single uint64_t.
//! Specializing it makes it slightly easier to manage.
//! In particular, it makes it easy to truncate/get next branch bits/etc,
//! since most operations can be done with just one or two bitwise ops
//! (and we don't have to worry about cross-word actions).
class UInt64Prefix {
	uint64_t prefix;

	constexpr static uint8_t BRANCH_BITS = 4;
	constexpr static uint8_t BRANCH_MASK = 0x0F;

	constexpr static uint8_t MAX_LEN_BITS = 64;
	constexpr static uint8_t MAX_LEN_BYTES = 8;

public:

	UInt64Prefix(uint64_t id = 0) : prefix(id) {}

	UInt64Prefix(const uint8_t* ptr, slice_ctor_t) : prefix(0)
	{
		utils::read_unsigned_big_endian(ptr, prefix);
	}

	std::strong_ordering 
	operator<=>(const UInt64Prefix& other) const = default;

	bool 
	operator==(const UInt64Prefix& other) const = default;

	//! Get the bits of the prefix just beyond branch_point
	uint8_t get_branch_bits(const PrefixLenBits& branch_point) const {
		if (branch_point.len >= MAX_LEN_BITS) {
			std::printf("Bad branch bits was %u\n", branch_point.len);
			throw std::runtime_error("can't branch beyond end");
		}
		return (prefix >> (60 - branch_point.len)) & BRANCH_MASK;
	}

	//! Compute the length of the longest matching initial subsequence
	//! of this prefix and the other prefix.
	PrefixLenBits 
	get_prefix_match_len(
		const PrefixLenBits& self_len, 
		const UInt64Prefix& other, 
		const PrefixLenBits& other_len) const {

		uint64_t diff = prefix ^ other.prefix;
		uint16_t computed_bits = MAX_LEN_BITS;

		if (diff != 0) {
			size_t matching_bits = __builtin_clzll(diff);
			uint16_t match_rounded 
				= matching_bits - (matching_bits % BRANCH_BITS);
			computed_bits = match_rounded;
		}
		return std::min<PrefixLenBits>({computed_bits, self_len, other_len});
	}

	//! Truncate the prefix to a defined length
	void truncate(const PrefixLenBits& truncate_point) {
		if (truncate_point.len == 0) {
			prefix = 0;
		} else {
			prefix &= (UINT64_MAX << (64 - truncate_point.len));
		}
	}

	//! Convert prefix to an array of bytes.
	template<typename array_t = std::array<uint8_t, MAX_LEN_BYTES>>
	array_t get_bytes_array() const {
		array_t out;

		static_assert(out.size() == MAX_LEN_BYTES, "size mismatch");

		utils::write_unsigned_big_endian(out, prefix);
		return out;
	}

	void write_bytes_to(std::vector<uint8_t>& out, PrefixLenBits const& prefix_len) const
	{
		utils::append_unsigned_big_endian(out, prefix);
		const uint8_t extra_bytes = 8 - prefix_len.num_prefix_bytes();
		out.erase(out.end() - extra_bytes, out.end());
		out.back() &= prefix_len.get_truncate_mask();
	}

	void
	from_bytes_array(const std::vector<uint8_t>& bytes)
	{
		if (bytes.size() != MAX_LEN_BYTES)
		{
			throw std::runtime_error("invalid initialization from_bytes_array");
		}

		utils::read_unsigned_big_endian(bytes, prefix);
	}

	//! Bounds checked byte access.
	const uint8_t 
	at(size_t i) const {
		if (i >= MAX_LEN_BYTES) {
			throw std::runtime_error("invalid prefix array access!");
		}

		const unsigned char* data_ptr = reinterpret_cast<const uint8_t*>(&prefix);
		return data_ptr[i];
	}

	uint8_t& at(size_t i) {
		if (i >= MAX_LEN_BYTES) {
			throw std::runtime_error("invalid prefix array access!");
		}

		unsigned char* data_ptr = reinterpret_cast<unsigned char*>(&prefix);
		return data_ptr[i];
	}

	uint64_t uint64() const {
		return prefix;
	}

	constexpr static PrefixLenBits len() {
		return PrefixLenBits{MAX_LEN_BITS};
	}

	void clear() {
		prefix = 0;
	}

	std::string to_string(const PrefixLenBits& len) const {
		auto bytes = get_bytes_array<std::array<uint8_t, MAX_LEN_BYTES>>();
		auto str = utils::array_to_str(bytes.data(), len.num_prefix_bytes());
		if (len.len % 8 == 4)
		{
			str = str.substr(0, str.size() - 1);
		}
		return str;
	}

	//! Modify the prefix by setting the bits after fixed_len to bb
	void set_next_branch_bits(PrefixLenBits const& fixed_len, const uint8_t bb) {
		const uint8_t offset = (60-fixed_len.len);	
		const uint64_t mask = ((uint64_t) BRANCH_MASK) << offset;
		const uint64_t adjust = ((uint64_t) bb) << offset;
		prefix = (prefix & (~mask)) | adjust;
	}

	constexpr static size_t size_bytes() {
		return sizeof(uint64_t); // 8
	}
};

template<TriePrefix prefix_t>
static void write_node_header(
	std::vector<unsigned char>& buf, 
	prefix_t const& prefix, 
	const PrefixLenBits& prefix_len_bits)
{
	utils::append_unsigned_big_endian(buf, prefix_len_bits.len);
	prefix.write_bytes_to(buf, prefix_len_bits);
}

} /* trie */

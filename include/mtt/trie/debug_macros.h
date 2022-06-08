#pragma once

#include <cstdio>
#include <iomanip>
#include <sstream>

/*! \file debug_macros.h

A set of debugging macros.  Activate/deactivate based on DEBUG_LEVEL_* settings.
Printouts include file/line information.
*/

#include "mtt/trie/debug_levels.h"

#define TRIE_LOG(s, ...) std::printf((std::string("%-45s") + s + "\n").c_str(), (std::string(__FILE__) + "." + std::to_string(__LINE__) + ":").c_str() __VA_OPT__(,) __VA_ARGS__)

#ifndef LOG
#define LOG(s, ...) TRIE_LOG(s, __VA_ARGS__)
#endif

#ifndef TEST_START_ON
	#if TRIE_DEBUG <= DEBUG_LEVEL_INFO
		#define TEST_START_ON 1
	#endif
#endif

#ifdef TEST_START_ON
#define TEST_START() LOG("Starting Test:%s", __FUNCTION__)
#else
#define TEST_START() (void)0
#endif

#if TRIE_DEBUG <= DEBUG_LEVEL_ERROR
#define TRIE_ERROR(s, ...) LOG(s, __VA_ARGS__)
#define TRIE_ERROR_F(s) s
#else
#define TRIE_ERROR(s, ...) (void)0
#define TRIE_ERROR_F(s) (void)0
#endif

#if TRIE_DEBUG <= DEBUG_LEVEL_INFO
#define TRIE_INFO(s, ...) LOG(s, __VA_ARGS__)
#define TRIE_INFO_F(s) s
#else
#define TRIE_INFO(s, ...) (void)0
#define TRIE_INFO_F(s) (void)0
#endif

#if PROOF_DEBUG <= DEBUG_LEVEL_ERROR
#define PROOF_ERROR(s, ...) LOG(s, __VA_ARGS__)
#define PROOF_ERROR_F(s) s
#else
#define PROOF_ERROR(s, ...) (void)0
#define PROOF_ERROR_F(s) (void)0
#endif

#if PROOF_DEBUG <= DEBUG_LEVEL_INFO
#define PROOF_INFO(s, ...) LOG(s, __VA_ARGS__)
#define PROOF_INFO_F(s) s
#else
#define PROOF_INFO(s, ...) (void)0
#define PROOF_INFO_F(s) (void)0
#endif

namespace debug {
//! Convert a byte array to a hex string.
static std::string array_to_str(const unsigned char* array, const int len) {
	std::stringstream s;
	s.fill('0');
	for (int i = 0; i < len; i++) {
		s<< std::setw(2) << std::hex << (unsigned short)array[i];
	}
	return s.str();
}

template<typename ArrayLike>
[[maybe_unused]]
static std::string
array_to_str(const ArrayLike& array)
{
	return array_to_str(array.data(), array.size());
}

} /* namespace debug */




#pragma once

#include <cstdio>
#include <iomanip>
#include <sstream>

#include "xdr/types.h"

/*! \file debug_macros.h

A set of debugging macros.  Activate/deactivate based on DEBUG_LEVEL_* settings.
Printouts include file/line information.
*/

#ifndef DEBUG_LEVEL_NONE
#define DEBUG_LEVEL_NONE 100
#endif

#ifndef DEBUG_LEVEL_ERROR
#define DEBUG_LEVEL_ERROR 15
#endif

#ifndef DEBUG_LEVEL_INFO
#define DEBUG_LEVEL_INFO 10
#endif

#define TRIE_DEBUG DEBUG_LEVEL_ERROR
#define PROOF_DEBUG DEBUG_LEVEL_NONE

#define TRIE_LOG(s, ...) std::printf((std::string("%-45s") + s + "\n").c_str(), (std::string(__FILE__) + "." + std::to_string(__LINE__) + ":").c_str() __VA_OPT__(,) __VA_ARGS__)

#ifndef LOG
#define LOG(s, ...) TRIE_LOG(s, __VA_ARGS__)
#endif

#ifndef TEST_START

#if TRIE_DEBUG <= DEBUG_LEVEL_INFO
#define TEST_START() LOG("Starting Test:%s", __FUNCTION__)
#else
#define TEST_START() (void)0
#endif

#endif /* #ifndef TEST_START */

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

namespace trie {
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

[[maybe_unused]]
static std::string hash_to_str(const Hash& hash) {
	return array_to_str(hash.data(), hash.size());
}

} /* namespace debug */
} /* namespace trie */




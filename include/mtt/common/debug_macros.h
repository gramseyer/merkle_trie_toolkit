#pragma once

#include <cstdio>
#include <iomanip>
#include <sstream>

/*! \file debug_macros.h

A set of debugging macros.  Activate/deactivate based on DEBUG_LEVEL_* settings.
Printouts include file/line information.
*/

#include "mtt/common/debug_levels.h"

#define TRIE_LOG(s, ...) std::printf((std::string("%-45s") + s + "\n").c_str(), (std::string(__FILE__) + "." + std::to_string(__LINE__) + ":").c_str() __VA_OPT__(,) __VA_ARGS__)
#define TRIE_LOG_FILE(o, s, ...) std::fprintf(o, (std::string("%-45s") + s + "\n").c_str(), (std::string(__FILE__) + "." + std::to_string(__LINE__) + ":").c_str() __VA_OPT__(,) __VA_ARGS__)

#if TRIE_DEBUG <= DEBUG_LEVEL_ERROR
#define TRIE_ERROR(s, ...) TRIE_LOG(s, __VA_ARGS__)
#define TRIE_ERROR_F(s) s
#else
#define TRIE_ERROR(s, ...) (void)0
#define TRIE_ERROR_F(s) (void)0
#endif

#if TRIE_DEBUG <= DEBUG_LEVEL_INFO
#define TRIE_INFO(s, ...) TRIE_LOG(s, __VA_ARGS__)
#define TRIE_INFO_F(s) s
#else
#define TRIE_INFO(s, ...) (void)0
#define TRIE_INFO_F(s) (void)0
#endif

#if PROOF_DEBUG <= DEBUG_LEVEL_ERROR
#define PROOF_ERROR(s, ...) TRIE_LOG(s, __VA_ARGS__)
#define PROOF_ERROR_F(s) s
#else
#define PROOF_ERROR(s, ...) (void)0
#define PROOF_ERROR_F(s) (void)0
#endif

#if PROOF_DEBUG <= DEBUG_LEVEL_INFO
#define PROOF_INFO(s, ...) TRIE_LOG(s, __VA_ARGS__)
#define PROOF_INFO_F(s) s
#else
#define PROOF_INFO(s, ...) (void)0
#define PROOF_INFO_F(s) (void)0
#endif



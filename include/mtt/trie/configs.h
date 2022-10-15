#pragma once

#include <atomic>
#include <cstdio>

namespace trie
{

#ifndef _LOG_HASH_RECORDS
	#define _LOG_HASH_RECORDS 0
#endif

constexpr static bool TRIE_LOG_HASH_RECORDS = (_LOG_HASH_RECORDS != 0);

namespace detail
{
	// when in a header that gets included by many translation units,
	// log_configs() gets called many times, instead of just once,
	// leading to many repeated printouts (annoying)
	inline static std::atomic<bool> configs_printed = false;
}

[[maybe_unused]]
static void
__attribute__((constructor))
log_configs()
{
	if (!detail::configs_printed.exchange(true))
	{
		std::printf("========== trie configs ==========\n");
		std::printf("TRIE_LOG_HASH_RECORDS         = %u\n", TRIE_LOG_HASH_RECORDS);
	}
}

}
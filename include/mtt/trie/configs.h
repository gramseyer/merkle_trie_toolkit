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
	// need struct namespace to ensure only one instance of the static 
	// variable globally
	struct ConfigsPrinted
	{
		// when in a header that gets included by many translation units,
		// log_configs() gets called many times, instead of just once,
		// leading to many repeated printouts (annoying)
		inline static std::atomic<int32_t> configs_printed = 0;
	};
}

[[maybe_unused]]
static void
__attribute__((constructor))
log_configs()
{
	int32_t res = detail::ConfigsPrinted::configs_printed.fetch_add(1);
	if (res == 0)
	{
		std::printf("========== trie configs ==========\n");
		std::printf("TRIE_LOG_HASH_RECORDS         = %u\n", TRIE_LOG_HASH_RECORDS);
	}
}

}

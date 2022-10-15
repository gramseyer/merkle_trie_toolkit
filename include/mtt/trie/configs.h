#pragma once

namespace trie
{

#ifndef _LOG_HASH_RECORDS
	#define _LOG_HASH_RECORDS 0
#endif

constexpr static bool TRIE_LOG_HASH_RECORDS = (_LOG_HASH_RECORDS != 0);


[[maybe_unused]]
static void
__attribute__((constructor))
log_configs()
{
	std::printf("========== trie configs ==========\n");
	std::printf("TRIE_LOG_HASH_RECORDS         = %u\n", TRIE_LOG_HASH_RECORDS);
}

}
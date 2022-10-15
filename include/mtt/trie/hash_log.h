#pragma once

#include <utils/log_collector.h>
#include <utils/debug_utils.h>

#include "mtt/trie/prefix.h"

#include <string>
#include <vector>

namespace trie
{

template<typename PrefixT>
struct HashLog
{
	utils::LogCollector logs;

	void add_record(PrefixT const& prefix, PrefixLenBits const& prefix_len, std::vector<unsigned char> const& hash_input)
	{
		std::string res = std::string("prefix=") + prefix.to_string(prefix_len) + " len=" + std::to_string(prefix_len.len) + " value="
			+ utils::array_to_str(hash_input);

		logs.log(res);
	}

	template<typename ArrayLike>
	void add_root(ArrayLike const& hash_input)
	{
		std::string res = std::string("root input=") + utils::array_to_str(hash_input);
	}

	void write_logs(std::string filename)
	{
		logs.write_logs(filename);
	}
};


}
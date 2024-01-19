#pragma once

#include "mtt/common/types.h"

#include <array>
#include <cstdint>

namespace trie
{

[[maybe_unused]]
static
std::vector<uint8_t> 
hash_serialize_fn(const Hash& hash)
{
  return std::vector<uint8_t>(hash.begin(), hash.end());
}


struct ProofNode
{
	std::array<uint8_t, 4> prefix_length_and_bv;
	std::vector<Hash> hashes;
};

struct Proof
{
	std::vector<ProofNode> nodes;
	std::vector<uint8_t> prefix;

	uint32_t trie_size;
	Hash root_node_hash;
	
	std::vector<uint8_t> value_bytes;
	uint32_t membership_flag;
};

} /* trie */

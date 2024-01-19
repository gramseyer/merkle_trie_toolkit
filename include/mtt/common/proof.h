#pragma once

#include "mtt/common/prefix.h"

#include <utils/serialize_endian.h>

#include <vector>
#include <cstdint>

namespace trie
{

template<TriePrefix prefix_t>
struct TrieProof
{
	prefix_t proved_prefix;

	struct ProofLayer {
		PrefixLenBits len;
		TrieBitVector bv;
		// not including the child data of the prev thing,
		// except for the first one
		// vector of size 1 in case of a value node
		std::vector<std::vector<uint8_t>> child_data;

		void serialize(std::vector<uint8_t>& output) const
		{
			utils::write_unsigned_big_endian(output, len.len);
			bv.write(output);

			for (auto const& child : child_data)
			{
				if (child.size() > UINT16_MAX)
				{
					throw std::runtime_error("too long");
				}
				uint16_t child_len = static_cast<uint16_t>(child.size());

				utils::write_unsigned_big_endian(output, child_len);

				output.insert(
					output.end(),
					child.begin(),
					child.end());
			}
		}
	};

	// top of stack is longest prefix len
	std::vector<ProofLayer> proof_stack;

	std::vector<uint8_t> serialize() const
	{
		std::vector<uint8_t> out;
		proved_prefix.write_bytes_to(out, prefix_t::len());
		for (auto const& layer : proof_stack)
		{
			layer.serialize(out);
		}
		return out;
	}
};

}


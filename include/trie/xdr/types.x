namespace trie
{


typedef unsigned hyper uint64;
typedef unsigned int uint32;

typedef opaque Hash[32]; // 256 bit hash, i.e. output of sha256

struct ProofNode {
	opaque prefix_length_and_bv[4];
	Hash hashes<16>;
};

struct Proof {
	ProofNode nodes<>;
	opaque prefix<>;

	uint32 trie_size;
	Hash root_node_hash;
	
	opaque value_bytes<>;
	uint32 membership_flag;
};

} /* trie */

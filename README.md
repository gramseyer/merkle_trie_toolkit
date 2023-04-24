# Merkle Trie

A C++20 header-only merkle trie library.  Keys are fixed-length.

The implementation is optimized around parallel execution of batch operations.

This project should be includeable as a submodule, importing the makefile fragment.
There is also a standalone autotools build script.
However, this project relies on gramseyer/utility.git, which could be
included as a submodule here but is more naturally 
added to a project via its out makefile fragment
(see scslab/smart-contract-scalability.git for an example).

# Project Structure

## snapshot_trie/

Trie designed around periodic batch modifications.
Operations are atomic and threadsafe;
that is, insertions can be processed concurrently.
Batch modifications should generally not be done concurrently with
insertions.

The general pattern (as e.g. used in scslab/smart-contract-scalability.git)
is to build, per each batch of modifications, an `ephemeral_trie` with the same keyspace 
that logs which keys need to be updated, and then using the ephemeral trie to 
execute a parallel job over the main trie.

Replaces `trie/`.

## ephemeral_trie/

Trie with limited functionality using a custom, recycling memory allocator.
Designed to be thrown away and recreated after each batch of operations on a
`snapshot_trie/` or `layered_trie/`.

## layered_trie/

Experimental copy-on-write version of `snapshot_trie/`.

## trie/

Merkle trie designed around insertions, deletions, and merge operations.
General use case is one where each thread accumulates its own subtrie locally,
and then tries are merged together in a batch.

Generally not as good performance as `snapshot_trie/`

### trie/recycling_impl

Subset of merkle trie methods using a custom allocator.  
This implementation is designed around batch operations.
The allocator is the simplest one can think of -- pointers are indexes into a 
(set of) large backing array(s), allocation is by incrementing a uint32_t,
 and memory is freed all at once.

This implementation is designed around tries that are created, manipulated for a short time,
and then deleted.  Within SPEEDEX, these tries are used for per-block operations
(i.e. a log of which accounts are modified within one block).

The advantage of the custom allocator is that the location of all of the children of one node
can be stored using a single uint32_t (i.e. a pointer to a block of 16 allocated nodes).
This enables a trie node to fit into a single 64-byte cache line (as opposed to storing 16 8-byte pointers).
(hash: 32 bytes, children_map: (union of value offset (4 bytes), children pointer (4bytes) + 2 byte bitvector), 1 byte tag) = 9 bytes,
hash_valid flag = 1 byte, spinlock = 1byte, prefix_length = 2 bytes (could be made 1), prefix = 8 bytes
total = 53 (although alignment concerns push the total usage to 64).

An alternate approach would be to make every node log an 8-byte pointer to a normally allocated
block of 16 nodes.  The implementation in merkle_trie.h uses a continuously allocated block of 16 pointers (stored within the
trie node), so each node is ultimately 3 or 4 cache lines (depending on the size of the value type).

Replaced by `ephemeral_trie/`.  The batch merge operations tend to be less performant than desired.

# Dependencies

Depends on gramseyer/utility.git, which could be included as a submodule or installed locally
(It's not included as a submodule here, but that would be a small configure.ac change)

# Notes to the Reader

- Written in c++20, header only

- One should be able to build and run tests with `make test`.

- Trie operations are safe to use concurrently
  (except for those in `trie/`, when the locking mechanisms are turned off
  --methods with names \_nolocks do not use locking).

- Will update documentation if requested.  

# History

I wrote a merkle trie implementation for SPEEDEX.  
I pulled it into a separate repo so I could use it in other projects.

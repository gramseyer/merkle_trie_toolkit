# Merkle Trie

A C++20 header-only merkle trie library.  Keys are fixed-length.

The implementation is optimized around parallel execution of batch operations.

## /trie

Merkle trie implementation and associated helper objects.

### /trie/recycling_impl

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

## /utils

A number of utility classes.

# Notes to the Reader

- Written in c++20, header only

- One should be able to build and run tests with `make test`.

- Trie operations are safe to use concurrently, unless the locking mechanisms are turned off
  (methods with names \_nolocks do not use locking).

- Will update documentation if requested.  

# History

I wrote a merkle trie implementation for SPEEDEX.  
I pulled it into a separate repo so I could use it in other projects.

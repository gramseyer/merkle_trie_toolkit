# Merkle Trie

## /trie

I wrote a merkle trie implementation for SPEEDEX.  The implementation has a bunch of tricks to boost speed
(certain settings get one cache line per node, e.g.)
and to effectively paralellize a lot of batch operations.

I pulled it into a separate repo so I could use it in other projects.

## /utils

A number of generic utility classes that I also wanted.

# Notes to the Reader

- Written in c++20.

- One should be able to build and run tests with `make test`.

- Trie operations should all be safe to use concurrently, unless the locking mechanisms are turned off.

- It's only partially documented and only some of my tests are pulled into this repository.  If you (i.e. anyone
  other than me)
  do wind up using this library for anything, let me know, and I will update documentation & add more tests.

- I _think_ the autoconf setup works, but no guarantees that everything is set up correctly for all cases.

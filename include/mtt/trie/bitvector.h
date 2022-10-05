#pragma once

#include "mtt/utils/serialize_endian.h"

#include <utils/bitvector.h>

namespace trie {
/*!

Bitvector of size 16.  Used for storing which of a
list of trie node children pointers are actove.

*/
typedef utils::BitVector<uint16_t> TrieBitVector;

} // namespace trie
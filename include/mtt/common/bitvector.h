#pragma once

#include <utils/bitvector.h>
#include <utils/serialize_endian.h>

namespace trie {

/*!

Bitvector of size 16.  Used for storing which of a
list of trie node children pointers are actove.

*/
struct TrieBitVector : public utils::BitVector<uint16_t>
{
    void write_to(unsigned char* ptr)
    {
        utils::write_unsigned_big_endian(ptr, bv);
    }

    TrieBitVector(uint16_t bv = 0) : utils::BitVector<uint16_t>(bv) {}
    TrieBitVector(const utils::BitVector<uint16_t>& other) : utils::BitVector<uint16_t>(other) {}
};

} // namespace trie

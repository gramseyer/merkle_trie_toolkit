#pragma once

#include <cstdint>
#include <vector>

#include <utils/serialize_endian.h>

namespace trie
{
namespace test
{

typedef uint64_t AccountID;
typedef uint64_t Price;

struct Offer
{
  AccountID owner;
  Price minPrice;
  uint64_t amount;
};

static 
std::vector<uint8_t> offer_serialize_fn(const Offer& offer)
{
  std::vector<uint8_t> out;
  utils::append_unsigned_big_endian(out, offer.owner);
  utils::append_unsigned_big_endian(out, offer.minPrice);
  utils::append_unsigned_big_endian(out, offer.amount);
  return out;
}

} /* test */
} /* trie */

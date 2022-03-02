
%#include "trie/xdr/types.h"

namespace trie
{

namespace test
{

typedef uint64 AccountID;

typedef uint32 AssetID;

enum OfferType
{
	SELL = 0
};
const NUM_OFFER_TYPES = 1;

struct OfferCategory
{
	AssetID sellAsset;
	AssetID buyAsset;
	OfferType type;
};

// sell order executes if current price >= given price;
// Interpreted as price/2^radix
typedef uint64 Price;

//44 bytes
struct Offer
{
	OfferCategory category;
	uint64 offerId; // the operation number (sequence number + lowbits idx) that created this offer
	AccountID owner;
	uint64 amount;
	Price minPrice;
};

} /* test */
} /* trie */

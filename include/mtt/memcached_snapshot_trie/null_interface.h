#pragma once

#include "mtt/memcached_snapshot_trie/durable_interface.h"

namespace trie {

/**
 * Null interface.
 */

template<uint8_t _KEY_LEN_BYTES>
class NullInterface
{

  public:
    constexpr static uint8_t KEY_LEN_BYTES = _KEY_LEN_BYTES;

    using result_t = DurableResult<KEY_LEN_BYTES, std::vector<uint8_t>>;

    void log_durable_value(TimestampPointerPair const& key,
                           DurableValue<KEY_LEN_BYTES> const& value)
    {}

    result_t restore_durable_value(TimestampPointerPair const& key) const
    {
        throw std::runtime_error("unimplemented");
    }
};

} // namespace trie

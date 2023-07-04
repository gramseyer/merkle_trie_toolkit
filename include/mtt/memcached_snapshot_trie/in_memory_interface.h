#pragma once

#include "mtt/memcached_snapshot_trie/durable_interface.h"

#include <map>
#include <mutex>

namespace trie {

/**
 * Used for testing.  Clearly does not actuallly
 * store data in a durable medium.
 *
 * Contains additional correctness assertions.
 */

template<uint8_t _KEY_LEN_BYTES>
class InMemoryInterface
{
    std::mutex mtx;

    std::map<TimestampPointerPair, std::vector<uint8_t>> values;

  public:
    constexpr static uint8_t KEY_LEN_BYTES = _KEY_LEN_BYTES;

    using result_t = DurableResult<KEY_LEN_BYTES, std::vector<uint8_t>>;

    void log_durable_value(TimestampPointerPair const& key,
                           DurableValue<KEY_LEN_BYTES> const& value)
    {
        std::lock_guard lock(mtx);

        if (values.find(key) != values.end()) {
            throw std::runtime_error("cannot reinsert preexisting key");
        }

        values[key] = value.get_buffer();
    }

    result_t restore_durable_value(TimestampPointerPair const& key)
    {
        result_t out;

        std::lock_guard lock(mtx);

        auto it = values.find(key);
        if (it == values.end()) {
            throw std::runtime_error("value not found");
        }

        out.get_backing_data() = it->second;

        return out;
    }
};

} // namespace trie

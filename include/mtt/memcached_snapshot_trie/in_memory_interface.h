#pragma once

#include "mtt/memcached_snapshot_trie/durable_interface.h"

#include <map>
#include <mutex>

#include <utils/debug_utils.h>

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
    mutable std::mutex mtx;

    std::map<TimestampPointerPair, std::vector<uint8_t>> values;

    uint32_t stores = 0;
    uint32_t loads = 0;

  public:
    constexpr static uint8_t KEY_LEN_BYTES = _KEY_LEN_BYTES;

    using result_t = DurableResult<KEY_LEN_BYTES, std::vector<uint8_t>>;

    void log_durable_value(TimestampPointerPair const& key,
                           DurableValue<KEY_LEN_BYTES> const& value)
    {
        std::lock_guard lock(mtx);

        // std::printf("logging key %p %lu value=%s\n", key.ptr, key.timestamp,
        // utils::array_to_str(value.get_buffer()).c_str());

        if (values.find(key) != values.end()) {
            throw std::runtime_error("cannot reinsert preexisting key");
        }

        values[key] = value.get_buffer();
        stores++;
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
        loads++;

        return out;
    }

    std::vector<uint8_t> const& get_raw(TimestampPointerPair const& key) const
    {
        std::lock_guard lock(mtx);

        return values.at(key);
    }

    uint32_t get_store_count() const {
        std::lock_guard lock(mtx);
        return stores;
    }
    uint32_t get_load_count() const {
        std::lock_guard lock(mtx);
        return loads;
    }
};

} // namespace trie

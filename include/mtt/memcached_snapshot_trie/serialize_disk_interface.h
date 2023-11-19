#pragma once

#include "mtt/memcached_snapshot_trie/durable_interface.h"

#include <map>
#include <mutex>
#include <type_traits>

#include <utils/debug_utils.h>
#include <utils/threadlocal_cache.h>


namespace trie {

template<uint8_t _KEY_LEN_BYTES, uint32_t TLCACHE_SIZE>
class SerializeDiskInterface
{
    utils::ThreadlocalCache<std::vector<uint8_t>, TLCACHE_SIZE> cache;

  public:
    constexpr static uint8_t KEY_LEN_BYTES = _KEY_LEN_BYTES;

    using result_t = DurableResult<KEY_LEN_BYTES, std::vector<uint8_t>>;

    void log_durable_value(TimestampPointerPair const& key,
                           DurableValue<KEY_LEN_BYTES> const& value)
    {

        auto& buf = cache.get();
        auto const* ptr = reinterpret_cast<const uint8_t*>(&key);

        static_assert(std::is_trivially_copyable<TimestampPointerPair>::value, "design error");

        buf.insert(buf.end(),
            ptr, ptr + sizeof(TimestampPointerPair));
        
        auto const& b = value.get_buffer();

        buf.insert(buf.end(),
            b.begin(),
            b.end());
    }

    result_t restore_durable_value(TimestampPointerPair const& key) const
    {
        throw std::runtime_error("unimplemented");
    }

    void swap_buffers(std::array<std::vector<uint8_t>, TLCACHE_SIZE>& old_buffers) {
        auto& bufs = cache.get_objects();
        for (size_t i = 0; i < TLCACHE_SIZE; i++)
        {
            if (!bufs[i])
            {
                bufs[i].emplace();
            }
            std::swap(*bufs[i], old_buffers[i]);
        }
    }
};

} // namespace trie

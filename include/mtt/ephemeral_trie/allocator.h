#pragma once

#include <cstdint>

#include <utils/non_movable.h>

namespace trie {

template<uint8_t OFFSET_BITS>
struct EphemeralTrieNodeAllocatorConstants
{
    constexpr static uint8_t BUFFER_ID_BITS = 32 - OFFSET_BITS;

    // 2^19 = 524'288
    constexpr static size_t BUF_SIZE = static_cast<uint32_t>(1) << OFFSET_BITS;

    constexpr static uint32_t NUM_BUFFERS = static_cast<uint32_t>(1) << BUFFER_ID_BITS;

    constexpr static uint32_t OFFSET_MASK
        = (static_cast<uint32_t>(1) << (OFFSET_BITS)) - 1;

    static_assert(BUFFER_ID_BITS + OFFSET_BITS == 32, "ptrs are size 32 bits");

    EphemeralTrieNodeAllocatorConstants() = delete;
};

template<typename ObjType, typename ValueType, uint8_t LOG_BUFSIZE>
struct EphemeralTrieNodeAllocator;

/*! Singlethreaded node/value allocator.
When it runs out, it asks the main node allocator for another working buffer.
Allocations are never recycled, until the main node allocator is cleared
(after which a context should not be used until reset)
*/
template<typename ObjType, typename ValueType, uint8_t LOG_BUFSIZE>
class EphemeralTrieNodeAllocationContext : private utils::NonMovableOrCopyable
{
    uint32_t cur_buffer_offset_and_index = UINT32_MAX;
    uint32_t value_buffer_offset_and_index = UINT32_MAX;

    using allocator_t = EphemeralTrieNodeAllocator<ObjType, ValueType, LOG_BUFSIZE>;

    allocator_t& allocator;

    constexpr static size_t BUF_SIZE
        = EphemeralTrieNodeAllocatorConstants<LOG_BUFSIZE>::BUF_SIZE;
   // constexpr static uint8_t OFFSET_BITS
     //   = EphemeralTrieNodeAllocatorConstants<LOG_BUFSIZE>::OFFSET_BITS;
    constexpr static uint32_t OFFSET_MASK
        = EphemeralTrieNodeAllocatorConstants<LOG_BUFSIZE>::OFFSET_MASK;

    using value_t = ValueType;//typename allocator_t::value_t;

    static bool overflow_check(uint32_t offset_and_index, uint8_t new_allocs)
    {
        return (offset_and_index & OFFSET_MASK) + new_allocs >= BUF_SIZE;
    }

  public:
    EphemeralTrieNodeAllocationContext(
            uint32_t cur_buffer_offset_and_index,
                      uint32_t value_buffer_offset_and_index,
                      allocator_t& allocator)
        : cur_buffer_offset_and_index(cur_buffer_offset_and_index)
        , value_buffer_offset_and_index(value_buffer_offset_and_index)
        , allocator(allocator)
    {}

    uint32_t allocate(uint8_t num_nodes)
    {
        if (overflow_check(cur_buffer_offset_and_index, num_nodes))
        {
            allocator.assign_new_buffer(*this);
        }

        uint32_t out = cur_buffer_offset_and_index;
        cur_buffer_offset_and_index += num_nodes;
        return out;
    }

    uint32_t allocate_value()
    {
        if (overflow_check(value_buffer_offset_and_index, 1))
        {
        //if (((value_buffer_offset_and_index + 1) & OFFSET_MASK) >= BUF_SIZE) {
            allocator.assign_new_value_buffer(*this);
        }
        uint32_t out = value_buffer_offset_and_index;
        value_buffer_offset_and_index += 1;
        return out;
    }

    void set_cur_buffer_offset_and_index(uint32_t value)
    {
        cur_buffer_offset_and_index = value;
    }

    void set_cur_value_buffer_offset_and_index(uint32_t value)
    {
        value_buffer_offset_and_index = value;
    }

    uint32_t init_root_node()
    {
        auto ptr = allocate(1);
        auto& node = get_object(ptr);
        node.set_as_empty_node();
        return ptr;
    }

    ObjType& get_object(uint32_t ptr) const
    {
        return allocator.get_object(ptr);
    }

    value_t& get_value(uint32_t ptr) const { return allocator.get_value(ptr); }
};

/*! Manages a group of allocation contexts.
New contexts can be requested from this object,
and when those allocation contexts use up their buffers,
this node grants additional buffers.

Allocations are not freed until the whole allocator is reset.
After resetting, created contexts should be nullified.

This struct is threadsafe.
*/
template<typename ObjType, typename ValueType, uint8_t LOG_BUFSIZE>
struct EphemeralTrieNodeAllocator : private utils::NonMovableOrCopyable
{
    constexpr static size_t BUF_SIZE
        = EphemeralTrieNodeAllocatorConstants<LOG_BUFSIZE>::BUF_SIZE;
    //constexpr static uint8_t OFFSET_BITS
    //    = EphemeralTrieNodeAllocatorConstants<LOG_BUFSIZE>::OFFSET_BITS;
    constexpr static uint32_t OFFSET_MASK
        = EphemeralTrieNodeAllocatorConstants<LOG_BUFSIZE>::OFFSET_MASK;

    using buffer_t = std::array<ObjType, BUF_SIZE>;

    using object_t = ObjType;

    using value_t = ValueType;//typename ObjType::value_t;

    using value_buffer_t = std::array<value_t, BUF_SIZE>;

    using context_t = EphemeralTrieNodeAllocationContext<ObjType, value_t, LOG_BUFSIZE>;

  private:
    std::atomic<uint32_t> next_available_buffer = 0;
    std::atomic<uint32_t> next_available_value_buffer = 0;

    using buffer_ptr_t = std::unique_ptr<buffer_t>;

    std::array<buffer_ptr_t, EphemeralTrieNodeAllocatorConstants<LOG_BUFSIZE>::NUM_BUFFERS> buffers;

    using value_buffer_ptr_t = std::unique_ptr<value_buffer_t>;

    std::array<value_buffer_ptr_t, EphemeralTrieNodeAllocatorConstants<LOG_BUFSIZE>::NUM_BUFFERS> value_buffers;

  public:
    //! Get a new allocation context
    context_t get_new_allocator()
    {
        uint32_t idx
            = next_available_buffer.fetch_add(1, std::memory_order_relaxed);
        if (idx >= buffers.size()) {
            throw std::runtime_error("used up all allocation buffers!!!");
        }

        if (!buffers[idx]) {
            buffers[idx] = std::make_unique<buffer_t>();
        }

        uint32_t value_buffer_idx = next_available_value_buffer.fetch_add(
            1, std::memory_order_relaxed);
        if (value_buffer_idx >= value_buffers.size()) {
            throw std::runtime_error("used up all value buffers");
        }

        if (!value_buffers[value_buffer_idx]) {
            value_buffers[value_buffer_idx]
                = std::make_unique<value_buffer_t>();
        }

        return context_t(static_cast<uint32_t>(idx) << LOG_BUFSIZE,
                         static_cast<uint32_t>(value_buffer_idx) << LOG_BUFSIZE,
                         *this);
    }

    //! Give a context a new trie node buffer
    void assign_new_buffer(context_t& context)
    {
        uint32_t idx
            = next_available_buffer.fetch_add(1, std::memory_order_relaxed);
        if (idx >= buffers.size()) {
            throw std::runtime_error("used up all allocation buffers!!!");
        }

        if (!buffers[idx]) {
            buffers[idx] = std::make_unique<buffer_t>();
        }

        context.set_cur_buffer_offset_and_index(static_cast<uint32_t>(idx) << LOG_BUFSIZE);
    }

    //! Give a context a new trie value buffer
    void assign_new_value_buffer(context_t& context)
    {
        uint32_t value_buffer_idx = next_available_value_buffer.fetch_add(
            1, std::memory_order_relaxed);
        if (value_buffer_idx >= value_buffers.size()) {
            throw std::runtime_error("used up all value buffers");
        }

        if (!value_buffers[value_buffer_idx]) {
            value_buffers[value_buffer_idx]
                = std::make_unique<value_buffer_t>();
        }

        context.set_cur_value_buffer_offset_and_index(
            static_cast<uint32_t>(value_buffer_idx) << LOG_BUFSIZE);
    }

    //! Access a particular node, given a handle
    ObjType& get_object(uint32_t ptr) const
    {
        uint32_t idx = ptr >> LOG_BUFSIZE;
        uint32_t offset = ptr & OFFSET_MASK;
        return (*buffers[idx])[offset];
    }

    //! Access a particular trie value, given a handle
    value_t& get_value(uint32_t value_ptr) const
    {
        uint32_t idx = value_ptr >> LOG_BUFSIZE;
        uint32_t offset = value_ptr & OFFSET_MASK;

        return (*value_buffers[idx])[offset];
    }

    //! Reset the allocator.  All contexts should be cleared or deleted.
    void reset()
    {
        next_available_buffer = 0;
        next_available_value_buffer = 0;
    }
};

template<typename allocator_t>
struct ApplyableNodeReference
{
    using ValueType = typename allocator_t::object_t;

    ValueType* ptr;
    allocator_t& allocator;

    template<typename ApplyFn>
    void apply(ApplyFn& fn, auto&&... args)
    {
        ptr->apply(fn, allocator, args...);
    }

    template<typename ApplyFn>
    void apply_to_keys(ApplyFn& fn)
    {
        ptr->apply_to_keys(fn, allocator);
    }

    template<typename ApplyFn>
    void apply_to_kvs(ApplyFn& fn) const
    {
        ptr->apply_to_kvs(fn, allocator);
    }

    template<typename ApplyFn>
    void apply_to_kvs(ApplyFn& fn)
    {
        ptr->apply_to_kvs(fn, allocator);
    }

    auto get_prefix() const { return ptr->get_prefix(); }

    PrefixLenBits get_prefix_len() const
    {
        return ptr->get_prefix_len();
    }
};

template<typename allocator_t>
struct ConstApplyableNodeReference
{
    using ValueType = typename allocator_t::object_t;

    const ValueType* ptr;
    const allocator_t& allocator;

    template<typename ApplyFn>
    void apply(ApplyFn& fn, auto&&... args) const
    {
        ptr->apply(fn, allocator, args...);
    }

    template<typename ApplyFn>
    void apply_to_keys(ApplyFn& fn, PrefixLenBits max_len = ValueType::prefix_t::len()) const
    {
       ptr->apply_to_keys(fn, max_len, allocator);
    }

    template<typename ApplyFn>
    void apply_to_kvs(ApplyFn& fn) const
    {
       ptr->apply_to_kvs(fn, allocator);
    }

    auto get_prefix() const { return ptr->get_prefix(); }

    PrefixLenBits get_prefix_len() const
    {
        return ptr->get_prefix_len();
    }
};

} // namespace trie

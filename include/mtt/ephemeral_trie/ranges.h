#pragma once

#include <cstdint>
#include <vector>

#include "mtt/ephemeral_trie/allocator.h"

#include "utils/assert.h"

namespace trie
{

//! TBB range when accumulating a list of the values in the trie.
template<typename TrieT>
struct EphemeralTrieAccumulateValuesRange
{
    using allocator_t = TrieT::allocator_t;

    const uint32_t GRAIN_SIZE;

    //! Nodes for which this range is responsible.
    //! The lists of values underneath these pointers
    //! are consecutive.
    std::vector<uint64_t> work_list;

    //! Total number of values underneath pointers in
    //! work_list
    uint32_t work_size;

    //! Offset in the accumulator vector in which to
    //! start placing values.
    uint32_t vector_offset;

    //! Convert recycling ptrs into virtual addresses
    const allocator_t& allocator;

    //! TBB: is this range worth executing
    bool empty() const { return work_size == 0; }

    //! TBB: can this range be effectively subdivided.
    bool is_divisible() const { return work_size > GRAIN_SIZE; }

    //! Construct range covering the whole trie
    EphemeralTrieAccumulateValuesRange(
    	std::vector<uint64_t> work_list,
        const allocator_t& allocator,
        uint32_t GRAIN_SIZE)
        : GRAIN_SIZE(GRAIN_SIZE)
        , work_list(work_list)
        , work_size(0)
        , vector_offset(0)
        , allocator(allocator)
    {
        for (auto const& obj : work_list)
        {
        	work_size += (obj & 0xFFFF'FFFF);
        }
    }

    //! TBB: splitting constructor
    EphemeralTrieAccumulateValuesRange(EphemeralTrieAccumulateValuesRange& other,
                                   tbb::split)
        : GRAIN_SIZE(other.GRAIN_SIZE)
        , work_list()
        , work_size(0)
        , vector_offset(other.vector_offset)
        , allocator(other.allocator)
    {

        auto original_sz = other.work_size;
        while (work_size < original_sz / 2) {
            if (other.work_list.size() == 1) {
                other.work_list = allocator.get_object(other.work_list.at(0) >> 32)
                                      .children_and_sizes_list();
            }
            utils::print_assert(
                other.work_list.size() != 1,
                "other.work_list.size() == 1");
            /*
            if (other.work_list.size() == 1) {
                utils::print_assert(
                    )
                std::printf("other.work_list.size() = 1?!\n");
                throw std::runtime_error(
                    "shouldn't still have other.work_list.size() == 1");
            } */
            utils::print_assert(
                other.work_list.size() != 0,
                "other.work_list.size() == 0");

            /*
            if (other.work_list.size() == 0) {
                std::printf("other.work_list.size() = 0?!\n");
                throw std::runtime_error(
                    "shouldn't get to other.work_list.size() == 0");
            } */

            work_list.push_back(other.work_list[0]);

            other.work_list.erase(other.work_list.begin());

            uint32_t sz = work_list.back() & 0xFFFF'FFFF;//allocator.get_object(work_list.back()).size();
            work_size += sz;
            other.work_size -= sz;

            other.vector_offset += sz;
        }
    }
};

// Main difference with hash range is accounting for subnodes marked deleted.
// No nodes in work_list overlap, even after splitting
template<typename TrieT>
struct EphemeralTrieApplyRange
{
    using allocator_t = TrieT::allocator_t;

    std::vector<uint64_t> work_list;

    uint32_t work_size;

    const allocator_t& allocator;

    const uint32_t GRAIN_SIZE;

    bool empty() const { return work_size == 0; }

    bool is_divisible() const { return work_size > GRAIN_SIZE; }

    EphemeralTrieApplyRange(const TrieT* work_root, const allocator_t& allocator, uint32_t GRAIN_SIZE)
        : work_list(work_root -> children_and_sizes_list())
        , work_size(0)
        , allocator(allocator)
        , GRAIN_SIZE(GRAIN_SIZE)
    {
        for (auto const& obj : work_list)
        {
        	work_size += (obj & 0xFFFF'FFFF);
        }
    }

    EphemeralTrieApplyRange(EphemeralTrieApplyRange& other, tbb::split)
        : work_list()
        , work_size(0)
        , allocator(other.allocator)
        , GRAIN_SIZE(other.GRAIN_SIZE)
    {

        auto original_sz = other.work_size;
        if (original_sz == 0) {
            return;
        }
        while (work_size < original_sz / 2) {

            utils::print_assert(other.work_list.size() != 0,
                "other.work_list.size() == 0");

            //if (other.work_list.size() == 0) {
            //    std::printf("other work list shouldn't be zero!\n");
            //    throw std::runtime_error("errors in tbb don't print, sadly");
            //}
            if (other.work_list.size() == 1)
            {
                utils::print_assert(
                    other.work_list[0] >> 32 != UINT32_MAX,
                    "found nullptr in EphemeralTrieApplyRange");
                //if (other.work_list.at(0) >> 32 == UINT32_MAX) {
                //    throw std::runtime_error("found nullptr in ApplyRange!");
               // }

                other.work_list = allocator.get_object(other.work_list.at(0) >> 32)
                                      .children_and_sizes_list();

            } else {

	            work_list.push_back(other.work_list[0]);
	            other.work_list.erase(other.work_list.begin());

	            uint32_t sz = work_list.back() & 0xFFFF'FFFF;
	            work_size += sz;
	            other.work_size -= sz;
            }
        }
    }
};

//! TBB iterator range used when hashing a trie.
template<typename TrieT>
class EphemeralTrieHashRange
{

    uint32_t num_children;
    using allocator_t = TrieT::allocator_t;//RecyclingTrieNodeAllocator<TrieT>;
    //using ptr_t = TrieT::ptr_t;

    allocator_t& allocator;

  public:
    //! Nodes for which this range is responsible for hashing.
    std::vector<TrieT*> nodes;

    //! TBB: is this range worth executing
    bool empty() const { return num_children == 0; }

    //! TBB: can this range be divided
    bool is_divisible() const { return num_children > 1000; }

    //! Number of nodes for which this range is responsible.
    size_t num_nodes() const { return nodes.size(); }

    //! Get an actual reference on a node to be hashed.
    TrieT& operator[](size_t idx) const
    {
        return *nodes[idx];//allocator.get_object(nodes[idx]);
    }

    //! Construct a default range (for the whole trie)
    //! from the trie root.
    EphemeralTrieHashRange(TrieT* root, allocator_t& allocator)
        : num_children(0)
        , allocator(allocator)
        , nodes()
    {
        nodes.push_back(root);
        num_children = root -> size();
    };

    //! TBB: splitting constructor.
    EphemeralTrieHashRange(EphemeralTrieHashRange& other, tbb::split)
        : num_children(0)
        , allocator(other.allocator)
        , nodes()
    {
        auto original_sz = other.num_children;
        while (num_children < original_sz / 2) {
            if (other.nodes.size() == 1) {
                auto ptrs = other.nodes[0] -> children_list();
                other.nodes.clear();
                for (auto ptr : ptrs)
                {
                    other.nodes.push_back(&allocator.get_object(ptr));
                }
               // other.nodes
                //    = allocator.get_object(other.nodes[0]).children_list();
            }
            if (other.nodes.size() == 0) {
                std::printf("other.nodes.size() = 0!");
                return;
            }

            nodes.push_back(other.nodes[0]);
            other.nodes.erase(other.nodes.begin());
            auto sz = nodes.back() -> size(); //allocator.get_object(nodes.back()).size();
            num_children += sz;
            other.num_children -= sz;
        }
    }
};




}
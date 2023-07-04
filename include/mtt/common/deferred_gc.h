/**
 * Copyright 2023 Geoffrey Ramseyer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <cstdint>
#include <vector>

#include "utils/threadlocal_cache.h"

namespace trie {

// avoid ABA problem
template<typename node_t, uint32_t TLCACHE_SIZE>
class DeferredGC
{
    struct LocalGC
    {
        std::vector<node_t*> nodes;
    };

    utils::ThreadlocalCache<LocalGC, TLCACHE_SIZE> cache;

  public:
    void free(node_t* ptr) { cache.get().nodes.push_back(ptr); }

    void gc()
    {
        auto& locals = cache.get_objects();

        for (auto& l : locals) {
            if (l) {
                auto& ptrs = l->nodes;
                for (auto* ptr : ptrs) {
                    delete ptr;
                }
            }
        }

        cache.clear();
    }

    ~DeferredGC() { gc(); }
};

// credit to https://stackoverflow.com/a/66275373
template<typename T>
concept deferred_gc_t = requires(T** a)
{
    []<typename node_t, uint32_t x>(DeferredGC<node_t, x>**) {}(a);
};

} // namespace trie

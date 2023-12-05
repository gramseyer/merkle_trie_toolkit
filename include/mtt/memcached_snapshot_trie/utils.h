#pragma once

#include "mtt/common/utils.h"

#include "mtt/memcached_snapshot_trie/durable_interface.h"

namespace trie
{

struct EmptyDurableValue : public EmptyValue
{
	using EmptyValue::EmptyValue;

	EmptyDurableValue(DurableValueSlice const& s) {
		if (s.len != 0) {
			throw std::runtime_error("invalid slice init");
		}
	}

	bool has_logical_value() const {
		return true;
	}
};

}

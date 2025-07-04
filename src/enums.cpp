#include "enums.h"

namespace bpftrace {

bool EnumRegistry::add(const std::string &enum_name,
         const std::string &enumerator_name,
         uint64_t val)
{
  // Returns false if this new entry clashes with an existing entry
  if (!enum_defs_[enum_name].insert({val, enumerator_name}).second)
    return false;
  if (!enumerators_.insert({enumerator_name, {val, enum_name}}).second)
    return false;
  return true;
}

bool EnumRegistry::contains(const std::string &enum_name) const
{
  return enum_defs_.contains(enum_name);
}

const std::optional<std::reference_wrapper<const std::string>> EnumRegistry::lookup(const std::string &enum_name, uint64_t val) const
{
  auto it1 = enum_defs_.find(enum_name);
  if (it1 == enum_defs_.end())
    return {};

  auto &val_map = it1->second;
  auto it2 = val_map.find(val);
  if (it2 == val_map.end())
    return {};

  return it2->second;
}

const std::optional<uint64_t> EnumRegistry::get_value(const std::string &enumerator_name) const
{
  auto it = enumerators_.find(enumerator_name);
  if (it == enumerators_.end())
    return {};
  return it->second.first;
}

const std::optional<std::reference_wrapper<const std::string>> EnumRegistry::get_containing_enum(const std::string &enumerator_name) const
{
  auto it = enumerators_.find(enumerator_name);
  if (it == enumerators_.end())
    return {};
  return it->second.second;
}

} // namespace bpftrace

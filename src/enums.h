#pragma once

#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>

namespace bpftrace {

class EnumRegistry {
public:
  bool add(const std::string &enum_name,
           const std::string &enumerator_name,
           uint64_t val);

  bool contains(const std::string &enum_name) const;

  // (enum name, val) -> enumerator name
  const std::optional<std::reference_wrapper<const std::string>> lookup(const std::string &enum_name, uint64_t val) const;

  // enumerator_name -> val
  const std::optional<uint64_t> get_value(const std::string &enumerator_name) const;

  // enumerator name -> enum name
  const std::optional<std::reference_wrapper<const std::string>> get_containing_enum(const std::string &enumerator_name) const;

private:
  // enum name -> (value -> enumerator name)
  std::unordered_map<std::string, std::unordered_map<uint64_t, std::string>> enum_defs_;

  // enumerator name -> (value, enum name)
  std::unordered_map<std::string, std::pair<uint64_t, std::string>> enumerators_;
};

} // namespace bpftrace

#include "functions.h"

namespace bpftrace {

void FunctionRegistry::add(Function::Origin origin,
    std::string name,
    SizedType returnType,
    std::vector<Param> params)
{
  all_funcs_.push_back(
      std::make_unique<Function>(origin, name, returnType, params));
  Function &newFunc = *all_funcs_.back().get();
  funcs_by_name_[newFunc.name()].push_back(newFunc);
}

const Function* FunctionRegistry::get(const std::string &name) const
{
  auto it=funcs_by_name_.find(name);
  if (it == funcs_by_name_.end()) {
    // uh-oh TODO
    return nullptr;
  }

  const auto &candidates = it->second;
  assert(candidates.size() == 1);
  return &candidates[0].get();
}

////
//// TODO START USING THIS OVERLOAD-AWARE FUNCTION
////
const Function* FunctionRegistry::get(const std::string &name, const std::vector<Param> &params) const
{
  auto it=funcs_by_name_.find(name);
  if (it == funcs_by_name_.end()) {
    // uh-oh TODO
    return nullptr;
  }

  const auto &candidates = it->second;
  for (const Function &candidate : candidates) {
    if (candidate.params().size() != params.size())
      continue;

    bool match = true;
    for (size_t i=0; i<params.size(); i++) {
      if (candidate.params()[i].type() != params[i].type()) {
        match = false;
        break;
      }
    }

    if (match)
      return &candidate;
  }

  // uh-oh TODO
  return nullptr;
}

} // namespace bpftrace

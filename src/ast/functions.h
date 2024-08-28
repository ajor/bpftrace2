#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "types.h"

namespace bpftrace {

/**
 * A parameter for a BpfScript function
 */
class Param {
public:
  Param(std::string name, SizedType type) : name_(std::move(name)), type_(std::move(type)) {}

  const std::string &name() const { return name_; }
  const SizedType &type() const { return type_; }

private:
  std::string name_;
  SizedType type_;
};

/**
 * A function which is callable in a BpfScript program
 */
class Function {
public:
  enum class Origin {
    Builtin,
    Library,
  };

  Function(Origin origin, std::string name, SizedType returnType, std::vector<Param> params)
    : name_(std::move(name)), returnType_(returnType), params_(std::move(params)), origin_(origin) {}

  const std::string &name() const { return name_; }
  const SizedType &returnType() const { return returnType_; }
  const std::vector<Param> &params() const { return params_; }
  Origin origin() const { return origin_; }

private:
  std::string name_;
  SizedType returnType_;
  std::vector<Param> params_;
  Origin origin_;
};

/**
 * Registry of callable functions
 *
 * Multiple functions may share the same name, in which case overload resolution
 * rules come into play.
 */
class FunctionRegistry {
public:
  void add(Function::Origin origin,
      std::string_view name,
      SizedType returnType,
      std::vector<Param> params);
  void add(Function::Origin origin,
      std::string_view module,
      std::string_view name,
      SizedType returnType,
      std::vector<Param> params);
  const Function* get(const std::string &name) const;
  const Function* get(const std::string &name, const std::vector<Param> &params) const;

private:
  std::unordered_map<std::string, std::vector<std::reference_wrapper<Function>>> funcs_by_fq_name_;
  std::vector<std::unique_ptr<Function>> all_funcs_;
};

} // namespace

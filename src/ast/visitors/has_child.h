#pragma once

#include <functional>
#include <vector>

#include "ast/visitors.h"

namespace bpftrace::ast {

/*
 * HasChild
 *
 * Returns true if any descendent of the provided node matches the predicate.
 */
template <typename NodeT>
class HasChild : public Visitor {
public:
  bool run(
      Node &node,
      std::function<bool(const NodeT &)> pred = [](const auto &) {
        return true;
      })
  {
    pred_ = pred;
    node.accept(*this);
    return has_match_;;
  }

private:
  void visit(NodeT &node) override
  {
    if (pred_(node)) {
      has_match_ = true;
    }
  }

  std::function<bool(const NodeT &)> pred_;
  bool has_match_ = false;
};

} // namespace bpftrace::ast

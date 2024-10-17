#pragma once

#include <ostream>

#include "struct.h"

namespace bpftrace::types {

class TypePrinter {
public:
  void visitRecord(const SizedType &stype);
};

} // namespace bpftrace::types

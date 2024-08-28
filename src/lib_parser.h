#pragma once

#include <filesystem>

namespace bpftrace {

class FunctionRegistry;
class StructManager;

/**
 * Extracts information from pre-compiled BPF libraries
 */
class LibParser {
public:
  bool parse(std::filesystem::path lib_path, FunctionRegistry &functions, StructManager &structs);
};

} // namespace bpftrace

#include "common.h"

namespace bpftrace {
namespace test {
namespace codegen {

TEST(codegen, builtin_pid_tid)
{
  test("kprobe:f { @x = pid; @y = tid }", NAME);
}

TEST(codegen, builtin_pid_tid_namespace)
{
  MockBPFtrace bpftrace;
  bpftrace.feature_ = std::make_unique<MockBPFfeature>(true);
  bpftrace.in_root_pid_ns = false;

  test(bpftrace, "kprobe:f { @x = pid; @y = tid }", NAME);
}

} // namespace codegen
} // namespace test
} // namespace bpftrace

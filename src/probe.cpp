#include "probe.h"

namespace bpftrace {

namespace {
std::string probetypeName(ProbeType t)
{
  // clang-format off
  switch (t)
  {
    case ProbeType::invalid:     return "invalid";     break;
    case ProbeType::special:     return "special";     break;
    case ProbeType::kprobe:      return "kprobe";      break;
    case ProbeType::kretprobe:   return "kretprobe";   break;
    case ProbeType::uprobe:      return "uprobe";      break;
    case ProbeType::uretprobe:   return "uretprobe";   break;
    case ProbeType::usdt:        return "usdt";        break;
    case ProbeType::tracepoint:  return "tracepoint";  break;
    case ProbeType::profile:     return "profile";     break;
    case ProbeType::interval:    return "interval";    break;
    case ProbeType::software:    return "software";    break;
    case ProbeType::hardware:    return "hardware";    break;
    case ProbeType::watchpoint:  return "watchpoint";  break;
    case ProbeType::asyncwatchpoint: return "asyncwatchpoint"; break;
    case ProbeType::kfunc:       return "kfunc";       break;
    case ProbeType::kretfunc:    return "kretfunc";    break;
    case ProbeType::iter:        return "iter";        break;
    case ProbeType::rawtracepoint: return "rawtracepoint";  break;
  }
  // clang-format on

  return {}; // unreached
}
}

std::ostream &operator<<(std::ostream &os, ProbeType type)
{
  os << probetypeName(type);
  return os;
}

} // namespace bpftrace

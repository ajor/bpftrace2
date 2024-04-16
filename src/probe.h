#pragma once

#include <cstdint>
#include <ostream>
#include <string>
#include <variant>
#include <vector>

#include <cereal/access.hpp>

namespace bpftrace {

enum class ProbeType {
  invalid,
  special,
  kprobe,
  kretprobe,
  uprobe,
  uretprobe,
  usdt,
  tracepoint,
  profile,
  interval,
  software,
  hardware,
  watchpoint,
  asyncwatchpoint,
  kfunc,
  kretfunc,
  iter,
  rawtracepoint,
};

std::ostream &operator<<(std::ostream &os, ProbeType type);

struct Kprobe {
  // Syntax:
  //   kprobe:func
  //   kprobe:module:func
  //   kprobe:module:func+offset
  std::string module;
  std::string func;
  uint64_t offset = 0;

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(module, func, offset);
  }
};

struct KprobeMulti {
  // Syntax:
  //   kprobe:TODO
  std::vector<std::string> funcs;

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(funcs);
  }
};

struct Kfunc {
  // Syntax:
  //   kfunc:func
  //   kfunc:module:func
  std::string module;
  std::string func;

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(module, func);
  }
};

struct Uprobe {
  // Syntax:
  //   uprobe:path:func
  //   uprobe:path:func+offset
  //   uprobe:path:address
  std::string path;
  std::string func;
  uint64_t offset = 0;
  uint64_t address = 0;

  uint64_t loc = 0; // TODO: should not be needed

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(path, func, offset, address);
  }
};

struct UprobeMulti {
  std::string path;
  std::vector<std::string> funcs;

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(path, funcs);
  }
};

struct Usdt {
  // Syntax:
  //   usdt:path:ns:event
  std::string path;
  std::string ns;
  std::string event;

  uint64_t loc = 0; // for USDT probes
  int usdt_location_idx = 0; // to disambiguate duplicate USDT markers

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(path, ns, event, loc, usdt_location_idx);
  }
};

struct Tracepoint {
  // Syntax:
  //   tracepoint:ns:event
  std::string ns;
  std::string event;

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(ns, event);
  }
};

struct RawTracepoint {
  // Syntax:
  //   rawtracepoint:event
  std::string event;

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(event);
  }
};

struct Profile {
  // Syntax:
  //   profile:hz:freq
  //   interval:s:period
  int freq;
  int period;

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(freq, period);
  }
};

struct Perf {
  // Syntax:
  //   software:event
  //   software:event:sample_rate
  std::string event;
  int sample_rate;

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(event, sample_rate);
  }
};

struct Watchpoint {
  // Syntax:
  //   watchpoint:address:length:mode
  uint64_t address = 0;
  uint64_t len = 0;   // size of region
  std::string mode;   // watch mode (rwx)
  bool async = false; // if it's an async watchpoint

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(address, len, mode, async);
  }
};

struct Iter {
  // Syntax:
  //   iter:object
  //   iter:object:pin
  std::string object;
  std::string pin;

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(object, pin);
  }
};

struct Probe {
  ProbeType type;
  std::string name;
  std::string orig_name;
  int index = 0; // TODO what is this for??
  bool need_expansion;
  uint64_t log_size = 1000000;
  std::variant<Kprobe, KprobeMulti, Kfunc, Uprobe, UprobeMulti, Usdt, Tracepoint, RawTracepoint, Profile, Perf, Watchpoint, Iter> detail;

private:
  friend class cereal::access;
  template <typename Archive>
  void serialize(Archive &archive)
  {
    archive(type,
            name,
            orig_name,
            index,
            need_expansion,
            log_size,
            detail);
  }
};


} // namespace bpftrace

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <algorithm>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <linux/hw_breakpoint.h>
#include <linux/limits.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <tuple>
#include <unistd.h>

#include <bcc/bcc_elf.h>
#include <bcc/bcc_syms.h>
#include <bcc/bcc_usdt.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "attached_probe.h"
#include "bpftrace.h"
#include "disasm.h"
#include "log.h"
#include "probe_matcher.h"
#include "usdt.h"
#include "utils.h"

namespace bpftrace {

// TODO move this somewhere more sensible
template <typename... Ts>
struct overload : Ts... { using Ts::operator()...; };

//not needed with C++20:
template <typename... Ts>
overload(Ts...) -> overload<Ts...>;

/*
 * Kernel functions that are unsafe to trace are excluded in the Kernel with
 * `notrace`. However, the ones below are not excluded.
 */
const std::set<std::string> banned_kretprobes = {
  "_raw_spin_lock",
  "_raw_spin_lock_irqsave",
  "_raw_spin_unlock_irqrestore",
  "queued_spin_lock_slowpath",
};

bpf_probe_attach_type attachtype(ProbeType t)
{
  // clang-format off
  switch (t)
  {
    case ProbeType::kprobe:    return BPF_PROBE_ENTRY;  break;
    case ProbeType::kretprobe: return BPF_PROBE_RETURN; break;
    case ProbeType::special:   return BPF_PROBE_ENTRY;  break;
    case ProbeType::uprobe:    return BPF_PROBE_ENTRY;  break;
    case ProbeType::uretprobe: return BPF_PROBE_RETURN; break;
    case ProbeType::usdt:      return BPF_PROBE_ENTRY;  break;
    default:
      LOG(FATAL) << "invalid probe attachtype \"" << t << "\"";
  }
  // clang-format on
}

libbpf::bpf_prog_type progtype(ProbeType t)
{
  switch (t) {
    // clang-format off
    case ProbeType::special:    return libbpf::BPF_PROG_TYPE_RAW_TRACEPOINT; break;
    case ProbeType::kprobe:     return libbpf::BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::kretprobe:  return libbpf::BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::uprobe:     return libbpf::BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::uretprobe:  return libbpf::BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::usdt:       return libbpf::BPF_PROG_TYPE_KPROBE; break;
    case ProbeType::tracepoint: return libbpf::BPF_PROG_TYPE_TRACEPOINT; break;
    case ProbeType::profile:    return libbpf::BPF_PROG_TYPE_PERF_EVENT; break;
    case ProbeType::interval:   return libbpf::BPF_PROG_TYPE_PERF_EVENT; break;
    case ProbeType::software:   return libbpf::BPF_PROG_TYPE_PERF_EVENT; break;
    case ProbeType::watchpoint: return libbpf::BPF_PROG_TYPE_PERF_EVENT; break;
    case ProbeType::asyncwatchpoint: return libbpf::BPF_PROG_TYPE_PERF_EVENT; break;
    case ProbeType::hardware:   return libbpf::BPF_PROG_TYPE_PERF_EVENT; break;
    case ProbeType::kfunc:      return libbpf::BPF_PROG_TYPE_TRACING; break;
    case ProbeType::kretfunc:   return libbpf::BPF_PROG_TYPE_TRACING; break;
    case ProbeType::iter:       return libbpf::BPF_PROG_TYPE_TRACING; break;
    case ProbeType::rawtracepoint: return libbpf::BPF_PROG_TYPE_RAW_TRACEPOINT; break;
    // clang-format on
    case ProbeType::invalid:
      LOG(FATAL) << "program type invalid";
  }

  return {}; // unreached
}

std::string progtypeName(libbpf::bpf_prog_type t)
{
  switch (t) {
    // clang-format off
    case libbpf::BPF_PROG_TYPE_KPROBE:     return "BPF_PROG_TYPE_KPROBE";     break;
    case libbpf::BPF_PROG_TYPE_TRACEPOINT: return "BPF_PROG_TYPE_TRACEPOINT"; break;
    case libbpf::BPF_PROG_TYPE_PERF_EVENT: return "BPF_PROG_TYPE_PERF_EVENT"; break;
    case libbpf::BPF_PROG_TYPE_TRACING:    return "BPF_PROG_TYPE_TRACING";    break;
    // clang-format on
    default:
      LOG(FATAL) << "invalid program type: " << t;
  }
}

void check_banned_kretprobes(std::string const &kprobe_name)
{
  if (banned_kretprobes.find(kprobe_name) != banned_kretprobes.end()) {
    LOG(ERROR) << "error: kretprobe:" << kprobe_name
               << " can't be used as it might lock up your system.";
    exit(1);
  }
}

void AttachedProbe::attach_kfunc(void)
{
  if (progfd_ < 0)
    // Errors for kfunc are handled in load_prog, ignore here
    return;
  tracing_fd_ = bpf_raw_tracepoint_open(nullptr, progfd_);
  if (tracing_fd_ < 0)
    LOG(FATAL) << "Error attaching probe: " << probe_.name;
}

int AttachedProbe::detach_kfunc(void)
{
  close(tracing_fd_);
  return 0;
}

void AttachedProbe::attach_iter(void)
{
  linkfd_ = bpf_link_create(progfd_,
                            0,
                            static_cast<enum ::bpf_attach_type>(
                                libbpf::BPF_TRACE_ITER),
                            NULL);
  if (linkfd_ < 0) {
    LOG(FATAL) << "Error attaching probe: " << probe_.name;
  }
}

int AttachedProbe::detach_iter(void)
{
  close(linkfd_);
  return 0;
}

void AttachedProbe::attach_raw_tracepoint(void)
{
  const auto &tp = std::get<RawTracepoint>(probe_.detail);
  if (progfd_ < 0)
    // Errors for raw_tracepoint are handled in load_prog, ignore here
    return;
  tracing_fd_ = bpf_raw_tracepoint_open(tp.event.c_str(), progfd_);
  if (tracing_fd_ < 0) {
    if (tracing_fd_ == -ENOENT)
      LOG(FATAL) << "Probe does not exist: " << probe_.name;
    else if (tracing_fd_ == -EINVAL)
      LOG(FATAL) << "Error attaching probe: " << probe_.name
                 << ", maybe trying to access arguments beyond "
                    "what's available in this tracepoint";
    else
      LOG(FATAL) << "Error attaching probe: " << probe_.name;
  }
}

int AttachedProbe::detach_raw_tracepoint(void)
{
  close(tracing_fd_);
  return 0;
}

AttachedProbe::AttachedProbe(Probe &probe,
                             BpfProgram &&prog,
                             bool safe_mode,
                             BPFfeature &feature,
                             BTF &btf)
    : probe_(probe), prog_(std::move(prog)), btf_(btf)
{
  load_prog(feature);
  if (bt_verbose)
    std::cerr << "Attaching " << probe_.orig_name << std::endl;
  std::visit(overload{
      [&](const Kprobe &kprobe) {
        if (probe_.type == ProbeType::kretprobe)
          check_banned_kretprobes(kprobe.func);
        attach_kprobe(safe_mode);
      },
      [&](const KprobeMulti &) { attach_kprobe(safe_mode); },
      [&](const Kfunc &) { attach_kfunc(); },
      [&](const Uprobe &) {
        assert(probe_.type == ProbeType::special);
        // If BPF_PROG_TYPE_RAW_TRACEPOINT is available, no need to attach prog
        // to anything -- we will simply BPF_PROG_RUN it
        if (!feature.has_raw_tp_special())
          attach_uprobe(getpid(), safe_mode);
      },
      [&](const UprobeMulti &) { abort(); },
      [&](const Usdt &) { abort(); },
      [&](const Tracepoint &) { attach_tracepoint(); },
      [&](const RawTracepoint &) { attach_raw_tracepoint(); },
      [&](const Profile &) {
        if (probe_.type == ProbeType::profile)
          attach_profile();
        else
          attach_interval();
      },
      [&](const Perf &) {
        if (probe_.type == ProbeType::software)
          attach_software();
        else
          attach_hardware();
      },
      [&](const Watchpoint &) { attach_raw_tracepoint(); },
      [&](const Iter &) { attach_iter(); },
  }, probe_.detail);

//    default:
//      LOG(FATAL) << "invalid attached probe type \"" << probe_.type << "\"";
}

AttachedProbe::AttachedProbe(Probe &probe,
                             BpfProgram &&prog,
                             int pid,
                             BPFfeature &feature,
                             BTF &btf,
                             bool safe_mode)
    : probe_(probe), prog_(std::move(prog)), btf_(btf)
{
  load_prog(feature);
  std::visit(overload{
      [&](const Uprobe &) {
        attach_uprobe(pid, safe_mode);
      },
      [&](const Usdt &) {
        attach_usdt(pid, feature);
      },
      [&](const Watchpoint &) {
        attach_watchpoint(pid);
      },
      [](auto) { abort(); },
  }, probe_.detail);
//    default:
//      LOG(FATAL) << "invalid attached probe type \"" << probe_.type << "\"";
}

AttachedProbe::~AttachedProbe()
{
  int err = 0;
  for (int perf_event_fd : perf_event_fds_) {
    err = bpf_close_perf_event_fd(perf_event_fd);
    if (err)
      LOG(ERROR) << "failed to close perf event FDs for probe: " << probe_.name;
  }

  err = 0;

  std::visit(overload{
      [&](const Kprobe &) { err = bpf_detach_kprobe(eventname().c_str()); },
      [&](const KprobeMulti &) { close(linkfd_); },
      [&](const Kfunc &) { err = detach_kfunc(); },
      [&](const Uprobe &) { err = bpf_detach_uprobe(eventname().c_str()); },
      [&](const UprobeMulti &) { err = bpf_detach_uprobe(eventname().c_str()); },
      [&](const Usdt &) {
        if (usdt_destructor_)
          usdt_destructor_();
        err = bpf_detach_uprobe(eventname().c_str()); },
      [&](const Tracepoint &tp) { err = bpf_detach_tracepoint(tp.event.c_str(), eventname().c_str()); },
      [&](const RawTracepoint &) { err = detach_raw_tracepoint(); },
      [&](const Iter &) { err = detach_iter(); },
      //[&](const Profile&) {},
      //[&](const Perf&) {},
      //[&](const Watchpoint&) {},
      //[&](const Iter&) {},
      [](auto) {},
      }, probe_.detail);

  if (err)
    LOG(ERROR) << "failed to detach probe: " << probe_.name;

  if (close_progfd_ && progfd_ >= 0)
    close(progfd_);
}

const Probe &AttachedProbe::probe() const
{
  return probe_;
}

int AttachedProbe::progfd() const
{
  return progfd_;
}

std::string AttachedProbe::eventprefix() const
{
  switch (attachtype(probe_.type)) {
    case BPF_PROBE_ENTRY:
      return "p_";
    case BPF_PROBE_RETURN:
      return "r_";
  }

  return {}; // unreached
}

std::string AttachedProbe::eventname() const
{
  std::ostringstream offset_str;
  std::string index_str = "_" + std::to_string(probe_.index);

  return std::visit(overload{
      [&](const Kprobe &kprobe) {
        offset_str << std::hex << offset_;
        return eventprefix() + sanitise_bpf_program_name(kprobe.func) +
               "_" + offset_str.str() + index_str;
      },
      [&](const Uprobe &uprobe) {
        offset_str << std::hex << offset_;
        return eventprefix() + sanitise_bpf_program_name(uprobe.path) + "_" +
               offset_str.str() + index_str;
      },
      [&](const UprobeMulti &uprobe) {
        offset_str << std::hex << offset_;
        return eventprefix() + sanitise_bpf_program_name(uprobe.path) + "_" +
               offset_str.str() + index_str;
      },
      [&](const Usdt &usdt) {
        offset_str << std::hex << offset_;
        return eventprefix() + sanitise_bpf_program_name(usdt.path) + "_" +
               offset_str.str() + index_str;
      },
      [&](const Tracepoint &tp) {
        return tp.event;
      },
      [&](const RawTracepoint &tp) {
        offset_str << std::hex << offset_;
        return eventprefix() + sanitise_bpf_program_name(tp.event) +
               "_" + offset_str.str() + index_str;
      },
      [](const auto &) { abort(); return std::string{}; /*TODO*/},
      }, probe_.detail);

  abort();

//  switch (probe_.type) {
//    default:
//      LOG(FATAL) << "invalid eventname probe \"" << probe_.type << "\"";
//  }
}

static int sym_name_cb(const char *symname,
                       uint64_t start,
                       uint64_t size,
                       void *p)
{
  struct symbol *sym = static_cast<struct symbol *>(p);

  if (sym->name == symname) {
    sym->start = start;
    sym->size = size;
    return -1;
  }

  return 0;
}

static int sym_address_cb(const char *symname,
                          uint64_t start,
                          uint64_t size,
                          void *p)
{
  struct symbol *sym = static_cast<struct symbol *>(p);

  if (sym->address >= start && sym->address < (start + size)) {
    sym->start = start;
    sym->size = size;
    sym->name = symname;
    return -1;
  }

  return 0;
}

static uint64_t resolve_offset(const std::string &path,
                               const std::string &symbol,
                               uint64_t loc)
{
  bcc_symbol bcc_sym;

  if (bcc_resolve_symname(
          path.c_str(), symbol.c_str(), loc, 0, nullptr, &bcc_sym))
    LOG(FATAL) << "Could not resolve symbol: " << path << ":" << symbol;

  // Have to free sym.module, see:
  // https://github.com/iovisor/bcc/blob/ba73657cb8c4dab83dfb89eed4a8b3866255569a/src/cc/bcc_syms.h#L98-L99
  if (bcc_sym.module)
    ::free(const_cast<char *>(bcc_sym.module));

  return bcc_sym.offset;
}

static void check_alignment(const std::string &path,
                            const std::string &symbol,
                            uint64_t sym_offset,
                            uint64_t func_offset,
                            bool safe_mode,
                            ProbeType type)
{
  Disasm dasm(path);
  AlignState aligned = dasm.is_aligned(sym_offset, func_offset);

  std::string tmp = path + ":" + symbol + "+" + std::to_string(func_offset);

  // If we did not allow unaligned uprobes in the
  // compile time, force the safe mode now.
#ifndef HAVE_UNSAFE_PROBE
  safe_mode = true;
#endif

  switch (aligned) {
    case AlignState::Ok:
      return;
    case AlignState::NotAlign:
      if (safe_mode)
        LOG(FATAL) << "Could not add " << type
                   << " into middle of instruction: " << tmp;
      else
        LOG(WARNING) << "Unsafe " << type
                     << " in the middle of the instruction: " << tmp;
      break;

    case AlignState::Fail:
      if (safe_mode)
        LOG(FATAL) << "Failed to check if " << type
                   << " is in proper place: " << tmp;
      else
        LOG(WARNING) << "Unchecked " << type << ": " << tmp;
      break;

    case AlignState::NotSupp:
      if (safe_mode)
        LOG(FATAL) << "Can't check if " << type
                   << " is in proper place (compiled without "
                      "(k|u)probe offset support): "
                   << tmp;
      else
        LOG(WARNING) << "Unchecked " << type << " : " << tmp;
      break;
  }
}

bool AttachedProbe::resolve_offset_uprobe(bool safe_mode)
{
  auto &probe = std::get<Uprobe>(probe_.detail);
  struct bcc_symbol_option option = {};
  struct symbol sym = {};
  std::string &symbol = probe.func;
  uint64_t func_offset = probe.offset;

  sym.name = "";
  option.use_debug_file = 1;
  option.use_symbol_type = 0xffffffff;

  if (symbol.empty()) {
    sym.address = probe.address;
    bcc_elf_foreach_sym(probe.path.c_str(), sym_address_cb, &option, &sym);

    if (!sym.start) {
      if (safe_mode) {
        std::stringstream ss;
        ss << "0x" << std::hex << probe.address;
        LOG(FATAL) << "Could not resolve address: " << probe.path << ":"
                   << ss.str();
      } else {
        LOG(WARNING) << "Could not determine instruction boundary for "
                     << probe_.name
                     << " (binary appears stripped). Misaligned probes "
                        "can lead to tracee crashes!";
        offset_ = probe.address;
        return true;
      }
    }

    symbol = sym.name;
    func_offset = probe.address - sym.start;
  } else {
    sym.name = symbol;
    bcc_elf_foreach_sym(probe.path.c_str(), sym_name_cb, &option, &sym);

    if (!sym.start)
      LOG(FATAL) << "Could not resolve symbol: " << probe.path << ":"
                 << symbol;
  }

  if (probe_.type == ProbeType::uretprobe && func_offset != 0) {
    LOG(FATAL) << "uretprobes cannot be attached at function offset. "
               << "(address resolved to: " << symbol << "+" << func_offset
               << ")";
  }

  if (sym.size == 0 && func_offset == 0) {
    if (safe_mode) {
      std::stringstream msg;
      msg << "Could not determine boundary for " << sym.name
          << " (symbol has size 0).";
      if (probe_.orig_name == probe_.name) {
        msg << " Use --unsafe to force attachment.";
        LOG(FATAL) << msg.str();
      } else {
        LOG(WARNING)
            << msg.str()
            << " Skipping attachment (use --unsafe to force attachment).";
      }
      return false;
    }
  } else if (func_offset >= sym.size) {
    std::stringstream ss;
    ss << sym.size;
    LOG(FATAL) << "Offset outside the function bounds ('" << symbol
               << "' size is " << ss.str() << ")";
  }

  uint64_t sym_offset = resolve_offset(probe.path,
                                       probe.func,
                                       probe.loc);
  offset_ = sym_offset + func_offset;

  // If we are not aligned to the start of the symbol,
  // check if we are on the instruction boundary.
  if (func_offset == 0)
    return true;

  check_alignment(
      probe.path, symbol, sym_offset, func_offset, safe_mode, probe_.type);
  return true;
}

// find vmlinux file containing the given symbol information
static std::string find_vmlinux(const struct vmlinux_location *locs,
                                struct symbol &sym)
{
  struct bcc_symbol_option option = {};
  option.use_debug_file = 0;
  option.use_symbol_type = BCC_SYM_ALL_TYPES;
  struct utsname buf;

  uname(&buf);

  for (int i = 0; locs[i].path; i++) {
    if (locs[i].raw)
      continue; // This file is for BTF. skip
    char path[PATH_MAX + 1];
    snprintf(path, PATH_MAX, locs[i].path, buf.release);
    if (access(path, R_OK))
      continue;
    bcc_elf_foreach_sym(path, sym_name_cb, &option, &sym);
    if (sym.start) {
      if (bt_verbose)
        std::cout << "vmlinux: using " << path << std::endl;
      return path;
    }
  }

  return "";
}

void AttachedProbe::resolve_offset_kprobe(bool safe_mode)
{
  const auto &probe = std::get<Kprobe>(probe_.detail);
  struct symbol sym = {};
  const std::string &symbol = probe.func;
  uint64_t func_offset = probe.offset;
  offset_ = func_offset;

#ifndef HAVE_UNSAFE_PROBE
  safe_mode = true;
#endif

  if (func_offset == 0)
    return;

  sym.name = symbol;
  const struct vmlinux_location *locs = vmlinux_locs;
  struct vmlinux_location locs_env[] = {
    { nullptr, false },
    { nullptr, false },
  };
  char *env_path = std::getenv("BPFTRACE_VMLINUX");
  if (env_path) {
    locs_env[0].path = env_path;
    locs = locs_env;
  }

  std::string path = find_vmlinux(locs, sym);
  if (path.empty()) {
    if (bt_verbose) {
      LOG(WARNING) << "Could not resolve symbol " << symbol
                   << ". Skipping usermode offset checking.";
      LOG(WARNING) << "The kernel will verify the safety of the location but "
                      "will also allow the offset to be in a different symbol.";
    }

    return;
  }

  if (func_offset >= sym.size)
    LOG(FATAL) << "Offset outside the function bounds ('" << symbol
               << "' size is " << std::to_string(sym.size) << ")";

  uint64_t sym_offset = resolve_offset(path, probe.func, 0/*probe_.loc*/);

  check_alignment(
      path, symbol, sym_offset, func_offset, safe_mode, probe_.type);
}

std::map<std::string, int> AttachedProbe::cached_prog_fds_;

bool AttachedProbe::use_cached_progfd(void)
{
  // Enabled for so far only for kprobes/kretprobes
  if (probe_.type != ProbeType::kprobe && probe_.type != ProbeType::kretprobe)
    return false;

  // Only for a wildcard probe which does not need expansion,
  // because we can have multiple programs attached to a single probe
  if (!has_wildcard(probe_.orig_name) || probe_.need_expansion)
    return false;

  // Keep map of loaded programs based on their 'orig_name',
  // and make sure they are loaded just once and use cached
  // fd as probe's progfd_.
  // This way we prevent multiple copies of the same program
  // loaded for wildcard probe.
  auto search = cached_prog_fds_.find(probe_.orig_name);

  if (search != cached_prog_fds_.end()) {
    progfd_ = search->second;
    close_progfd_ = false;
    return true;
  }

  return false;
}

void AttachedProbe::cache_progfd(void)
{
  if (probe_.type != ProbeType::kprobe && probe_.type != ProbeType::kretprobe)
    return;
  cached_prog_fds_[probe_.orig_name] = progfd_;
}

namespace {
/*
 * Searches the verifier's log for err_pattern. If a match is found, extracts
 * the name and ID of the problematic helper and throws a HelperVerifierError.
 *
 * Example verfier log extract:
 *     [...]
 *     36: (b7) r3 = 64                      ; R3_w=64
 *     37: (85) call bpf_d_path#147
 *     helper call is not allowed in probe
 *     [...]
 *
 *  In the above log, "bpf_d_path" is the helper's name and "147" is the ID.
 */
void maybe_throw_helper_verifier_error(std::string_view log,
                                       std::string_view err_pattern,
                                       const std::string &exception_msg_suffix)
{
  auto err_pos = log.find(err_pattern);
  if (err_pos == log.npos)
    return;

  std::string_view call_pattern = " call ";
  auto call_pos = log.rfind(call_pattern, err_pos);
  if (call_pos == log.npos)
    return;

  auto helper_begin = call_pos + call_pattern.size();
  auto hash_pos = log.find("#", helper_begin);
  if (hash_pos == log.npos)
    return;

  auto eol = log.find("\n", hash_pos + 1);
  if (eol == log.npos)
    return;

  auto helper_name = std::string{ log.substr(helper_begin,
                                             hash_pos - helper_begin) };
  auto func_id = std::stoi(
      std::string{ log.substr(hash_pos + 1, eol - hash_pos - 1) });

  std::string msg = std::string{ "helper " } + helper_name +
                    exception_msg_suffix;
  throw HelperVerifierError(msg, static_cast<libbpf::bpf_func_id>(func_id));
}
}

void AttachedProbe::load_prog(BPFfeature &feature)
{
  if (use_cached_progfd())
    return;

  auto &insns = prog_.getCode();
  auto func_infos = prog_.getFuncInfos();
  const char *license = "GPL";
  int log_level = 0;

  uint64_t log_buf_size = probe_.log_size;
  auto log_buf = std::make_unique<char[]>(log_buf_size);
  std::string name;
  std::string tracing_type;

  {
    if (bt_debug != DebugLevel::kNone)
      log_level = 15;
    if (bt_verbose)
      log_level = 1;

    if (probe_.type == ProbeType::kprobe ||
        probe_.type == ProbeType::kretprobe) {
      // Use orig_name for program name so we get proper name for
      // wildcard probes, replace wildcards with '.'
      name = probe_.orig_name;
      std::replace(name.begin(), name.end(), '*', '.');
    } else
      name = probe_.name;

    // bpf_prog_load rejects some characters in probe names, so we clean them
    // start the name after the probe type, after ':'
    if (auto last_colon = name.rfind(':'); last_colon != std::string::npos)
      name = name.substr(last_colon + 1);
    name = sanitise_bpf_program_name(name);

    auto prog_type = progtype(probe_.type);
    if (probe_.type == ProbeType::special && !feature.has_raw_tp_special())
      prog_type = progtype(ProbeType::uprobe);

    for (int attempt = 0; attempt < 3; attempt++) {
      auto version = kernel_version(attempt);
      if (version == 0 && attempt > 0) {
        // Recent kernels don't check the version so we should try to call
        // bpf_prog_load during first iteration even if we failed to determine
        // the version. We should not do that in subsequent iterations to avoid
        // zeroing of log_buf on systems with older kernels.
        continue;
      }

      LIBBPF_OPTS(bpf_prog_load_opts, opts);
      opts.log_buf = log_buf.get();
      opts.log_size = log_buf_size;
      opts.log_level = log_level;

      if (probe_.type == ProbeType::kfunc)
        opts.expected_attach_type = static_cast<::bpf_attach_type>(
            libbpf::BPF_TRACE_FENTRY);
      else if (probe_.type == ProbeType::kretfunc)
        opts.expected_attach_type = static_cast<::bpf_attach_type>(
            libbpf::BPF_TRACE_FEXIT);
      else if (probe_.type == ProbeType::iter)
        opts.expected_attach_type = static_cast<::bpf_attach_type>(
            libbpf::BPF_TRACE_ITER);

      // We want to avoid kprobe_multi when a module is specified
      // because the BPF_TRACE_KPROBE_MULTI link type does not
      // currently support the `module:function` syntax.
      if (std::holds_alternative<KprobeMulti>(probe_.detail)) {
        opts.expected_attach_type = static_cast<::bpf_attach_type>(
            libbpf::BPF_TRACE_KPROBE_MULTI);
      }

      if (std::holds_alternative<UprobeMulti>(probe_.detail)) {
        opts.expected_attach_type = static_cast<::bpf_attach_type>(
            libbpf::BPF_TRACE_UPROBE_MULTI);
      }

      if (const auto *probe = std::get_if<Kfunc>(&probe_.detail)) {
        auto btf_id = btf_.get_btf_id_fd(probe->func, probe->module);
        if (btf_id.first < 0) {
          std::string msg = "No BTF found for " + probe->module + ":" + probe->func;
          if (probe_.orig_name != probe_.name) {
            // one attachpoint in a multi-attachpoint (wildcard or list) probe
            // failed, print a warning but continue
            LOG(WARNING) << msg << ", skipping.";
            return;
          } else
            // explicit match failed, fail hard
            LOG(FATAL) << msg;
        }

        opts.attach_btf_id = btf_id.first;
        opts.attach_btf_obj_fd = btf_id.second;
      } else if (const auto *probe = std::get_if<Iter>(&probe_.detail)) {
        // TODO func and "" might not be correct here
        std::string func = "bpf_iter_" + probe->object;
        auto btf_id = btf_.get_btf_id_fd(func, "");
        if (btf_id.first < 0) {
          std::string msg = "No BTF found for " + func;
          if (probe_.orig_name != probe_.name) {
            // one attachpoint in a multi-attachpoint (wildcard or list) probe
            // failed, print a warning but continue
            LOG(WARNING) << msg << ", skipping.";
            return;
          } else
            // explicit match failed, fail hard
            LOG(FATAL) << msg;
        }

        opts.attach_btf_id = btf_id.first;
        opts.attach_btf_obj_fd = btf_id.second;
      } else {
        opts.kern_version = version;
      }

      {
        // Redirect stderr, so we don't get error messages from libbpf
        StderrSilencer silencer;
        if (bt_debug == DebugLevel::kNone)
          silencer.silence();

        LIBBPF_OPTS(bpf_btf_load_opts,
                    btf_opts,
                    .log_buf = log_buf.get(),
                    .log_level = static_cast<__u32>(log_level),
                    .log_size = static_cast<__u32>(log_buf_size), );

        auto &btf = prog_.getBTF();
        auto btf_fd = bpf_btf_load(btf.data(), btf.size(), &btf_opts);

        opts.prog_btf_fd = btf_fd;

        if (!func_infos.empty()) {
          opts.func_info_rec_size = sizeof(struct bpf_func_info);
          opts.func_info = func_infos.data();
          opts.func_info_cnt = func_infos.size() / sizeof(struct bpf_func_info);
        }

        // Don't attempt to load the program if the BTF load failed.
        // This will fall back to the error handling for failed program load,
        // which is more robust.
        if (btf_fd >= 0) {
          progfd_ = bpf_prog_load(static_cast<::bpf_prog_type>(prog_type),
                                  name.c_str(),
                                  license,
                                  reinterpret_cast<const struct bpf_insn *>(
                                      insns.data()),
                                  insns.size() / sizeof(struct bpf_insn),
                                  &opts);
          close(btf_fd);
        }
      }

      if (opts.attach_btf_obj_fd > 0)
        close(opts.attach_btf_obj_fd);
      if (progfd_ >= 0)
        break;
    }
  }

  if (progfd_ < 0) {
    if (bt_verbose) {
      std::cerr << std::endl
                << "Error log: " << std::endl
                << log_buf.get() << std::endl;
      if (errno == ENOSPC) {
        LOG(FATAL) << "Error: Failed to load program, verification log buffer "
                   << "not big enough, try increasing the BPFTRACE_LOG_SIZE "
                   << "environment variable beyond the current value of "
                   << 1000000/*probe_.log_size*/ << " bytes";
      }
    }

    maybe_throw_helper_verifier_error(log_buf.get(),
                                      "helper call is not allowed in probe",
                                      " not allowed in probe");

    std::stringstream errmsg;
    errmsg << "Error loading program: " << probe_.name
           << (bt_verbose ? "" : " (try -v)");
    if (probe_.orig_name != probe_.name) {
      // one attachpoint in a multi-attachpoint (wildcard or list) probe failed,
      // print a warning but continue
      LOG(WARNING) << errmsg.str() << ", skipping.";
      return;
    } else
      // explicit match failed, fail hard
      LOG(FATAL) << errmsg.str();
  }

  if (bt_verbose) {
    struct bpf_prog_info info = {};
    uint32_t info_len = sizeof(info);
    int ret;

    ret = bpf_obj_get_info(progfd_, &info, &info_len);
    if (ret == 0) {
      std::cout << std::endl << "Program ID: " << info.id << std::endl;
    }
    std::cout << std::endl
              << "The verifier log: " << std::endl
              << log_buf.get() << std::endl;
  }

  cache_progfd();
}

void AttachedProbe::attach_multi_kprobe(void)
{
  const auto &probe = std::get<KprobeMulti>(probe_.detail);
  DECLARE_LIBBPF_OPTS(bpf_link_create_opts, opts);
  std::vector<const char *> syms;
  unsigned int i = 0;

  for (i = 0; i < probe.funcs.size(); i++) {
    syms.push_back(probe.funcs[i].c_str());
  }

  opts.kprobe_multi.syms = syms.data();
  opts.kprobe_multi.cnt = syms.size();
  opts.kprobe_multi.flags = probe_.type == ProbeType::kretprobe
                                ? BPF_F_KPROBE_MULTI_RETURN
                                : 0;

  if (bt_verbose) {
    std::cout << "Attaching to " << probe.funcs.size() << " functions"
              << std::endl;

    if (bt_verbose2) {
      for (i = 0; i < opts.kprobe_multi.cnt; i++) {
        std::cout << " " << syms[i] << std::endl;
      }
    }
  }

  linkfd_ = bpf_link_create(progfd_,
                            0,
                            static_cast<enum ::bpf_attach_type>(
                                libbpf::BPF_TRACE_KPROBE_MULTI),
                            &opts);
  if (linkfd_ < 0) {
    LOG(FATAL) << "Error attaching probe: " << probe_.name;
  }
}

void AttachedProbe::attach_kprobe(bool safe_mode)
{
  if (std::holds_alternative<KprobeMulti>(probe_.detail)) {
    attach_multi_kprobe();
    return;
  }

  const auto &probe = std::get<Kprobe>(probe_.detail);
  // Construct a string containing "module:function."
  // Also log a warning or throw an error if the module doesn't exist,
  // before attempting to attach.
  // Note that we do not pass vmlinux, if it is specified.
  std::string funcname = probe.func;
  const std::string &modname = probe.module;
  if ((modname.length() > 0) && modname != "vmlinux") {
    if (!is_module_loaded(modname)) {
      std::string message = "specified module " + modname + " in probe " +
                            probe_.name + " is not loaded.";
      if (probe_.orig_name != probe_.name) {
        // Wildcard usage just gets a warning
        LOG(WARNING) << message;
      } else {
        // Explicitly specified modules should fail
        LOG(FATAL) << "Error attaching probe: " << probe_.name << ": "
                   << message;
      }
    }
    funcname = modname + ":" + funcname;
  }

  resolve_offset_kprobe(safe_mode);
  int perf_event_fd = bpf_attach_kprobe(progfd_,
                                        attachtype(probe_.type),
                                        eventname().c_str(),
                                        funcname.c_str(),
                                        offset_,
                                        0);

  if (perf_event_fd < 0) {
    if (probe_.orig_name != probe_.name) {
      // a wildcard expansion couldn't probe something, just print a warning
      // as this is normal for some kernel functions (eg, do_debug())
      LOG(WARNING) << "could not attach probe " << probe_.name << ", skipping.";
    } else {
      if (errno == EILSEQ)
        LOG(ERROR) << "Possible attachment attempt in the middle of an "
                      "instruction, try a different offset.";
      // an explicit match failed, so fail as the user must have wanted it
      LOG(FATAL) << "Error attaching probe: " << probe_.name;
    }
  }

  perf_event_fds_.push_back(perf_event_fd);
}

#ifdef HAVE_LIBBPF_UPROBE_MULTI
struct bcc_sym_cb_data {
  std::vector<std::string> &syms;
  std::set<uint64_t> &offsets;
};

static int bcc_sym_cb(const char *symname, uint64_t start, uint64_t, void *p)
{
  struct bcc_sym_cb_data *data = static_cast<struct bcc_sym_cb_data *>(p);
  std::vector<std::string> &syms = data->syms;

  if (std::binary_search(syms.begin(), syms.end(), symname)) {
    data->offsets.insert(start);
  }

  return 0;
}

struct addr_offset {
  uint64_t addr;
  uint64_t offset;
};

static int bcc_load_cb(uint64_t v_addr,
                       uint64_t mem_sz,
                       uint64_t file_offset,
                       void *p)
{
  std::vector<struct addr_offset> *addrs =
      static_cast<std::vector<struct addr_offset> *>(p);

  for (auto &a : *addrs) {
    if (a.addr >= v_addr && a.addr < (v_addr + mem_sz)) {
      a.offset = a.addr - v_addr + file_offset;
    }
  }

  return 0;
}

static void resolve_offset_uprobe_multi(const std::string &path,
                                        const std::string &probe_name,
                                        const std::vector<std::string> &funcs,
                                        std::vector<std::string> &syms,
                                        std::vector<unsigned long> &offsets)
{
  struct bcc_symbol_option option = {};
  int err;

  // Parse symbols names into syms vector
  for (const std::string &func : funcs) {
    auto pos = func.find(':');

    if (pos == std::string::npos) {
      LOG(FATAL) << "Error resolving probe: " << probe_name;
    }

    syms.push_back(func.substr(pos + 1));
  }

  std::sort(std::begin(syms), std::end(syms));

  option.use_debug_file = 1;
  option.use_symbol_type = 0xffffffff;

  std::vector<struct addr_offset> addrs;
  std::set<uint64_t> set;
  struct bcc_sym_cb_data data = {
    .syms = syms,
    .offsets = set,
  };

  // Resolve symbols into addresses
  err = bcc_elf_foreach_sym(path.c_str(), bcc_sym_cb, &option, &data);
  if (err) {
    LOG(FATAL) << "Failed to list symbols for probe: " << probe_name;
  }

  for (auto a : set) {
    struct addr_offset addr = {
      .addr = a,
      .offset = 0x0,
    };

    addrs.push_back(addr);
  }

  // Translate addresses into offsets
  err = bcc_elf_foreach_load_section(path.c_str(), bcc_load_cb, &addrs);
  if (err) {
    LOG(FATAL) << "Failed to resolve symbols offsets for probe: " << probe_name;
  }

  for (auto a : addrs) {
    offsets.push_back(a.offset);
  }
}

void AttachedProbe::attach_multi_uprobe(int pid)
{
  const auto &probe = std::get<UprobeMulti>(probe_.detail);
  std::vector<std::string> syms;
  std::vector<unsigned long> offsets;
  unsigned int i;

  // Resolve probe_.funcs into offsets and syms vector
  resolve_offset_uprobe_multi(
      probe.path, probe_.name, probe.funcs, syms, offsets);

  // Attach uprobe through uprobe_multi link
  DECLARE_LIBBPF_OPTS(bpf_link_create_opts, opts);

  opts.uprobe_multi.path = probe.path.c_str();
  opts.uprobe_multi.offsets = offsets.data();
  opts.uprobe_multi.cnt = offsets.size();
  opts.uprobe_multi.flags = probe_.type == ProbeType::uretprobe
                                ? BPF_F_UPROBE_MULTI_RETURN
                                : 0;
  if (pid != 0) {
    opts.uprobe_multi.pid = pid;
  }

  if (bt_verbose) {
    std::cout << "Attaching to " << probe.funcs.size() << " functions"
              << std::endl;

    if (bt_verbose2) {
      for (i = 0; i < syms.size(); i++) {
        std::cout << probe.path << ":" << syms[i] << std::endl;
      }
    }
  }

  linkfd_ = bpf_link_create(progfd_,
                            0,
                            static_cast<enum ::bpf_attach_type>(
                                libbpf::BPF_TRACE_UPROBE_MULTI),
                            &opts);
  if (linkfd_ < 0) {
    LOG(FATAL) << "Error attaching probe: " << probe_.name;
  }
}
#else
void AttachedProbe::attach_multi_uprobe(int)
{
}
#endif // HAVE_LIBBPF_UPROBE_MULTI

void AttachedProbe::attach_uprobe(int pid, bool safe_mode)
{
  if (std::holds_alternative<UprobeMulti>(probe_.detail)) {
    attach_multi_uprobe(pid);
    return;
  }

  const auto &probe = std::get<Uprobe>(probe_.detail);

  if (!resolve_offset_uprobe(safe_mode))
    return;

  int perf_event_fd = bpf_attach_uprobe(progfd_,
                                        attachtype(probe_.type),
                                        eventname().c_str(),
                                        probe.path.c_str(),
                                        offset_,
                                        pid == 0 ? -1 : pid,
                                        0);

  if (perf_event_fd < 0)
    LOG(FATAL) << "Error attaching probe: " << probe_.name;

  perf_event_fds_.push_back(perf_event_fd);
}

int AttachedProbe::usdt_sem_up_manual(const std::string &fn_name, void *ctx)
{
  const auto &probe = std::get<Usdt>(probe_.detail);
  int err;

#ifdef BCC_USDT_HAS_FULLY_SPECIFIED_PROBE
  if (probe.ns == "")
    err = bcc_usdt_enable_probe(ctx,
                                probe.event.c_str(),
                                fn_name.c_str());
  else
    err = bcc_usdt_enable_fully_specified_probe(
        ctx, probe.ns.c_str(), probe.event.c_str(), fn_name.c_str());
#else
  err = bcc_usdt_enable_probe(ctx,
                              probe.event.c_str(),
                              fn_name.c_str());
#endif // BCC_USDT_HAS_FULLY_SPECIFIED_PROBE

  // Defer context destruction until probes are detached b/c context
  // destruction will decrement usdt semaphore count.
  usdt_destructor_ = [ctx]() { bcc_usdt_close(ctx); };

  return err;
}

int AttachedProbe::usdt_sem_up_manual_addsem(int pid,
                                             const std::string &fn_name,
                                             void *ctx)
{
  const auto &probe = std::get<Usdt>(probe_.detail);
  // NB: we are careful to capture by value here everything that will not
  // be available in AttachedProbe destructor.
  auto addsem = [&probe, fn_name](void *c, int16_t val) -> int {
    if (probe.ns == "")
      return bcc_usdt_addsem_probe(
          c, probe.event.c_str(), fn_name.c_str(), val);
    else
      return bcc_usdt_addsem_fully_specified_probe(
          c,
          probe.ns.c_str(),
          probe.event.c_str(),
          fn_name.c_str(),
          val);
  };

  // Set destructor to decrement the semaphore count
  usdt_destructor_ = [pid, addsem]() {
    void *c = bcc_usdt_new_frompid(pid, nullptr);
    if (!c)
      return;

    addsem(c, -1);
    bcc_usdt_close(c);
  };

  // Use semaphore increment API to avoid having to hold onto the usdt context
  // for the entire tracing session. Reason we do it this way instead of
  // holding onto usdt context is b/c each usdt context can take lots of memory
  // (~10MB). This, coupled with --usdt-file-activation and tracees that have a
  // forking model can cause bpftrace to use huge amounts of memory if we hold
  // onto the contexts.
  int err = addsem(ctx, +1);

  // Now close the context to save some memory
  bcc_usdt_close(ctx);

  return err;
}

int AttachedProbe::usdt_sem_up([[maybe_unused]] BPFfeature &feature,
                               [[maybe_unused]] int pid,
                               const std::string &fn_name,
                               void *ctx)
{
  // If we have BCC and kernel support for uprobe refcnt API, then we don't
  // need to do anything here. The kernel will increment the semaphore count
  // for us when we provide the semaphore offset.
  if (feature.has_uprobe_refcnt()) {
    bcc_usdt_close(ctx);
    return 0;
  }

  return usdt_sem_up_manual_addsem(pid, fn_name, ctx);
}

void AttachedProbe::attach_usdt(int pid, BPFfeature &feature)
{
  auto &probe = std::get<Usdt>(probe_.detail);
  struct bcc_usdt_location loc = {};
  int err;
  void *ctx;
  // TODO: fn_name may need a unique suffix for each attachment on the same
  // probe:
  std::string fn_name = "probe_" + probe.event + "_1";

  if (pid) {
    // FIXME when iovisor/bcc#2064 is merged, optionally pass probe_.path
    ctx = bcc_usdt_new_frompid(pid, nullptr);
    if (!ctx)
      LOG(FATAL) << "Error initializing context for probe: " + probe_.name +
                        ", for PID: " + std::to_string(pid);
  } else {
    ctx = bcc_usdt_new_frompath(probe.path.c_str());
    if (!ctx)
      LOG(FATAL) << "Error initializing context for probe: " << probe_.name;
  }

  // Resolve location of usdt probe
  auto u = USDTHelper::find(pid, probe.path, probe.ns, probe.event);
  if (!u.has_value())
    LOG(FATAL) << "Failed to find usdt probe: " << eventname();
  probe.path = u->path;

  err = bcc_usdt_get_location(ctx,
                              probe.ns.c_str(),
                              probe.event.c_str(),
                              probe.usdt_location_idx,
                              &loc);
  if (err)
    LOG(FATAL) << "Error finding location for probe: " << probe_.name;
  probe.loc = loc.address;

  offset_ = resolve_offset(probe.path, probe.event, probe.loc);

  // Should be 0 if there's no semaphore
  //
  // Cast to 32 bits b/c kernel API only takes 32 bit offset
  [[maybe_unused]] auto semaphore_offset = static_cast<uint32_t>(
      u->semaphore_offset);

  // Increment the semaphore count (will noop if no semaphore)
  //
  // NB: Do *not* use `ctx` after this call. It may either be open or closed,
  // depending on which path was taken.
  err = usdt_sem_up(feature, pid, fn_name, ctx);

  if (err) {
    std::string errstr;
    errstr += "Error finding or enabling probe: " + probe_.name;
    errstr += '\n';
    errstr +=
        "Try using -p or --usdt-file-activation if there's USDT semaphores";
    LOG(FATAL) << errstr;
  }

  int perf_event_fd = bpf_attach_uprobe(progfd_,
                                        attachtype(probe_.type),
                                        eventname().c_str(),
                                        probe.path.c_str(),
                                        offset_,
                                        pid == 0 ? -1 : pid,
                                        semaphore_offset);

  if (perf_event_fd < 0) {
    if (pid)
      LOG(FATAL) << "Error attaching probe: " << probe_.name
                 << ", to PID: " << std::to_string(pid);
    else
      LOG(FATAL) << "Error attaching probe: " << probe_.name;
  }

  perf_event_fds_.push_back(perf_event_fd);
}

void AttachedProbe::attach_tracepoint()
{
  const auto &probe = std::get<Tracepoint>(probe_.detail);
  int perf_event_fd = bpf_attach_tracepoint(progfd_,
                                            probe.ns.c_str(),
                                            eventname().c_str());

  if (perf_event_fd < 0 && probe_.name == probe_.orig_name) {
    // do not fail if there are other attach points where attaching may succeed
    LOG(FATAL) << "Error attaching probe: " << probe_.name;
  }

  perf_event_fds_.push_back(perf_event_fd);
}

void AttachedProbe::attach_profile()
{
  const auto &probe = std::get<Profile>(probe_.detail);
  int pid = -1;
  int group_fd = -1;

  std::vector<int> cpus = get_online_cpus();
  for (int cpu : cpus) {
    int perf_event_fd = bpf_attach_perf_event(progfd_,
                                              PERF_TYPE_SOFTWARE,
                                              PERF_COUNT_SW_CPU_CLOCK,
                                              probe.period,
                                              probe.freq,
                                              pid,
                                              cpu,
                                              group_fd);

    if (perf_event_fd < 0)
      LOG(FATAL) << "Error attaching probe: " << probe_.name;

    perf_event_fds_.push_back(perf_event_fd);
  }
}

void AttachedProbe::attach_interval()
{
  const auto &probe = std::get<Profile>(probe_.detail);
  int pid = -1;
  int group_fd = -1;
  int cpu = 0;

  int perf_event_fd = bpf_attach_perf_event(progfd_,
                                            PERF_TYPE_SOFTWARE,
                                            PERF_COUNT_SW_CPU_CLOCK,
                                            probe.period,
                                            probe.freq,
                                            pid,
                                            cpu,
                                            group_fd);

  if (perf_event_fd < 0)
    LOG(FATAL) << "Error attaching probe: " << probe_.name;

  perf_event_fds_.push_back(perf_event_fd);
}

void AttachedProbe::attach_software()
{
  const auto &probe = std::get<Perf>(probe_.detail);
  int pid = -1;
  int group_fd = -1;

  uint64_t period = probe.sample_rate;
  uint64_t defaultp = 1;
  uint32_t type = 0;

  // from linux/perf_event.h, with aliases from perf:
  for (auto &probeListItem : SW_PROBE_LIST) {
    if (probe.event == probeListItem.path ||
        probe.event == probeListItem.alias) {
      type = probeListItem.type;
      defaultp = probeListItem.defaultp;
    }
  }

  if (period == 0)
    period = defaultp;

  std::vector<int> cpus = get_online_cpus();
  for (int cpu : cpus) {
    int perf_event_fd = bpf_attach_perf_event(
        progfd_, PERF_TYPE_SOFTWARE, type, period, 0, pid, cpu, group_fd);

    if (perf_event_fd < 0)
      LOG(FATAL) << "Error attaching probe: " << probe_.name;

    perf_event_fds_.push_back(perf_event_fd);
  }
}

void AttachedProbe::attach_hardware()
{
  const auto &probe = std::get<Perf>(probe_.detail);
  int pid = -1;
  int group_fd = -1;

  uint64_t period = probe.sample_rate;
  uint64_t defaultp = 1000000;
  uint32_t type = 0;

  // from linux/perf_event.h, with aliases from perf:
  for (auto &probeListItem : HW_PROBE_LIST) {
    if (probe.event == probeListItem.path ||
        probe.event == probeListItem.alias) {
      type = probeListItem.type;
      defaultp = probeListItem.defaultp;
    }
  }

  if (period == 0)
    period = defaultp;

  std::vector<int> cpus = get_online_cpus();
  for (int cpu : cpus) {
    int perf_event_fd = bpf_attach_perf_event(
        progfd_, PERF_TYPE_HARDWARE, type, period, 0, pid, cpu, group_fd);

    if (perf_event_fd < 0)
      LOG(FATAL) << "Error attaching probe: " << probe_.name;

    perf_event_fds_.push_back(perf_event_fd);
  }
}

void AttachedProbe::attach_watchpoint(int pid)
{
  const auto &watchpoint = std::get<Watchpoint>(probe_.detail);
  struct perf_event_attr attr = {};
  attr.type = PERF_TYPE_BREAKPOINT;
  attr.size = sizeof(struct perf_event_attr);
  attr.config = 0;

  attr.bp_type = HW_BREAKPOINT_EMPTY;
  for (const char c : watchpoint.mode) {
    if (c == 'r')
      attr.bp_type |= HW_BREAKPOINT_R;
    else if (c == 'w')
      attr.bp_type |= HW_BREAKPOINT_W;
    else if (c == 'x')
      attr.bp_type |= HW_BREAKPOINT_X;
  }

  attr.bp_addr = watchpoint.address;
  attr.bp_len = watchpoint.len;
  // Generate a notification every 1 event; we care about every event
  attr.sample_period = 1;

  std::vector<int> cpus;
  if (pid >= 1) {
    cpus = { -1 };
  } else {
    cpus = get_online_cpus();
    pid = -1;
  }

  for (int cpu : cpus) {
    // We copy paste the code from bcc's bpf_attach_perf_event_raw here
    // because we need to know the exact error codes (and also we don't
    // want bcc's noisy error messages).
    int perf_event_fd = syscall(
        __NR_perf_event_open, &attr, pid, cpu, -1, PERF_FLAG_FD_CLOEXEC);
    if (perf_event_fd < 0) {
      if (errno == ENOSPC)
        throw EnospcException("No more HW registers left");
      else
        throw std::system_error(errno,
                                std::generic_category(),
                                "Error attaching probe: " + probe_.name);
    }
    if (ioctl(perf_event_fd, PERF_EVENT_IOC_SET_BPF, progfd_) != 0) {
      close(perf_event_fd);
      throw std::system_error(errno,
                              std::generic_category(),
                              "Error attaching probe: " + probe_.name);
    }
    if (ioctl(perf_event_fd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
      close(perf_event_fd);
      throw std::system_error(errno,
                              std::generic_category(),
                              "Error attaching probe: " + probe_.name);
    }

    perf_event_fds_.push_back(perf_event_fd);
  }
}

} // namespace bpftrace

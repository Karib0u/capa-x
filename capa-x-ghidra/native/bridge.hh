#pragma once
#include "rust/cxx.h"
#include <memory>
namespace capax {
struct NativeOutput;
enum class ValueType : uint8_t;
class Session {
  class Impl;
  std::unique_ptr<Impl> impl;
public:
  Session();
  ~Session();
  void add_section(uint64_t address, rust::Slice<const uint8_t> bytes, bool executable, bool readonly);
  void add_function(uint64_t address, rust::Str name, bool noreturn);
  void add_import(uint64_t address, rust::Str name, bool noreturn);
  void add_tail_call(uint64_t caller, uint64_t site, uint64_t target);
  void set_signature(uint64_t address, ValueType result, rust::Slice<const ValueType> parameters);
  void set_preserves_rax(uint64_t address);
  bool apply_prototype(uint64_t address, rust::Str name);
  rust::String validate_prototype_pack(uint32_t max_report);
  NativeOutput decompile(uint64_t address, uint32_t timeout_ms, uint32_t max_instructions, uint32_t max_work);
};
std::unique_ptr<Session> new_session();
}

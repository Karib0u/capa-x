#include "bridge.hh"
#include "capa-x-ghidra/src/lib.rs.h"
#include "hooks.hh"
#include "specs.hh"
#include "sleigh_arch.hh"
#include "funcdata.hh"
#include "flow.hh"
#include "printc.hh"
#include <chrono>
#include <mutex>
#include <stdexcept>
#include <limits>
#include <set>

using namespace ghidra;
namespace {
std::mutex engine_mutex;
std::once_flag initialized;
struct Budget {
  bool active = false;
  uint64_t remaining = 0;
  std::chrono::steady_clock::time_point deadline;
};
thread_local Budget budget;
struct BudgetGuard {
  BudgetGuard(uint32_t ms, uint32_t work) {
    budget = {true, work, std::chrono::steady_clock::now() + std::chrono::milliseconds(ms)};
  }
  ~BudgetGuard() { budget.active = false; }
};
// Convert Ghidra's non-std exceptions before CXX's std::exception boundary.
template<class F> auto checked(F f) -> decltype(f()) {
  try { return f(); }
  catch (const LowlevelError &e) { throw std::runtime_error(e.explain); }
  catch (const DecoderError &e) { throw std::runtime_error(e.explain); }
  catch (const std::exception &) { throw; }
  catch (...) { throw std::runtime_error("unknown native decompiler exception"); }
}
class OutputBuffer : public std::streambuf {
  std::string text;
protected:
  std::streamsize xsputn(const char *data, std::streamsize count) override {
    capax_check();
    if (count < 0 || uint64_t(count) > 4 * 1024 * 1024 - text.size())
      throw std::runtime_error("pseudocode output limit exceeded");
    text.append(data, size_t(count));
    return count;
  }
  int_type overflow(int_type ch) override {
    if (traits_type::eq_int_type(ch, traits_type::eof())) return traits_type::not_eof(ch);
    char byte = traits_type::to_char_type(ch);
    xsputn(&byte, 1);
    return ch;
  }
public:
  const std::string &str() const { return text; }
};
struct Section {
  uint64_t address;
  std::vector<uint8_t> bytes;
  bool executable;
};
class Image : public LoadImage {
public:
  std::vector<Section> sections;
  size_t total = 0;
  Image() : LoadImage("capa-x image") {}
  std::string getArchType() const override { return "x86:LE:64:default"; }
  void adjustVma(long) override { throw LowlevelError("image relocation is unsupported"); }
  bool executable(uint64_t address) const {
    for (const auto &s : sections)
      if (address >= s.address && address - s.address < s.bytes.size()) return s.executable;
    return false;
  }
  void loadFill(uint1 *ptr, int4 size, const Address &address) override {
    capax_check();
    auto current = address.getOffset();
    // Ghidra requests a lookahead window even for a one-byte instruction.
    // Padding after mapped bytes is allowed, but never an unmapped start.
    for (int4 i = 0; i < size; ++i) {
      bool mapped = false;
      for (const auto &s : sections) {
        if (current >= s.address && current - s.address < s.bytes.size()) {
          ptr[i] = s.bytes.at(current - s.address);
          mapped = true;
          break;
        }
      }
      if (i == 0 && !mapped) throw DataUnavailError("read from unmapped image address");
      if (!mapped) ptr[i] = 0;
      if (current == std::numeric_limits<uint64_t>::max() && i + 1 < size)
        throw DataUnavailError("image address overflow");
      ++current;
    }
  }
};
class ImageSleigh : public Sleigh {
  Image *image;
public:
  ImageSleigh(Image *loader, ContextDatabase *context) : Sleigh(loader, context), image(loader) {}
  int4 oneInstruction(PcodeEmit &emit, const Address &address) const override {
    if (!image->executable(address.getOffset())) throw LowlevelError("code flow left executable mapped memory");
    const auto length = Sleigh::oneInstruction(emit, address);
    if (length <= 0 || address.getOffset() > UINT64_MAX - uint64_t(length - 1) ||
        !image->executable(address.getOffset() + length - 1))
      throw LowlevelError("instruction crosses executable mapping boundary");
    return length;
  }
};
// Bounded discovery for an explicitly requested entry absent from recovery.
// Stop at any non-linear flow; only a direct jump to a supplied entry is a
// tail-call fact. All instructions are still translated by native SLEIGH.
class WrapperFlow : public PcodeEmit {
public:
  unsigned flows = 0;
  bool direct = false;
  Address target;
  void dump(const Address &, OpCode op, VarnodeData *, VarnodeData *inputs, int4 count) override {
    if (op == CPUI_BRANCH || op == CPUI_CBRANCH || op == CPUI_BRANCHIND ||
        op == CPUI_CALL || op == CPUI_CALLIND || op == CPUI_RETURN) {
      ++flows;
      if (op == CPUI_BRANCH && count == 1 && inputs[0].space->getType() == IPTR_PROCESSOR) {
        direct = true;
        target = Address(inputs[0].space, inputs[0].offset);
      }
    }
  }
};
class Architecture64 : public SleighArchitecture {
protected:
  void buildLoader(DocumentStorage &) override { loader = new Image(); }
  void resolveArchitecture() override { archid = "x86:LE:64:default:windows"; }
  void buildSpecFile(DocumentStorage &store) override {
    for (auto pair : {std::make_pair(pspec_bytes, sizeof(pspec_bytes)),
                      std::make_pair(cspec_bytes, sizeof(cspec_bytes))}) {
      std::istringstream stream(std::string(reinterpret_cast<const char *>(pair.first), pair.second));
      store.registerTag(store.parseDocument(stream)->getRoot());
    }
    std::istringstream stream("<sleigh>embedded</sleigh>");
    store.registerTag(store.parseDocument(stream)->getRoot());
  }
  Translate *buildTranslator(DocumentStorage &) override { return new ImageSleigh(static_cast<Image *>(loader), context); }
  void modifySpaces(Translate *) override {}
public:
  explicit Architecture64(std::ostream *errors) : SleighArchitecture("", "x86:LE:64:default:windows", errors) {
    if (!dynamic_cast<PrintC *>(print)) throw LowlevelError("C printer unavailable");
  }
  ~Architecture64() override { delete translate; translate = nullptr; }
  std::string getDescription() const override { return "x86-64 Windows"; }
  Image &image() { return *static_cast<Image *>(loader); }
};
std::string identifier(rust::Str input) {
  if (input.size() > 1024) throw std::runtime_error("symbol exceeds 1024 bytes");
  std::string result;
  for (unsigned char ch : input) {
    result += ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
               (ch >= '0' && ch <= '9') || ch == '_') ? char(ch) : '_';
  }
  if (result.empty()) throw std::runtime_error("empty symbol name");
  if (result.front() >= '0' && result.front() <= '9') result.insert(0, "_");
  return result;
}
}
std::string capax_sla() {
  return std::string(reinterpret_cast<const char *>(sla_bytes), sizeof(sla_bytes));
}
void capax_check() {
  if (!budget.active) return;
  if (budget.remaining-- == 0) throw std::runtime_error("native work limit exceeded");
  if (std::chrono::steady_clock::now() >= budget.deadline)
    throw std::runtime_error("native decompilation deadline exceeded");
}
namespace capax {
class Session::Impl {
public:
  std::ostringstream errors;
  Architecture64 arch;
  bool poisoned = false;
  size_t symbols = 0;
  size_t edges = 0;
  std::set<uint64_t> supplied_entries;
  TypeStruct *luid;
  TypeStruct *token_privileges;
  Impl() : arch(&errors) {
    DocumentStorage store;
    arch.init(store);
    arch.setPrintLanguage("c-language");
    // Windows x64 SDK layouts (winnt.h). DWORD and LONG are four bytes;
    // ANYSIZE_ARRAY is one in the declaration, not a runtime allocation bound.
    // See docs/decompiler.md for the declarations and provenance.
    auto *types = arch.types;
    auto *u32 = types->getBase(4, TYPE_UINT);
    luid = types->getTypeStruct("LUID");
    types->setFields({TypeField(0, 0, "LowPart", u32),
      TypeField(1, 4, "HighPart", types->getBase(4, TYPE_INT))}, luid, 8, 4, 0);
    auto *attributes = types->getTypeStruct("LUID_AND_ATTRIBUTES");
    types->setFields({TypeField(0, 0, "Luid", luid),
      TypeField(1, 8, "Attributes", u32)}, attributes, 12, 4, 0);
    token_privileges = types->getTypeStruct("TOKEN_PRIVILEGES");
    types->setFields({TypeField(0, 0, "PrivilegeCount", u32),
      TypeField(1, 4, "Privileges", types->getTypeArray(1, attributes))}, token_privileges, 16, 4, 0);
  }
  void ready() { if (poisoned) throw std::runtime_error("session failed previously; create a new session"); }
  void prepareRequestedWrapper(Funcdata *fd, uint32_t max_instructions) {
    auto entry = fd->getAddress().getOffset();
    if (supplied_entries.count(entry)) return;
    auto current = entry;
    // Local discovery policy: at most 64 straight-line instructions.
    for (uint32_t i = 0; i < std::min<uint32_t>(64, max_instructions); ++i) {
      if (current != entry && supplied_entries.count(current)) return;
      WrapperFlow flow;
      auto length = arch.translate->oneInstruction(flow, Address(arch.getDefaultCodeSpace(), current));
      if (flow.flows) {
        if (flow.flows == 1 && flow.direct && flow.target.getOffset() != entry &&
            supplied_entries.count(flow.target.getOffset()) &&
            arch.image().executable(flow.target.getOffset()))
          fd->getOverride().insertFlowOverride(Address(arch.getDefaultCodeSpace(), current), Override::CALL_RETURN);
        return;
      }
      if (length <= 0 || current > UINT64_MAX - uint64_t(length)) return;
      current += length;
    }
  }
  // Inference is request-local: no dependency on prior request order, and an
  // explicit signature supplied later never leaves stale inferred prototypes.
  // Local safety policy: at most 16 supporting functions and four call levels,
  // sharing the selected request's work/deadline budget.
  void inferCallees(Funcdata *caller, unsigned depth, std::set<uint64_t> &visited,
                    std::vector<Funcdata *> &inferred) {
    if (depth >= 4) return;
    std::set<uint64_t> targets;
    for (int4 i = 0; i < caller->numCalls(); ++i) {
      capax_check();
      auto *call = caller->getCallSpecs(i);
      if (!call->getEntryAddress().isInvalid()) targets.insert(call->getEntryAddress().getOffset());
    }
    for (auto target : targets) {
      capax_check();
      if (visited.size() >= 17) return;
      if (!arch.image().executable(target) || !visited.insert(target).second) continue;
      auto *fd = arch.symboltab->getGlobalScope()->queryFunction(Address(arch.getDefaultCodeSpace(), target));
      if (!fd || fd->getFuncProto().isInputLocked() || fd->getFuncProto().isOutputLocked()) continue;
      errors.str("");
      arch.clearAnalysis(fd);
      arch.allacts.getCurrent()->reset(*fd);
      int4 status = arch.allacts.getCurrent()->perform(*fd);
      const auto candidate_errors = errors.str();
      auto previous = inferred.size();
      inferCallees(fd, depth + 1, visited, inferred);
      if (inferred.size() != previous) {
        arch.clearAnalysis(fd);
        errors.str("");
        arch.allacts.getCurrent()->reset(*fd);
        status = arch.allacts.getCurrent()->perform(*fd);
      } else {
        errors.str(candidate_errors);
      }
      bool usable = status >= 0 && fd->getFuncProto().numParams() <= 32 && errors.str().empty();
      for (auto it = arch.commentdb->beginComment(fd->getAddress()); it != arch.commentdb->endComment(fd->getAddress()); ++it)
        if ((*it)->getType() & (Comment::warning | Comment::warningheader)) usable = false;
      for (int4 i = 0; i < fd->numCalls(); ++i) {
        const auto *call = fd->getCallSpecs(i);
        if (!call->isInputLocked() || !call->isOutputLocked()) usable = false;
      }
      if (usable) {
        fd->getFuncProto().setInputLock(true);
        fd->getFuncProto().setOutputLock(true);
        inferred.push_back(fd);
      }
      arch.clearAnalysis(fd);
      errors.str("");
    }
  }
  Funcdata *function(uint64_t address, const std::string &name, bool noreturn) {
    auto *scope = arch.symboltab->getGlobalScope();
    Address addr(arch.getDefaultCodeSpace(), address);
    auto *fd = scope->queryFunction(addr);
    if (!fd) {
      if (++symbols > 100000) throw std::runtime_error("symbol limit exceeded");
      fd = scope->addFunction(addr, name)->getFunction();
    }
    fd->getFuncProto().setModel(arch.defaultfp);
    if (noreturn) fd->getFuncProto().setNoReturn(true);
    return fd;
  }
};
Session::Session() : impl(checked([] { return std::unique_ptr<Impl>(new Impl()); })) {}
Session::~Session() { std::lock_guard<std::mutex> lock(engine_mutex); impl.reset(); }
std::unique_ptr<Session> new_session() {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([] {
    std::call_once(initialized, [] {
      AttributeId::initialize(); ElementId::initialize(); CapabilityPoint::initializeAll();
    });
    return std::unique_ptr<Session>(new Session());
  });
}
void Session::add_section(uint64_t address, rust::Slice<const uint8_t> bytes, bool executable, bool readonly) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    auto &image = impl->arch.image();
    if (bytes.empty() || bytes.size() > 256 * 1024 * 1024 - image.total ||
        address >= 0xffff000000000000ULL || bytes.size() >= 0xffff000000000000ULL - address || image.sections.size() >= 4096)
      throw std::runtime_error("invalid section range or mapped image limit exceeded");
    for (const auto &s : image.sections)
      if (address < s.address + s.bytes.size() && s.address < address + bytes.size())
        throw std::runtime_error("overlapping image sections");
    image.sections.push_back({address, std::vector<uint8_t>(bytes.begin(), bytes.end()), executable});
    image.total += bytes.size();
    if (readonly) impl->arch.symboltab->setPropertyRange(Varnode::readonly,
      Range(impl->arch.getDefaultCodeSpace(), address, address + bytes.size() - 1));
  });
}
void Session::add_function(uint64_t address, rust::Str name, bool noreturn) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    impl->function(address, identifier(name), noreturn);
    impl->supplied_entries.insert(address);
  });
}
void Session::add_import(uint64_t address, rust::Str name, bool noreturn) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    auto &arch = impl->arch;
    if (address > UINT64_MAX - 7) throw std::runtime_error("import slot address overflow");
    // Only the IAT slot is mutable. Preserve read-only strings/constants in
    // the rest of the section instead of disabling the whole section.
    arch.symboltab->clearPropertyRange(Varnode::readonly,
      Range(arch.getDefaultCodeSpace(), address, address + 7));
    // ExternRefSymbol's address is the IAT slot. Its target names a function
    // in a reserved unmapped range, never executable sample bytes.
    const uint64_t target = 0xffff000000000000ULL + impl->symbols * 16;
    impl->function(target, identifier(name), noreturn);
    arch.symboltab->getGlobalScope()->addExternalRef(Address(arch.getDefaultCodeSpace(), address),
      Address(arch.getDefaultCodeSpace(), target), identifier(name));
  });
}
void Session::add_tail_call(uint64_t caller, uint64_t site, uint64_t target) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    auto &arch = impl->arch;
    auto *fd = arch.symboltab->getGlobalScope()->queryFunction(Address(arch.getDefaultCodeSpace(), caller));
    const auto target_address = Address(arch.getDefaultCodeSpace(), target);
    const bool known_import = arch.symboltab->getGlobalScope()->queryExternalRefFunction(target_address) != nullptr;
    if (!fd || !arch.image().executable(site) || (!arch.image().executable(target) && !known_import))
      throw std::runtime_error("tail call requires a registered caller, executable site and code/import target");
    if (++impl->edges > 1000000) throw std::runtime_error("call edge limit exceeded");
    fd->getOverride().insertFlowOverride(Address(arch.getDefaultCodeSpace(), site), Override::CALL_RETURN);
  });
}
void Session::set_signature(uint64_t address, ValueType result, rust::Slice<const ValueType> parameters) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    if (parameters.size() > 32) throw std::runtime_error("signature exceeds 32 parameters");
    auto &arch = impl->arch;
    auto *scope = arch.symboltab->getGlobalScope();
    Address addr(arch.getDefaultCodeSpace(), address);
    auto *fd = scope->queryFunction(addr);
    if (!fd) fd = scope->queryExternalRefFunction(addr);
    if (!fd) throw std::runtime_error("signature address is not a registered function or import");
    auto type = [&](ValueType value) -> Datatype * {
      switch (value) {
      case ValueType::Void: return arch.types->getTypeVoid();
      case ValueType::I32: return arch.types->getBase(4, TYPE_INT);
      case ValueType::U32: return arch.types->getBase(4, TYPE_UINT);
      case ValueType::I64: return arch.types->getBase(8, TYPE_INT);
      case ValueType::U64: return arch.types->getBase(8, TYPE_UINT);
      case ValueType::Pointer: return arch.types->getTypePointer(8, arch.types->getTypeVoid(), 1);
      case ValueType::CharPointer: return arch.types->getTypePointer(8, arch.types->getTypeChar(1), 1);
      case ValueType::WideCharPointer: return arch.types->getTypePointer(8, arch.types->getTypeChar(2), 1);
      case ValueType::U32Pointer: return arch.types->getTypePointer(8, arch.types->getBase(4, TYPE_UINT), 1);
      case ValueType::PointerPointer: return arch.types->getTypePointer(8,
          arch.types->getTypePointer(8, arch.types->getTypeVoid(), 1), 1);
      case ValueType::LuidPointer: return arch.types->getTypePointer(8, impl->luid, 1);
      case ValueType::TokenPrivilegesPointer: return arch.types->getTypePointer(8, impl->token_privileges, 1);
      default: throw std::runtime_error("unknown signature type");
      }
    };
    PrototypePieces pieces;
    pieces.model = arch.defaultfp;
    pieces.outtype = type(result);
    pieces.firstVarArgSlot = -1;
    for (auto parameter : parameters) {
      if (parameter == ValueType::Void) throw std::runtime_error("void is not a parameter type");
      pieces.intypes.push_back(type(parameter));
      pieces.innames.push_back("param_" + std::to_string(pieces.intypes.size()));
    }
    auto &proto = fd->getFuncProto();
    const bool noreturn = proto.isNoReturn();
    proto.setPieces(pieces);
    proto.setInputLock(true);
    proto.setOutputLock(true);
    proto.setModelLock(true);
    proto.setNoReturn(noreturn);
  });
}
void Session::set_preserves_rax(uint64_t address) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    auto &arch = impl->arch;
    auto *fd = arch.symboltab->getGlobalScope()->queryFunction(Address(arch.getDefaultCodeSpace(), address));
    if (!fd) throw std::runtime_error("register effect requires a registered function");
    // FuncProto's documented XML effect overrides merge with the compiler
    // model. Preserve the signature and all other default register effects.
    auto &proto = fd->getFuncProto();
    std::ostringstream encoded;
    XmlEncode encoder(encoded);
    proto.encode(encoder);
    std::istringstream input(encoded.str());
    DocumentStorage store;
    auto *root = store.parseDocument(input)->getRoot();
    auto *effects = new Element(root);
    root->addChild(effects);
    effects->setName("unaffected");
    auto *reg = new Element(effects);
    effects->addChild(reg);
    reg->setName("register");
    reg->addAttribute("name", "RAX");
    XmlDecode decoder(&arch, root);
    proto.decode(decoder, &arch);
  });
}
NativeOutput Session::decompile(uint64_t address, uint32_t timeout_ms, uint32_t max_instructions, uint32_t max_work) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([&] {
    impl->ready();
    if (!timeout_ms || timeout_ms > 60000 || !max_instructions || max_instructions > 100000 || !max_work || max_work > 10000000)
      throw std::runtime_error("invalid decompilation limits");
    auto &arch = impl->arch;
    if (!arch.image().executable(address)) throw std::runtime_error("function is not in executable mapped memory");
    auto *fd = arch.symboltab->getGlobalScope()->queryFunction(Address(arch.getDefaultCodeSpace(), address));
    if (!fd) {
      std::ostringstream name;
      name << "FUN_" << std::hex << address;
      fd = impl->function(address, name.str(), false);
    }
    BudgetGuard guard(timeout_ms, max_work);
    try {
      impl->prepareRequestedWrapper(fd, max_instructions);
      arch.clearAnalysis(fd);
      arch.max_instructions = max_instructions;
      arch.flowoptions |= FlowInfo::error_toomanyinstructions;
      impl->errors.str("");
      std::vector<Funcdata *> inferred;
      std::set<uint64_t> visited{address};
      arch.allacts.getCurrent()->reset(*fd);
      int4 result = arch.allacts.getCurrent()->perform(*fd);
      const auto selected_errors = impl->errors.str();
      impl->inferCallees(fd, 0, visited, inferred);
      if (!inferred.empty()) {
        arch.clearAnalysis(fd);
        impl->errors.str("");
        arch.allacts.getCurrent()->reset(*fd);
        result = arch.allacts.getCurrent()->perform(*fd);
      } else {
        impl->errors.str(selected_errors);
      }
      capax_check();
      OutputBuffer buffer;
      std::ostream output(&buffer);
      output.exceptions(std::ios::badbit | std::ios::failbit);
      arch.print->setOutputStream(&output);
      arch.print->setMarkup(false);
      arch.print->docFunction(fd);
      arch.print->setOutputStream(&impl->errors);
      NativeOutput response;
      response.text = buffer.str();
      for (auto it = arch.commentdb->beginComment(fd->getAddress()); it != arch.commentdb->endComment(fd->getAddress()); ++it)
        if ((*it)->getType() & (Comment::warning | Comment::warningheader)) response.warnings.push_back((*it)->getText());
      if (!impl->errors.str().empty()) response.warnings.push_back(impl->errors.str());
      for (int4 index = 0; index < fd->numCalls(); ++index) {
        const auto *call = fd->getCallSpecs(index);
        if (!call->isInputLocked() || !call->isOutputLocked()) {
          response.warnings.push_back("Unknown callee prototype: forwarded arguments or return types may be missing. Supply signatures for reliable call reconstruction.");
          break;
        }
      }
      response.incomplete = result < 0 || !response.warnings.empty();
      if (!inferred.empty()) response.warnings.push_back("Direct callee prototypes inferred from bounded native analysis; validate against machine code.");
      arch.clearAnalysis(fd);
      for (auto *callee : inferred) {
        callee->getFuncProto().setInputLock(false);
        callee->getFuncProto().setOutputLock(false);
        callee->getFuncProto().setModelLock(false);
        arch.clearAnalysis(callee);
      }
      return response;
    } catch (...) {
      arch.print->setOutputStream(&impl->errors);
      impl->poisoned = true;
      throw;
    }
  });
}
}

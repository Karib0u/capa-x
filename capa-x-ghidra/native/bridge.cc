#include "bridge.hh"
#include "capa-x-ghidra/src/lib.rs.h"
#include "hooks.hh"
#include "specs.hh"
#include "sleigh_arch.hh"
#include "funcdata.hh"
#include "flow.hh"
#include "printc.hh"
#include <algorithm>
#include <chrono>
#include <cctype>
#include <iomanip>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <limits>
#include <set>
#include <map>
#include <vector>
#include <zlib.h>

using namespace ghidra;
namespace {
std::mutex engine_mutex;
std::once_flag initialized;
struct Budget {
  bool active = false;
  /// A checkpoint ran out of budget. The exception it threw can be swallowed by the engine.
  bool exhausted = false;
  uint64_t remaining = 0;
  std::chrono::steady_clock::time_point deadline;
  const char *reason = "";
};
thread_local Budget budget;
// Cooperative limits abort one request; the session stays usable because every
// request starts by clearing the analysis state it touched.
struct BudgetExceeded : std::runtime_error {
  using std::runtime_error::runtime_error;
};
// Charge \p work units, as if the engine had spent them itself.
void charge(uint64_t work) {
  if (!budget.active) return;
  if (budget.remaining < work) { budget.remaining = 0; budget.exhausted = true; budget.reason = "native work limit exceeded"; throw BudgetExceeded(budget.reason); }
  budget.remaining -= work;
}
struct BudgetGuard {
  BudgetGuard(uint32_t ms, uint32_t work) {
    budget = {true, false, work, std::chrono::steady_clock::now() + std::chrono::milliseconds(ms), ""};
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
// One entry per supported language. Everything that differs between x86-32 and
// x86-64 (language, specs, prototype pack, pointer width, the unmapped range used for
// import targets) lives here; the rest of the bridge reads it from the session.
struct Spec {
  bool wide;
  const char *archid;
  const unsigned char *sla; size_t sla_size;
  const unsigned char *pspec; size_t pspec_size;
  const unsigned char *cspec; size_t cspec_size;
  const unsigned char *pack; size_t pack_size;
  int pointer;
  uint64_t external_base;
  uint64_t address_limit;
};
const Spec &spec_for(bool wide) {
  static const Spec x64{true, "x86:LE:64:default:windows", sla_x64_bytes, sizeof(sla_x64_bytes),
    pspec_x64_bytes, sizeof(pspec_x64_bytes), cspec_x64_bytes, sizeof(cspec_x64_bytes),
    pack_x64_bytes, sizeof(pack_x64_bytes), 8, 0xffff000000000000ULL, 0xffff000000000000ULL};
  static const Spec x86{false, "x86:LE:32:default:windows", sla_x86_bytes, sizeof(sla_x86_bytes),
    pspec_x86_bytes, sizeof(pspec_x86_bytes), cspec_x86_bytes, sizeof(cspec_x86_bytes),
    pack_x86_bytes, sizeof(pack_x86_bytes), 4, 0xf0000000ULL, 0xf0000000ULL};
  return wide ? x64 : x86;
}
// Set under engine_mutex around architecture construction, where the SLEIGH hook
// asks for the compiled specification.
const Spec *constructing_spec = nullptr;
struct Section {
  uint64_t address;
  std::vector<uint8_t> bytes;
  bool executable;
};
class Image : public LoadImage {
public:
  std::vector<Section> sections;
  size_t total = 0;
  std::string arch_type;
  explicit Image(const Spec &spec)
    : LoadImage("capa-x image"), arch_type(spec.wide ? "x86:LE:64:default" : "x86:LE:32:default") {}
  std::string getArchType() const override { return arch_type; }
  void adjustVma(long) override { throw LowlevelError("image relocation is unsupported"); }
  bool executable(uint64_t address) const {
    for (const auto &s : sections)
      if (address >= s.address && address - s.address < s.bytes.size()) return s.executable;
    return false;
  }
  /// The mapped bytes from \p address to the end of its section, or empty.
  std::pair<const uint8_t *, size_t> bytesAt(uint64_t address) const {
    for (const auto &s : sections)
      if (address >= s.address && address - s.address < s.bytes.size())
        return {s.bytes.data() + (address - s.address), s.bytes.size() - size_t(address - s.address)};
    return {nullptr, 0};
  }
  bool mapped(uint64_t address) const { return bytesAt(address).first != nullptr; }
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
// Data symbols. Ghidra's Java analysis labels the data a function touches:
// `DAT_<addr>` for plain data, `PTR_<target>_<addr>` for a pointer cell and
// `s_<text>_<addr>` / `u_<text>_<addr>` for narrow and wide string literals.
// The embedded engine has no program database, so the adapter derives the same
// names from the image bytes, per request (see docs/decompiler.md). Constants
// copied from Ghidra 12.1.4's observed labels: at most 32 characters of text,
// every character other than a letter, digit, `_`, `<` or `>` becomes `_`, trailing
// line breaks are dropped, and the address is lowercase hex padded to 8 digits.
struct StringLiteral {
  bool wide = false;
  size_t chars = 0;
  std::string label;
};
constexpr size_t kMinStringChars = 4;
constexpr size_t kMaxStringChars = 4096;
constexpr size_t kMaxLabelChars = 32;
std::string hexAddress(uint64_t address) {
  char text[24];
  std::snprintf(text, sizeof(text), "%08llx", static_cast<unsigned long long>(address));
  return text;
}
/// The engine's own default name for a global it had no symbol for, e.g. `uRam0000000140004098`.
/// mapGlobals stores these in the global scope, where they would otherwise outlive the request.
bool placeholderName(const std::string &name) {
  size_t i = 0;
  while (i < 8 && i < name.size() && std::isalpha(static_cast<unsigned char>(name[i])) && name.compare(i, 3, "Ram") != 0) ++i;
  // The address prints with two hex digits per address byte: 16 in x86-64, 8 in x86-32.
  if (name.compare(i, 3, "Ram") != 0 || (name.size() != i + 3 + 16 && name.size() != i + 3 + 8)) return false;
  for (size_t k = i + 3; k < name.size(); ++k)
    if (!((name[k] >= '0' && name[k] <= '9') || (name[k] >= 'a' && name[k] <= 'f'))) return false;
  return true;
}
std::string labelFromText(const std::string &text) {
  size_t end = text.size();
  while (end && (text[end - 1] == '\n' || text[end - 1] == '\r' || text[end - 1] == '\t')) --end;
  std::string label;
  for (size_t i = 0; i < end && i < kMaxLabelChars; ++i) {
    const unsigned char ch = static_cast<unsigned char>(text[i]);
    const bool keep = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
                      ch == '_' || ch == '<' || ch == '>';
    label += keep ? char(ch) : '_';
  }
  return label;
}
bool printable(unsigned ch) { return (ch >= 0x20 && ch < 0x7f) || ch == '\t' || ch == '\n' || ch == '\r'; }
/// A NUL-terminated printable ASCII or UTF-16LE (ASCII range) string at \p address.
bool detectString(const Image &image, uint64_t address, StringLiteral &out) {
  const auto [data, available] = image.bytesAt(address);
  if (!data) return false;
  size_t n = 0;
  while (n < available && n < kMaxStringChars && printable(data[n])) ++n;
  if (n >= kMinStringChars && n < available && data[n] == 0) {
    out.wide = false;
    out.chars = n;
    out.label = labelFromText(std::string(reinterpret_cast<const char *>(data), n));
    return true;
  }
  std::string text;
  size_t w = 0;
  while ((w + 1) * 2 + 1 < available && w < kMaxStringChars && data[2 * w + 1] == 0 && printable(data[2 * w])) {
    text += char(data[2 * w]);
    ++w;
  }
  if (w >= kMinStringChars && (w * 2 + 1) < available && data[2 * w] == 0 && data[2 * w + 1] == 0) {
    out.wide = true;
    out.chars = w;
    out.label = labelFromText(text);
    return true;
  }
  return false;
}
class ImageSleigh : public Sleigh {
  Image *image;
public:
  ImageSleigh(Image *loader, ContextDatabase *context) : Sleigh(loader, context), image(loader) {}
  int4 oneInstruction(PcodeEmit &emit, const Address &address) const override {
    if (!image->executable(address.getOffset())) {
      char text[80];
      std::snprintf(text, sizeof(text), "code flow left executable mapped memory at 0x%llx",
                    static_cast<unsigned long long>(address.getOffset()));
      // Ghidra's flow analysis turns this error into a warning and truncates the flow, which
      // keeps the rest of the function instead of failing the request.
      throw BadDataError(text);
    }
    const auto length = Sleigh::oneInstruction(emit, address);
    if (length <= 0 || address.getOffset() > UINT64_MAX - uint64_t(length - 1) ||
        !image->executable(address.getOffset() + length - 1))
      throw BadDataError("instruction crosses executable mapping boundary");
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
// Prototype and type pack: Ghidra data type archive content exported offline
// (scripts/decompiler_types) in Ghidra's own decompiler marshalling. Entries are
// zlib blocks; a lookup inflates one bounded block. Serialized by engine_mutex.
class PrototypePack {
  struct Block { uint32_t offset, clength, rlength; std::string first; };
  std::vector<Block> blocks;
  const uint8_t *data = nullptr;
  size_t data_size = 0;
  std::map<size_t, std::string> cache;
  static uint32_t u32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | uint32_t(p[3]) << 24; }
  const std::string &inflated(size_t index) {
    auto found = cache.find(index);
    if (found != cache.end()) return found->second;
    const Block &b = blocks[index];
    if (b.rlength > 4 * 1024 * 1024) throw std::runtime_error("prototype pack block too large");
    std::string raw(b.rlength, '\0');
    uLongf length = b.rlength;
    if (uncompress(reinterpret_cast<Bytef *>(&raw[0]), &length, data + b.offset, b.clength) != Z_OK || length != b.rlength)
      throw std::runtime_error("corrupt prototype pack block");
    if (cache.size() >= 16) cache.clear();
    return cache.emplace(index, std::move(raw)).first->second;
  }
public:
  PrototypePack(const unsigned char *bytes, size_t size) {
    const char magic[] = "CXPROTO1";
    if (size < 12 || memcmp(bytes, magic, 8) != 0) throw std::runtime_error("bad prototype pack header");
    const uint32_t count = u32(bytes + 8);
    size_t pos = 12;
    for (uint32_t i = 0; i < count; i++) {
      if (size - pos < 14) throw std::runtime_error("truncated prototype pack index");
      Block b{u32(bytes + pos), u32(bytes + pos + 4), u32(bytes + pos + 8), ""};
      const size_t key = bytes[pos + 12] | bytes[pos + 13] << 8;
      pos += 14;
      if (size - pos < key) throw std::runtime_error("truncated prototype pack key");
      b.first.assign(reinterpret_cast<const char *>(bytes + pos), key);
      pos += key;
      blocks.push_back(std::move(b));
    }
    data = bytes + pos;
    data_size = size - pos;
    for (const auto &b : blocks)
      if (b.offset > data_size || b.clength > data_size - b.offset) throw std::runtime_error("prototype pack block out of range");
  }
  size_t block_count() const { return blocks.size(); }
  /// Value after the first tab of the line keyed \p key.
  bool find(const std::string &key, std::string &value) {
    auto it = std::upper_bound(blocks.begin(), blocks.end(), key,
      [](const std::string &k, const Block &b) { return k < b.first; });
    if (it == blocks.begin()) return false;
    const std::string &raw = inflated(size_t(it - blocks.begin()) - 1);
    size_t pos = 0;
    while (pos < raw.size()) {
      size_t end = raw.find('\n', pos);
      if (end == std::string::npos) end = raw.size();
      const size_t tab = raw.find('\t', pos);
      if (tab != std::string::npos && tab < end && raw.compare(pos, tab - pos, key) == 0) {
        value.assign(raw, tab + 1, end - tab - 1);
        return true;
      }
      pos = end + 1;
    }
    return false;
  }
  /// Every key of every block, for validation.
  std::vector<std::string> keys() {
    std::vector<std::string> out;
    for (size_t i = 0; i < blocks.size(); i++) {
      const std::string raw = inflated(i);
      size_t pos = 0;
      while (pos < raw.size()) {
        size_t end = raw.find('\n', pos);
        if (end == std::string::npos) end = raw.size();
        const size_t tab = raw.find('\t', pos);
        if (tab != std::string::npos && tab < end) out.push_back(raw.substr(pos, tab - pos));
        pos = end + 1;
      }
    }
    return out;
  }
};
PrototypePack &prototype_pack(const Spec &spec) {
  static PrototypePack x64(spec_for(true).pack, spec_for(true).pack_size);
  static PrototypePack x86(spec_for(false).pack, spec_for(false).pack_size);
  return spec.wide ? x64 : x86;
}
std::string type_key(uint64_t id) {
  char buffer[32];
  snprintf(buffer, sizeof buffer, "T:0x%llx", static_cast<unsigned long long>(id));
  return buffer;
}
/// Resolves named types the way Ghidra's decompiler asks its host: on demand.
class TypeFactoryPack : public TypeFactory {
  // Recursive definitions end at the stub objects the decoder creates, so
  // re-entry for an id is legitimate; bound it to protect the native stack.
  std::map<uint64_t, int> loading;
  int depth = 0;
  struct Loading {
    TypeFactoryPack &owner;
    uint64_t id;
    ~Loading() {
      owner.depth--;
      if (--owner.loading[id] == 0) owner.loading.erase(id);
    }
  };
public:
  const Spec &spec;
  TypeFactoryPack(Architecture *g, const Spec &s) : TypeFactory(g), spec(s) {}
  Datatype *resolve(uint64_t id) { return findById("", id, 0); }
  Datatype *findById(const std::string &n, uint8 id, int4 sz) override {
    Datatype *known = TypeFactory::findById(n, id, sz);
    if (known) return known;
    // Ghidra's untyped bytes; the C++ core types call them xunknown.
    if (n.size() == 10 && n.compare(0, 9, "undefined") == 0 && n[9] >= '1' && n[9] <= '8' && (n[9] == '1' || n[9] == '2' || n[9] == '4' || n[9] == '8'))
      return getBase(n[9] - '0', TYPE_UNKNOWN);
    if (id == 0 || sz > 0) return nullptr;
    std::string value;
    if (!prototype_pack(spec).find(type_key(id), value)) return nullptr;
    if (depth >= 64 || loading[id] >= 3) throw LowlevelError("packed type definition nests too deeply: " + n);
    loading[id]++;
    depth++;
    Loading guard{*this, id};
    const size_t tab = value.find('\t');
    if (tab == std::string::npos) throw LowlevelError("malformed packed type: " + n);
    std::istringstream input(value.substr(tab + 1));
    DocumentStorage store;
    XmlDecode decoder(glb, store.parseDocument(input)->getRoot());
    return decodeType(decoder);
  }
};
class ArchitectureX86 : public SleighArchitecture {
  const Spec &spec;
protected:
  void buildLoader(DocumentStorage &) override { loader = new Image(spec); }
  void buildTypegrp(DocumentStorage &) override { types = new TypeFactoryPack(this, spec); }
  void resolveArchitecture() override { archid = spec.archid; }
  void buildSpecFile(DocumentStorage &store) override {
    for (auto pair : {std::make_pair(spec.pspec, spec.pspec_size), std::make_pair(spec.cspec, spec.cspec_size)}) {
      std::istringstream stream(std::string(reinterpret_cast<const char *>(pair.first), pair.second));
      store.registerTag(store.parseDocument(stream)->getRoot());
    }
    std::istringstream stream("<sleigh>embedded</sleigh>");
    store.registerTag(store.parseDocument(stream)->getRoot());
  }
  Translate *buildTranslator(DocumentStorage &) override { return new ImageSleigh(static_cast<Image *>(loader), context); }
  void modifySpaces(Translate *) override {}
public:
  ArchitectureX86(const Spec &s, std::ostream *errors) : SleighArchitecture("", s.archid, errors), spec(s) {
    if (!dynamic_cast<PrintC *>(print)) throw LowlevelError("C printer unavailable");
  }
  ~ArchitectureX86() override { delete translate; translate = nullptr; }
  std::string getDescription() const override { return spec.wide ? "x86-64 Windows" : "x86-32 Windows"; }
  Image &image() { return *static_cast<Image *>(loader); }
  const Spec &language() const { return spec; }
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
  if (!constructing_spec) throw std::runtime_error("no language selected for the SLEIGH specification");
  return std::string(reinterpret_cast<const char *>(constructing_spec->sla), constructing_spec->sla_size);
}
void capax_check() {
  if (!budget.active) return;
  if (budget.remaining-- == 0) { budget.exhausted = true; budget.reason = "native work limit exceeded"; throw BudgetExceeded(budget.reason); }
  if (std::chrono::steady_clock::now() >= budget.deadline) {
    budget.exhausted = true;
    budget.reason = "native decompilation deadline exceeded";
    throw BudgetExceeded(budget.reason);
  }
}
// TypeFactory::setFields is private since Ghidra 12 and the public route is the
// XML decoder. Explicit instantiation may name a private member, which yields a
// member pointer without modifying the pinned headers or casting any object.
struct SetStructFieldsTag {
  using type = void (TypeFactory::*)(const vector<TypeField> &, const vector<TypeBitField> &,
                                     TypeStruct *, int4, int4, uint4);
};
SetStructFieldsTag::type access_set_struct_fields(SetStructFieldsTag);
template <typename Tag, typename Tag::type Member>
struct AccessPrivate {
  friend typename Tag::type access_set_struct_fields(Tag) { return Member; }
};
template struct AccessPrivate<SetStructFieldsTag, &TypeFactory::setFields>;

namespace capax {
class Session::Impl {
public:
  std::ostringstream errors;
  const Spec &spec;
  ArchitectureX86 arch;
  int ptr() const { return spec.pointer; }
  bool poisoned = false;
  size_t symbols = 0;
  size_t edges = 0;
  std::set<uint64_t> supplied_entries;
  TypeStruct *luid;
  TypeStruct *token_privileges;
  explicit Impl(const Spec &s) : spec(s), arch(s, &errors) {
    DocumentStorage store;
    arch.init(store);
    arch.setPrintLanguage("c-language");
    // Windows x64 SDK layouts (winnt.h). DWORD and LONG are four bytes;
    // ANYSIZE_ARRAY is one in the declaration, not a runtime allocation bound.
    // See docs/decompiler.md for the declarations and provenance.
    auto *types = arch.types;
    auto set_struct_fields = access_set_struct_fields(SetStructFieldsTag());
    auto *u32 = types->getBase(4, TYPE_UINT);
    luid = types->getTypeStruct("LUID");
    (types->*set_struct_fields)({TypeField(0, 0, "LowPart", u32),
      TypeField(1, 4, "HighPart", types->getBase(4, TYPE_INT))}, {}, luid, 8, 4, 0);
    auto *attributes = types->getTypeStruct("LUID_AND_ATTRIBUTES");
    (types->*set_struct_fields)({TypeField(0, 0, "Luid", luid),
      TypeField(1, 8, "Attributes", u32)}, {}, attributes, 12, 4, 0);
    token_privileges = types->getTypeStruct("TOKEN_PRIVILEGES");
    (types->*set_struct_fields)({TypeField(0, 0, "PrivilegeCount", u32),
      TypeField(1, 4, "Privileges", types->getTypeArray(1, attributes))}, {}, token_privileges, 16, 4, 0);
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
        {
          fd->getOverride().insertFlowOverride(Address(arch.getDefaultCodeSpace(), current), Override::CALL_RETURN);
          invalidateInferred();
        }
        return;
      }
      if (length <= 0 || current > UINT64_MAX - uint64_t(length)) return;
      current += length;
    }
  }
  // Callee prototype inference. Locks never outlive one function's analysis, so
  // the result for (target, level) is a pure function of the image and explicit
  // signatures and can be cached for the session. A cache hit charges the work
  // the original computation took, so limits behave identically in any request
  // order. set_signature and the other mutators drop the cache.
  // Local safety policy: at most 16 direct callees per request, 16 analyzed
  // functions below each, and four call levels.
  struct Inferred {
    bool usable = false;
    PrototypePieces pieces;
    uint64_t cost = 0;
    unsigned size = 0;
  };
  std::map<std::pair<uint64_t, unsigned>, Inferred> inferred_cache;
  std::set<uint64_t> in_progress;
  std::set<Funcdata *> touched;
  std::vector<Funcdata *> applied;
  void invalidateInferred() { inferred_cache.clear(); }
  // Data symbols added for the current request; dropped when it ends, so output is
  // a function of the image and the request, never of request order.
  std::vector<Symbol *> data_symbols;
  struct DataReference {
    int4 size = 0;
    bool address_taken = false;
  };
  /// Name the data \p fd's finished analysis touched. Returns true if any symbol was added.
  bool addDataSymbols(Funcdata *fd) {
    auto &image = arch.image();
    auto *scope = arch.symboltab->getGlobalScope();
    auto *space = arch.getDefaultCodeSpace();
    std::map<uint64_t, DataReference> refs;
    const auto data = [&](uint64_t address) { return image.mapped(address) && !image.executable(address); };
    for (auto it = fd->beginLoc(); it != fd->endLoc() && refs.size() < 4096; ++it) {
      const Varnode *vn = *it;
      if (vn->getSpace() != space || vn->isFree() || vn->isAnnotation()) continue;
      if (!data(vn->getOffset())) continue;
      auto &ref = refs[vn->getOffset()];
      ref.size = std::max(ref.size, vn->getSize());
    }
    for (auto it = fd->beginOpAll(); it != fd->endOpAll() && refs.size() < 4096; ++it) {
      const PcodeOp *op = it->second;
      if (op->isDead()) continue;
      for (int4 slot = 0; slot < op->numInput(); ++slot) {
        const Varnode *vn = op->getIn(slot);
        if (!vn->isConstant() || (slot == 0 && (op->code() == CPUI_LOAD || op->code() == CPUI_STORE))) continue;
        if (!data(vn->getOffset())) continue;
        const bool access = slot == 1 && (op->code() == CPUI_LOAD || op->code() == CPUI_STORE);
        auto &ref = refs[vn->getOffset()];
        if (access) {
          const int4 size = op->code() == CPUI_LOAD ? op->getOut()->getSize() : op->getIn(2)->getSize();
          ref.size = std::max(ref.size, size);
        } else {
          ref.address_taken = true;
        }
      }
    }
    uint64_t covered_until = 0;
    bool added = false;
    for (const auto &[address, ref] : refs) {
      if (address < covered_until) continue;
      // The first pass names untouched globals with engine default names such as `uRam...`;
      // those are placeholders to replace. Anything else (an import, a function) is kept.
      const auto occupied = [&](uint64_t at, bool replace) {
        for (int guard = 0; guard < 8; ++guard) {
          auto *found = scope->queryContainer(Address(space, at), 1, Address());
          if (!found) return false;
                  if (!replace || !(found->getSymbol()->isNameUndefined() || placeholderName(found->getSymbol()->getName()))) return true;
          scope->removeSymbol(found->getSymbol());
        }
        return true;
      };
      if (occupied(address, true)) continue;
      StringLiteral literal;
      const bool is_string = ref.address_taken && detectString(image, address, literal);
      int4 size = std::max<int4>(ref.size, 1);
      std::string name;
      Datatype *type = nullptr;
      if (is_string) {
        name = std::string(literal.wide ? "u_" : "s_") + literal.label + "_" + hexAddress(address);
        size = int4((literal.chars + 1) * (literal.wide ? 2 : 1));
        type = arch.types->getTypeArray(int4(literal.chars + 1), arch.types->getTypeChar(literal.wide ? 2 : 1));
      } else {
        std::string target = "DAT";
        std::string label;
        const auto [bytes, available] = image.bytesAt(address);
        const int width = ptr();
        if ((ref.size == width || ref.size == 0) && address % width == 0 && available >= size_t(width)) {
          uint64_t value = 0;
          for (int i = width - 1; i >= 0; --i) value = (value << 8) | bytes[i];
          if (image.executable(value)) {
            target = "PTR_FUN";
            size = width;
          } else if (image.mapped(value)) {
            size = width;
            StringLiteral pointee;
            target = detectString(image, value, pointee)
                         ? std::string("PTR_") + (pointee.wide ? "u_" : "s_") + pointee.label
                         : "PTR_DAT";
          }
        }
        name = target + "_" + hexAddress(address);
        type = arch.types->getBase(size, TYPE_UNKNOWN);
      }
      if (address > UINT64_MAX - uint64_t(size) || occupied(address + size - 1, true))
        continue;
      if (++symbols > 100000) throw std::runtime_error("symbol limit exceeded");
      auto *entry = scope->addSymbol(name, type, Address(space, address), Address());
      if (!entry) continue;
      scope->setAttribute(entry->getSymbol(), Varnode::namelock);
      data_symbols.push_back(entry->getSymbol());
      covered_until = address + size;
      added = true;
    }
    return added;
  }
  void dropDataSymbols() {
    auto *scope = arch.symboltab->getGlobalScope();
    for (auto *symbol : data_symbols) scope->removeSymbol(symbol);
    symbols -= std::min(symbols, data_symbols.size());
    data_symbols.clear();
    // Placeholder globals made while analyzing this request would otherwise leak into the
    // next one (named by whichever type was seen first), so output would depend on order.
    std::vector<Symbol *> placeholders;
    for (auto it = scope->begin(); it != scope->end(); ++it) {
      Symbol *symbol = (*it)->getSymbol();
      if (placeholderName(symbol->getName()) && placeholders.end() == std::find(placeholders.begin(), placeholders.end(), symbol))
        placeholders.push_back(symbol);
    }
    for (auto *symbol : placeholders) scope->removeSymbol(symbol);
  }
  static std::set<uint64_t> directTargets(Funcdata *caller) {
    std::set<uint64_t> targets;
    for (int4 i = 0; i < caller->numCalls(); ++i) {
      capax_check();
      auto *call = caller->getCallSpecs(i);
      if (!call->getEntryAddress().isInvalid()) targets.insert(call->getEntryAddress().getOffset());
    }
    return targets;
  }
  int4 analyze(Funcdata *fd) {
    arch.clearAnalysis(fd);
    errors.str("");
    int4 status;
    try {
      arch.allacts.getCurrent()->reset(*fd);
      status = arch.allacts.getCurrent()->perform(*fd);
    } catch (...) {
      // An exception out of the action tree (a limit, or an engine error) leaves its groups
      // half-run, and the next request can walk off the stale state into a null action
      // (seen after a deadline during jump table recovery). Derive a fresh tree.
      arch.allacts.resetDefaults();
      throw;
    }
    // Some engine paths swallow the checkpoint exception (jump table recovery runs nested
    // analysis), leaving a function without structure. An empty budget says why.
    if (budget.active && budget.exhausted) throw BudgetExceeded(budget.reason);
    return status;
  }
  void apply(uint64_t target, const Inferred &entry) {
    auto *fd = arch.symboltab->getGlobalScope()->queryFunction(Address(arch.getDefaultCodeSpace(), target));
    auto &proto = fd->getFuncProto();
    proto.setPieces(entry.pieces);
    proto.setInputLock(true);
    proto.setOutputLock(true);
    proto.setModelLock(true);
    applied.push_back(fd);
  }
  /// Drop every inferred lock and the analysis state of everything a request
  /// touched, so the next request sees only supplied facts.
  void release(Funcdata *selected) {
    for (auto *fd : applied) {
      fd->getFuncProto().setInputLock(false);
      fd->getFuncProto().setOutputLock(false);
      fd->getFuncProto().setModelLock(false);
    }
    applied.clear();
    in_progress.clear();
    touched.insert(selected);
    for (auto *fd : touched) {
      arch.clearAnalysis(fd);
      fd->getFuncProto().clearUnlockedInput();
      fd->getFuncProto().clearUnlockedOutput();
    }
    touched.clear();
  }
  const Inferred &infer(uint64_t target, unsigned level) {
    const auto key = std::make_pair(target, level);
    auto cached = inferred_cache.find(key);
    if (cached != inferred_cache.end()) {
      charge(cached->second.cost);
      return cached->second;
    }
    const uint64_t before = budget.active ? budget.remaining : 0;
    Inferred out;
    out.size = 1;
    auto *fd = arch.symboltab->getGlobalScope()->queryFunction(Address(arch.getDefaultCodeSpace(), target));
    if (arch.image().executable(target) && fd && !fd->getFuncProto().isInputLocked() &&
        !fd->getFuncProto().isOutputLocked()) {
      touched.insert(fd);
      in_progress.insert(target);
      // A callee whose flow cannot be translated (it runs into data or unmapped memory) only
      // costs its own inferred prototype; the selected function must not fail for it.
      const auto mark = applied.size();
      try {
        inferBody(fd, target, level, out);
      } catch (const LowlevelError &) {
        for (auto i = applied.size(); i-- > mark;) unlockOne(applied[i]);
        applied.resize(mark);
        out.usable = false;
        errors.str("");
        in_progress.erase(target);
        arch.clearAnalysis(fd);
      }
    }
    if (out.size > 16) out.usable = false;
    out.cost = budget.active ? before - budget.remaining : 0;
    return inferred_cache.emplace(key, std::move(out)).first->second;
  }
  void inferBody(Funcdata *fd, uint64_t target, unsigned level, Inferred &out) {
    {
      int4 status = analyze(fd);
      const auto own_errors = errors.str();
      std::vector<std::pair<uint64_t, const Inferred *>> usable_children;
      if (level < 4) {
        for (auto child : directTargets(fd)) {
          if (in_progress.count(child) || out.size > 16) continue;
          const auto &entry = infer(child, level + 1);
          out.size += entry.size;
          if (entry.usable) usable_children.emplace_back(child, &entry);
        }
      }
      if (!usable_children.empty()) {
        const auto mark = applied.size();
        for (auto &[child, entry] : usable_children) apply(child, *entry);
        status = analyze(fd);
        out.usable = status >= 0;
        collect(fd, out);
        for (auto i = applied.size(); i-- > mark;) unlockOne(applied[i]);
        applied.resize(mark);
      } else {
        errors.str(own_errors);
        out.usable = status >= 0;
        collect(fd, out);
      }
      in_progress.erase(target);
      arch.clearAnalysis(fd);
      errors.str("");
    }
  }
  static void unlockOne(Funcdata *fd) {
    fd->getFuncProto().setInputLock(false);
    fd->getFuncProto().setOutputLock(false);
    fd->getFuncProto().setModelLock(false);
  }
  /// Decide whether \p fd's finished analysis is trustworthy, and if so keep its pieces.
  void collect(Funcdata *fd, Inferred &out) {
    if (!out.usable || fd->getFuncProto().numParams() > 32 || !errors.str().empty()) { out.usable = false; return; }
    for (auto it = arch.commentdb->beginComment(fd->getAddress()); it != arch.commentdb->endComment(fd->getAddress()); ++it)
      if ((*it)->getType() & (Comment::warning | Comment::warningheader)) out.usable = false;
    for (int4 i = 0; i < fd->numCalls(); ++i) {
      const auto *call = fd->getCallSpecs(i);
      if (!call->isInputLocked() || !call->isOutputLocked()) out.usable = false;
    }
    if (out.usable) fd->getFuncProto().getPieces(out.pieces);
  }
  /// Infer and lock the direct callees of \p selected; returns how many were applied.
  size_t inferDirect(Funcdata *selected) {
    in_progress.insert(selected->getAddress().getOffset());
    size_t count = 0, seen = 0;
    std::vector<std::pair<uint64_t, const Inferred *>> usable;
    for (auto target : directTargets(selected)) {
      if (in_progress.count(target)) continue;
      if (++seen > 16) break;
      const auto &entry = infer(target, 1);
      if (entry.usable) usable.emplace_back(target, &entry);
    }
    for (auto &[target, entry] : usable) { apply(target, *entry); ++count; }
    return count;
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
  /// Apply a packed archive prototype to \p fd. Windows x64 has one ABI, so
  /// archive convention names such as __stdcall map to the default model.
  bool apply_pack_prototype(Funcdata *fd, const std::string &function) {
    std::string xml;
    if (!prototype_pack(spec).find("F:" + function, xml)) return false;
    const size_t at = xml.find(" model=\"");
    if (at != std::string::npos) {
      const size_t start = at + 8, end = xml.find('"', start);
      if (end != std::string::npos && !arch.getModel(xml.substr(start, end - start)))
        xml.replace(start, end - start, arch.defaultfp->getName());
    }
    std::istringstream input(xml);
    DocumentStorage store;
    XmlDecode decoder(&arch, store.parseDocument(input)->getRoot());
    // A symbol-backed prototype cannot decode a full definition, so decode into a
    // standalone prototype and transfer its pieces, as set_signature does.
    FuncProto decoded;
    decoded.setInternal(arch.defaultfp, arch.types->getTypeVoid());
    decoded.decode(decoder, &arch);
    PrototypePieces pieces;
    decoded.getPieces(pieces);
    auto &proto = fd->getFuncProto();
    const bool noreturn = proto.isNoReturn() || decoded.isNoReturn();
    proto.setPieces(pieces);
    proto.setInputLock(true);
    proto.setOutputLock(true);
    proto.setModelLock(true);
    proto.setNoReturn(noreturn);
    return true;
  }
};
Session::Session(bool wide) : impl(checked([wide] {
  const Spec &spec = spec_for(wide);
  constructing_spec = &spec;
  return std::unique_ptr<Impl>(new Impl(spec));
})) {}
Session::~Session() { std::lock_guard<std::mutex> lock(engine_mutex); impl.reset(); }
std::unique_ptr<Session> new_session(bool wide) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([wide] {
    std::call_once(initialized, [] {
      AttributeId::initialize(); ElementId::initialize(); CapabilityPoint::initializeAll();
    });
    return std::unique_ptr<Session>(new Session(wide));
  });
}
void Session::add_section(uint64_t address, rust::Slice<const uint8_t> bytes, bool executable, bool readonly) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    auto &image = impl->arch.image();
    if (bytes.empty() || bytes.size() > 256 * 1024 * 1024 - image.total ||
        address >= impl->spec.address_limit || bytes.size() >= impl->spec.address_limit - address || image.sections.size() >= 4096)
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
    impl->invalidateInferred();
    impl->function(address, identifier(name), noreturn);
    impl->supplied_entries.insert(address);
  });
}
void Session::add_import(uint64_t address, rust::Str name, bool noreturn) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    impl->invalidateInferred();
    auto &arch = impl->arch;
    if (address > UINT64_MAX - 7 || address + impl->ptr() > impl->spec.address_limit) throw std::runtime_error("import slot address overflow");
    // Only the IAT slot is mutable. Preserve read-only strings/constants in
    // the rest of the section instead of disabling the whole section.
    arch.symboltab->clearPropertyRange(Varnode::readonly,
      Range(arch.getDefaultCodeSpace(), address, address + impl->ptr() - 1));
    // ExternRefSymbol's address is the IAT slot. Its target names a function
    // in a reserved unmapped range, never executable sample bytes.
    const uint64_t target = impl->spec.external_base + impl->symbols * 16;
    impl->function(target, identifier(name), noreturn);
    arch.symboltab->getGlobalScope()->addExternalRef(Address(arch.getDefaultCodeSpace(), address),
      Address(arch.getDefaultCodeSpace(), target), identifier(name));
  });
}
bool Session::apply_prototype(uint64_t address, rust::Str name) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([&] {
    impl->ready();
    impl->invalidateInferred();
    if (name.size() > 256) throw std::runtime_error("function name exceeds 256 bytes");
    auto &arch = impl->arch;
    auto *scope = arch.symboltab->getGlobalScope();
    Address addr(arch.getDefaultCodeSpace(), address);
    auto *fd = scope->queryFunction(addr);
    if (!fd) fd = scope->queryExternalRefFunction(addr);
    if (!fd) throw std::runtime_error("prototype address is not a registered function or import");
    try {
      return impl->apply_pack_prototype(fd, std::string(name));
    } catch (const LowlevelError &) {
      // A handful of archive types still cannot be reconstructed (see the
      // validation test); leave the prototype unknown rather than guessed.
      return false;
    } catch (const DecoderError &) {
      return false;
    }
  });
}
rust::String Session::validate_prototype_pack(uint32_t max_report) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([&] {
    impl->ready();
    size_t functions = 0, types = 0, failures = 0;
    std::string report;
    auto fail = [&](const std::string &key, const std::string &what) {
      if (failures++ < max_report) report += "\n  " + key + ": " + what;
    };
    for (const auto &key : prototype_pack(impl->spec).keys()) {
      try {
        if (key.compare(0, 2, "T:") == 0) {
          types++;
          const uint64_t id = std::stoull(key.substr(2), nullptr, 16);
          if (!static_cast<TypeFactoryPack *>(impl->arch.types)->resolve(id)) fail(key, "not resolved");
        } else {
          functions++;
          if (impl->symbols + 1 > 99999) throw LowlevelError("validation symbol limit");
          const uint64_t target = impl->spec.external_base + impl->symbols * 16;
          auto *fd = impl->function(target, "validate_" + std::to_string(functions), false);
          if (!impl->apply_pack_prototype(fd, key.substr(2))) fail(key, "not found");
        }
      } catch (const LowlevelError &e) {
        fail(key, e.explain);
      } catch (const DecoderError &e) {
        fail(key, e.explain);
      }
    }
    return rust::String("functions=" + std::to_string(functions) + " types=" + std::to_string(types) +
                        " failures=" + std::to_string(failures) + report);
  });
}
void Session::add_tail_call(uint64_t caller, uint64_t site, uint64_t target) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    impl->invalidateInferred();
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
    impl->invalidateInferred();
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
      case ValueType::Pointer: return arch.types->getTypePointer(arch.getDefaultCodeSpace()->getAddrSize(), arch.types->getTypeVoid(), 1);
      case ValueType::CharPointer: return arch.types->getTypePointer(arch.getDefaultCodeSpace()->getAddrSize(), arch.types->getTypeChar(1), 1);
      case ValueType::WideCharPointer: return arch.types->getTypePointer(arch.getDefaultCodeSpace()->getAddrSize(), arch.types->getTypeChar(2), 1);
      case ValueType::U32Pointer: return arch.types->getTypePointer(arch.getDefaultCodeSpace()->getAddrSize(), arch.types->getBase(4, TYPE_UINT), 1);
      case ValueType::PointerPointer: return arch.types->getTypePointer(arch.getDefaultCodeSpace()->getAddrSize(),
          arch.types->getTypePointer(arch.getDefaultCodeSpace()->getAddrSize(), arch.types->getTypeVoid(), 1), 1);
      case ValueType::LuidPointer: return arch.types->getTypePointer(arch.getDefaultCodeSpace()->getAddrSize(), impl->luid, 1);
      case ValueType::TokenPrivilegesPointer: return arch.types->getTypePointer(arch.getDefaultCodeSpace()->getAddrSize(), impl->token_privileges, 1);
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
    impl->invalidateInferred();
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
void Session::set_call_fixup(uint64_t address, rust::Str fixup) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  checked([&] {
    impl->ready();
    auto &arch = impl->arch;
    auto *fd = arch.symboltab->getGlobalScope()->queryFunction(Address(arch.getDefaultCodeSpace(), address));
    if (!fd) throw std::runtime_error("call fixup requires a registered function");
    if (fixup.size() > 64) throw std::runtime_error("call fixup name exceeds 64 bytes");
    const std::string name(fixup.data(), fixup.size());
    const int4 id = arch.pcodeinjectlib->getPayloadId(InjectPayload::CALLFIXUP_TYPE, name);
    if (id < 0) throw std::runtime_error("unknown call fixup: " + name);
    impl->invalidateInferred();
    fd->getFuncProto().setInjectId(id);
  });
}
NativeOutput Session::decompile(uint64_t address, uint32_t timeout_ms, uint32_t max_instructions, uint32_t max_work) {
  std::lock_guard<std::mutex> lock(engine_mutex);
  return checked([&] {
    impl->ready();
    if (!timeout_ms || timeout_ms > 60000 || !max_instructions || max_instructions > 100000 || !max_work || max_work > 200000000)
      throw std::runtime_error("invalid decompilation limits");
    auto &arch = impl->arch;
    if (!arch.image().executable(address)) throw std::runtime_error("function is not in executable mapped memory");
    auto *fd = arch.symboltab->getGlobalScope()->queryFunction(Address(arch.getDefaultCodeSpace(), address));
    if (!fd) {
      std::ostringstream name;
      name << "FUN_" << std::hex;
      if (!impl->spec.wide) name << std::setw(8) << std::setfill('0');
      name << address;
      fd = impl->function(address, name.str(), false);
      impl->invalidateInferred();
    }
    // Each phase gets the full budget: a heavy callee inference must not starve
    // or lose the selected function's own analysis.
    const auto fresh = [&] { return BudgetGuard(timeout_ms, max_work); };
    const auto attempt = [&](bool truncate) -> NativeOutput {
    try {
      arch.max_instructions = max_instructions;
      if (truncate) arch.flowoptions &= ~FlowInfo::error_toomanyinstructions;
      else arch.flowoptions |= FlowInfo::error_toomanyinstructions;
      int4 result;
      std::string baseline_errors;
      {
        auto guard = fresh();
        impl->prepareRequestedWrapper(fd, max_instructions);
        result = impl->analyze(fd);
        baseline_errors = impl->errors.str();
      }
      // Name the data the first pass found, then analyze again so the names print.
      // The symbols are not part of the supplied facts: they live for this request only.
      if (result >= 0 && impl->addDataSymbols(fd)) {
        try {
          auto guard = fresh();
          result = impl->analyze(fd);
          baseline_errors = impl->errors.str();
        } catch (const BudgetExceeded &) {
          impl->dropDataSymbols();
          impl->release(fd);
          auto guard = fresh();
          result = impl->analyze(fd);
          baseline_errors = impl->errors.str();
        }
      }
      size_t inferred = 0;
      std::string skipped;
      try {
        auto guard = fresh();
        inferred = impl->inferDirect(fd);
        if (inferred) result = impl->analyze(fd);
      } catch (const BudgetExceeded &e) {
        skipped = e.what();
      }
      if (!skipped.empty()) {
        // Enrichment is optional: drop it and redo the selected function plainly.
        impl->release(fd);
        inferred = 0;
        auto guard = fresh();
        result = impl->analyze(fd);
      } else if (!inferred) {
        impl->errors.str(baseline_errors);
      }
      OutputBuffer buffer;
      NativeOutput response;
      response.unknown_callees = false;
      {
        auto guard = fresh();
        capax_check();
        std::ostream output(&buffer);
        output.exceptions(std::ios::badbit | std::ios::failbit);
        arch.print->setOutputStream(&output);
        arch.print->setMarkup(false);
        try {
          arch.print->docFunction(fd);
        } catch (const LowlevelError &e) {
          // The engine's own notes (flow errors, unrecovered jump tables) say why.
          arch.print->setOutputStream(&impl->errors);
          std::string notes = "analysis status " + std::to_string(result) + " " + impl->errors.str();
          for (auto it = arch.commentdb->beginComment(fd->getAddress()); it != arch.commentdb->endComment(fd->getAddress()); ++it)
            if ((*it)->getType() & (Comment::warning | Comment::warningheader)) notes += " " + (*it)->getText();
          if (notes.size() > 400) notes.resize(400);
          throw std::runtime_error(notes.empty() ? e.explain : e.explain + " (" + notes + ")");
        }
        arch.print->setOutputStream(&impl->errors);
      }
      response.text = buffer.str();
      for (auto it = arch.commentdb->beginComment(fd->getAddress()); it != arch.commentdb->endComment(fd->getAddress()); ++it)
        if ((*it)->getType() & (Comment::warning | Comment::warningheader)) response.warnings.push_back((*it)->getText());
      if (!impl->errors.str().empty()) response.warnings.push_back(impl->errors.str());
      for (int4 index = 0; index < fd->numCalls(); ++index) {
        const auto *call = fd->getCallSpecs(index);
        if (!call->isInputLocked() || !call->isOutputLocked()) {
          response.unknown_callees = true;
          response.warnings.push_back("Unknown callee prototype: forwarded arguments or return types may be missing. Supply signatures for reliable call reconstruction.");
          break;
        }
      }
      if (!skipped.empty())
        response.warnings.push_back("Callee prototype inference skipped (" + skipped + "); callee prototypes remain unknown.");
      // An applied call fixup is a modeled effect, not a gap in the analysis.
      bool only_informational = true;
      for (const auto &warning : response.warnings)
        if (std::string(warning).find(" replaced with injection: ") == std::string::npos) only_informational = false;
      response.incomplete = result < 0 || !only_informational;
      if (inferred) response.warnings.push_back("Direct callee prototypes inferred from bounded native analysis; validate against machine code.");
      impl->release(fd);
      impl->dropDataSymbols();
      return response;
    } catch (const BudgetExceeded &) {
      arch.print->setOutputStream(&impl->errors);
      impl->release(fd);
      impl->dropDataSymbols();
      throw;
    } catch (...) {
      arch.print->setOutputStream(&impl->errors);
      impl->poisoned = true;
      throw;
    }
    };
    // A function whose flow runs past the instruction limit (the entry stub of a packed file
    // walking into its payload) is still worth showing: Ghidra truncates the flow with a warning.
    try {
      return attempt(false);
    } catch (const LowlevelError &e) {
      if (e.explain.find("maximum allowable instructions") == std::string::npos) throw;
      impl->poisoned = false;
      impl->release(fd);
      impl->dropDataSymbols();
      NativeOutput truncated = attempt(true);
      truncated.incomplete = true;
      truncated.warnings.push_back("Instruction limit reached: some flow is truncated.");
      return truncated;
    }
  });
}
}

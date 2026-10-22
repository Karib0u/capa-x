//! The native boundary. All input slices are copied before native calls return.
//! Sessions own their translator and are deliberately neither Send nor Sync.
#![cfg(feature = "native")]

use std::{marker::PhantomData, rc::Rc};

#[cxx::bridge(namespace = "capax")]
mod ffi {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ValueType {
        Void,
        I32,
        U32,
        I64,
        U64,
        Pointer,
        CharPointer,
        WideCharPointer,
        U32Pointer,
        PointerPointer,
        LuidPointer,
        TokenPrivilegesPointer,
    }
    struct NativeOutput {
        text: String,
        warnings: Vec<String>,
        incomplete: bool,
    }
    unsafe extern "C++" {
        include!("bridge.hh");
        type Session;
        fn set_preserves_rax(self: Pin<&mut Session>, address: u64) -> Result<()>;
        fn set_call_fixup(self: Pin<&mut Session>, address: u64, fixup: &str) -> Result<()>;
        fn apply_prototype(self: Pin<&mut Session>, address: u64, name: &str) -> Result<bool>;
        fn validate_prototype_pack(self: Pin<&mut Session>, max_report: u32) -> Result<String>;
        fn add_tail_call(
            self: Pin<&mut Session>,
            caller: u64,
            site: u64,
            target: u64,
        ) -> Result<()>;
        fn set_signature(
            self: Pin<&mut Session>,
            address: u64,
            result: ValueType,
            parameters: &[ValueType],
        ) -> Result<()>;
        fn new_session() -> Result<UniquePtr<Session>>;
        fn add_section(
            self: Pin<&mut Session>,
            address: u64,
            bytes: &[u8],
            executable: bool,
            readonly: bool,
        ) -> Result<()>;
        fn add_function(
            self: Pin<&mut Session>,
            address: u64,
            name: &str,
            noreturn: bool,
        ) -> Result<()>;
        fn add_import(
            self: Pin<&mut Session>,
            address: u64,
            name: &str,
            noreturn: bool,
        ) -> Result<()>;
        fn decompile(
            self: Pin<&mut Session>,
            address: u64,
            timeout_ms: u32,
            max_instructions: u32,
            max_work: u32,
        ) -> Result<NativeOutput>;
    }
}

pub use cxx::Exception as Error;
pub use ffi::{NativeOutput, ValueType};

pub struct Session {
    inner: cxx::UniquePtr<ffi::Session>,
    _serial: PhantomData<Rc<()>>,
}
impl Session {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            inner: ffi::new_session()?,
            _serial: PhantomData,
        })
    }
    pub fn add_section(
        &mut self,
        address: u64,
        bytes: &[u8],
        executable: bool,
        readonly: bool,
    ) -> Result<(), Error> {
        self.inner
            .pin_mut()
            .add_section(address, bytes, executable, readonly)
    }
    pub fn add_function(&mut self, address: u64, name: &str, noreturn: bool) -> Result<(), Error> {
        self.inner.pin_mut().add_function(address, name, noreturn)
    }
    pub fn add_import(&mut self, address: u64, name: &str, noreturn: bool) -> Result<(), Error> {
        self.inner.pin_mut().add_import(address, name, noreturn)
    }
    /// Discovery metadata only; SLEIGH still translates every instruction.
    pub fn add_tail_call(&mut self, caller: u64, site: u64, target: u64) -> Result<(), Error> {
        self.inner.pin_mut().add_tail_call(caller, site, target)
    }
    pub fn set_signature(
        &mut self,
        address: u64,
        result: ValueType,
        parameters: &[ValueType],
    ) -> Result<(), Error> {
        self.inner
            .pin_mut()
            .set_signature(address, result, parameters)
    }
    /// Apply the archive prototype named `name` to a registered function or import.
    /// Returns false when the packed Ghidra data type archives do not know the name.
    pub fn apply_prototype(&mut self, address: u64, name: &str) -> Result<bool, Error> {
        self.inner.pin_mut().apply_prototype(address, name)
    }
    /// Decode every packed type and prototype; returns a summary with failures.
    #[doc(hidden)]
    pub fn validate_prototype_pack(&mut self, max_report: u32) -> Result<String, Error> {
        self.inner.pin_mut().validate_prototype_pack(max_report)
    }
    /// Explicit ABI fact, used for recognized runtime helpers only.
    pub fn set_preserves_rax(&mut self, address: u64) -> Result<(), Error> {
        self.inner.pin_mut().set_preserves_rax(address)
    }
    /// Replace calls to the function at `address` with one of the compiler
    /// specification's `<callfixup>` p-code snippets (for example
    /// `security_check_cookie`). Unknown fixup names are an error.
    pub fn set_call_fixup(&mut self, address: u64, fixup: &str) -> Result<(), Error> {
        self.inner.pin_mut().set_call_fixup(address, fixup)
    }
    pub fn decompile(
        &mut self,
        address: u64,
        timeout_ms: u32,
        max_instructions: u32,
        max_work: u32,
    ) -> Result<NativeOutput, Error> {
        self.inner
            .pin_mut()
            .decompile(address, timeout_ms, max_instructions, max_work)
    }
}

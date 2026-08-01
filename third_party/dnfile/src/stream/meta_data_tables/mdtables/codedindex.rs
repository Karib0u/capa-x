// The MDTable family passes column-set descriptors as `&Vec<&'static str>`;
// see neighbouring `mdtables/mod.rs` for the rationale.
#![allow(clippy::ptr_arg)]

use crate::{Error, Result};

pub fn clr_coded_index_struct_size(
    tag_bits: usize,
    table_names: &Vec<&'static str>,
    tables_row_counts: &[usize],
) -> usize {
    let mut max_index = 0;
    for name in table_names {
        let table_index = super::table_name_2_index(name).unwrap_or(0);
        let table_rowcnt = tables_row_counts[table_index];
        max_index = std::cmp::max(max_index, table_rowcnt);
    }
    if max_index <= 1 << (16 - tag_bits) {
        2
    } else {
        4
    }
}

// 0.5.0: `Send + Sync` supertraits — see MDTableTrait comment in mod.rs.
pub trait CodedIndex: Send + Sync {
    fn set_row_index(&mut self, value: usize);
    fn set_table(&mut self, value: &'static str);
    fn get_table_name(&self, index: usize) -> Result<&'static str>;
    fn get_tag_bits(&self) -> usize;
    fn table(&self) -> &'static str;
    fn row_index(&self) -> usize;
    fn set(
        &mut self,
        value: &[u8],
        _tables: &std::collections::BTreeMap<usize, super::MetaDataTable>,
    ) -> Result<()> {
        let value = crate::utils::read_usize(value)?;
        let table_name = self.get_table_name(value & ((1 << self.get_tag_bits()) - 1))?;
        self.set_row_index(value >> self.get_tag_bits());
        self.set_table(table_name);
        // We deliberately do NOT validate that `table_name` is populated:
        //
        //   1. A row_index of 0 is a valid "null reference" in ECMA-335
        //      (II.22). Forcing the target table to exist breaks every
        //      coded-index slot that's intentionally null.
        //
        //   2. Many real .NET binaries (especially obfuscated malware) leave
        //      optional tables like `File`, `ExportedType`, `ManifestResource`
        //      unpopulated while still encoding coded-index slots that would
        //      point at them.
        //
        // Consumers that need to materialize the target call
        // `ClrData::resolve_coded_index`, which returns a clean `Err`
        // (`UndefinedMetaDataTableName`) when the row is genuinely missing.
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct SimpleCodedIndex {
    pub tag_bits: usize,
    pub table_names: Vec<&'static str>,
    pub row_index: usize,
    pub table: &'static str,
}

impl SimpleCodedIndex {
    pub fn new(
        table_names: Vec<&'static str>,
        tag_bits: usize,
        value: &[u8],
        tables: &std::collections::BTreeMap<usize, super::MetaDataTable>,
    ) -> Result<SimpleCodedIndex> {
        let mut res = SimpleCodedIndex {
            tag_bits,
            table_names,
            row_index: 0,
            table: "",
        };
        res.set(value, tables)?;
        Ok(res)
    }
}

impl CodedIndex for SimpleCodedIndex {
    fn table(&self) -> &'static str {
        self.table
    }
    fn row_index(&self) -> usize {
        self.row_index
    }
    fn set_row_index(&mut self, value: usize) {
        self.row_index = value;
    }
    fn set_table(&mut self, value: &'static str) {
        self.table = value;
    }
    fn get_table_name(&self, index: usize) -> Result<&'static str> {
        // ADR 0003 (capa-x): upstream indexed `table_names[index]` directly
        // despite the tag bits coming from untrusted file bytes, panicking on
        // out-of-range values. Bounds-check instead of trusting the tag.
        self.table_names
            .get(index)
            .copied()
            .ok_or(Error::UndefinedMetaDataTableIndex(index as u32))
    }
    fn get_tag_bits(&self) -> usize {
        self.tag_bits
    }
}

#[derive(Debug, Clone)]
pub struct ResolutionScope {
    pub tag_bits: usize,
    pub table_names: Vec<&'static str>,
    pub row_index: usize,
    pub table: &'static str,
}

impl CodedIndex for ResolutionScope {
    fn table(&self) -> &'static str {
        self.table
    }
    fn row_index(&self) -> usize {
        self.row_index
    }
    fn set_row_index(&mut self, value: usize) {
        self.row_index = value;
    }
    fn set_table(&mut self, value: &'static str) {
        self.table = value;
    }
    fn get_table_name(&self, index: usize) -> Result<&'static str> {
        // ADR 0003 (capa-x): upstream indexed `table_names[index]` directly
        // despite the tag bits coming from untrusted file bytes, panicking on
        // out-of-range values. Bounds-check instead of trusting the tag.
        self.table_names
            .get(index)
            .copied()
            .ok_or(Error::UndefinedMetaDataTableIndex(index as u32))
    }
    fn get_tag_bits(&self) -> usize {
        self.tag_bits
    }
}

impl Default for ResolutionScope {
    fn default() -> Self {
        Self {
            tag_bits: 2,
            table_names: vec!["Module", "ModuleRef", "AssemblyRef", "TypeRef"],
            row_index: 0,
            table: "",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TypeDefOrRef {
    pub tag_bits: usize,
    pub table_names: Vec<&'static str>,
    pub row_index: usize,
    pub table: &'static str,
}

impl CodedIndex for TypeDefOrRef {
    fn table(&self) -> &'static str {
        self.table
    }
    fn row_index(&self) -> usize {
        self.row_index
    }
    fn set_row_index(&mut self, value: usize) {
        self.row_index = value;
    }
    fn set_table(&mut self, value: &'static str) {
        self.table = value;
    }
    fn get_table_name(&self, index: usize) -> Result<&'static str> {
        // ADR 0003 (capa-x): upstream indexed `table_names[index]` directly
        // despite the tag bits coming from untrusted file bytes, panicking on
        // out-of-range values. Bounds-check instead of trusting the tag.
        self.table_names
            .get(index)
            .copied()
            .ok_or(Error::UndefinedMetaDataTableIndex(index as u32))
    }
    fn get_tag_bits(&self) -> usize {
        self.tag_bits
    }
}

impl Default for TypeDefOrRef {
    fn default() -> Self {
        Self {
            tag_bits: 2,
            table_names: vec!["TypeDef", "TypeRef", "TypeSpec"],
            row_index: 0,
            table: "",
        }
    }
}

#[derive(Debug, Clone)]
pub struct MemberRefParent {
    pub tag_bits: usize,
    pub table_names: Vec<&'static str>,
    pub row_index: usize,
    pub table: &'static str,
}

impl CodedIndex for MemberRefParent {
    fn table(&self) -> &'static str {
        self.table
    }
    fn row_index(&self) -> usize {
        self.row_index
    }
    fn set_row_index(&mut self, value: usize) {
        self.row_index = value;
    }
    fn set_table(&mut self, value: &'static str) {
        self.table = value;
    }
    fn get_table_name(&self, index: usize) -> Result<&'static str> {
        // ADR 0003 (capa-x): upstream indexed `table_names[index]` directly
        // despite the tag bits coming from untrusted file bytes, panicking on
        // out-of-range values. Bounds-check instead of trusting the tag.
        self.table_names
            .get(index)
            .copied()
            .ok_or(Error::UndefinedMetaDataTableIndex(index as u32))
    }
    fn get_tag_bits(&self) -> usize {
        self.tag_bits
    }
}

impl Default for MemberRefParent {
    fn default() -> Self {
        Self {
            tag_bits: 3,
            table_names: vec!["TypeDef", "TypeRef", "ModuleRef", "MethodDef", "TypeSpec"],
            row_index: 0,
            table: "",
        }
    }
}

#[derive(Debug, Clone)]
pub struct HasConstant {
    pub tag_bits: usize,
    pub table_names: Vec<&'static str>,
    pub row_index: usize,
    pub table: &'static str,
}

impl CodedIndex for HasConstant {
    fn table(&self) -> &'static str {
        self.table
    }
    fn row_index(&self) -> usize {
        self.row_index
    }
    fn set_row_index(&mut self, value: usize) {
        self.row_index = value;
    }
    fn set_table(&mut self, value: &'static str) {
        self.table = value;
    }
    fn get_table_name(&self, index: usize) -> Result<&'static str> {
        // ADR 0003 (capa-x): upstream indexed `table_names[index]` directly
        // despite the tag bits coming from untrusted file bytes, panicking on
        // out-of-range values. Bounds-check instead of trusting the tag.
        self.table_names
            .get(index)
            .copied()
            .ok_or(Error::UndefinedMetaDataTableIndex(index as u32))
    }
    fn get_tag_bits(&self) -> usize {
        self.tag_bits
    }
}

impl Default for HasConstant {
    fn default() -> Self {
        Self {
            tag_bits: 2,
            table_names: vec!["Field", "Param", "Property"],
            row_index: 0,
            table: "",
        }
    }
}

#[derive(Debug, Clone)]
pub struct HasCustomAttribute {
    pub tag_bits: usize,
    pub table_names: Vec<&'static str>,
    pub row_index: usize,
    pub table: &'static str,
}

impl CodedIndex for HasCustomAttribute {
    fn table(&self) -> &'static str {
        self.table
    }
    fn row_index(&self) -> usize {
        self.row_index
    }
    fn set_row_index(&mut self, value: usize) {
        self.row_index = value;
    }
    fn set_table(&mut self, value: &'static str) {
        self.table = value;
    }
    fn get_table_name(&self, index: usize) -> Result<&'static str> {
        // ADR 0003 (capa-x): upstream indexed `table_names[index]` directly
        // despite the tag bits coming from untrusted file bytes, panicking on
        // out-of-range values. Bounds-check instead of trusting the tag.
        self.table_names
            .get(index)
            .copied()
            .ok_or(Error::UndefinedMetaDataTableIndex(index as u32))
    }
    fn get_tag_bits(&self) -> usize {
        self.tag_bits
    }
}

impl Default for HasCustomAttribute {
    fn default() -> Self {
        Self {
            tag_bits: 5,
            table_names: vec![
                "MethodDef",
                "Field",
                "TypeRef",
                "TypeDef",
                "Param",
                "InterfaceImpl",
                "MemberRef",
                "Module",
                "DeclSecurity",
                "Property",
                "Event",
                "StandAloneSig",
                "ModuleRef",
                "TypeSpec",
                "Assembly",
                "AssemblyRef",
                "File",
                "ExportedType",
                "ManifestResource",
                "GenericParam",
                "GenericParamConstraint",
            ],
            row_index: 0,
            table: "",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CustomAttributeType {
    pub tag_bits: usize,
    pub table_names: Vec<&'static str>,
    pub row_index: usize,
    pub table: &'static str,
}

impl CodedIndex for CustomAttributeType {
    fn table(&self) -> &'static str {
        self.table
    }
    fn row_index(&self) -> usize {
        self.row_index
    }
    fn set_row_index(&mut self, value: usize) {
        self.row_index = value;
    }
    fn set_table(&mut self, value: &'static str) {
        self.table = value;
    }
    fn get_table_name(&self, index: usize) -> Result<&'static str> {
        // ADR 0003 (capa-x): upstream indexed `table_names[index]` directly
        // despite the tag bits coming from untrusted file bytes, panicking on
        // out-of-range values. Bounds-check instead of trusting the tag.
        self.table_names
            .get(index)
            .copied()
            .ok_or(Error::UndefinedMetaDataTableIndex(index as u32))
    }
    fn get_tag_bits(&self) -> usize {
        self.tag_bits
    }
}

impl Default for CustomAttributeType {
    fn default() -> Self {
        Self {
            tag_bits: 3,
            table_names: vec!["Unused", "Unused", "MethodDef", "MemberRef", "Unused"],
            row_index: 0,
            table: "",
        }
    }
}

#[derive(Debug, Clone)]
pub struct HasFieldMarshall {
    pub tag_bits: usize,
    pub table_names: Vec<&'static str>,
    pub row_index: usize,
    pub table: &'static str,
}

impl CodedIndex for HasFieldMarshall {
    fn table(&self) -> &'static str {
        self.table
    }
    fn row_index(&self) -> usize {
        self.row_index
    }
    fn set_row_index(&mut self, value: usize) {
        self.row_index = value;
    }
    fn set_table(&mut self, value: &'static str) {
        self.table = value;
    }
    fn get_table_name(&self, index: usize) -> Result<&'static str> {
        // ADR 0003 (capa-x): upstream indexed `table_names[index]` directly
        // despite the tag bits coming from untrusted file bytes, panicking on
        // out-of-range values. Bounds-check instead of trusting the tag.
        self.table_names
            .get(index)
            .copied()
            .ok_or(Error::UndefinedMetaDataTableIndex(index as u32))
    }
    fn get_tag_bits(&self) -> usize {
        self.tag_bits
    }
}

impl Default for HasFieldMarshall {
    fn default() -> Self {
        Self {
            tag_bits: 1,
            table_names: vec!["Field", "Param"],
            row_index: 0,
            table: "",
        }
    }
}

#[derive(Debug, Clone)]
pub struct HasDeclSecurity {
    pub tag_bits: usize,
    pub table_names: Vec<&'static str>,
    pub row_index: usize,
    pub table: &'static str,
}

impl CodedIndex for HasDeclSecurity {
    fn table(&self) -> &'static str {
        self.table
    }
    fn row_index(&self) -> usize {
        self.row_index
    }
    fn set_row_index(&mut self, value: usize) {
        self.row_index = value;
    }
    fn set_table(&mut self, value: &'static str) {
        self.table = value;
    }
    fn get_table_name(&self, index: usize) -> Result<&'static str> {
        // ADR 0003 (capa-x): upstream indexed `table_names[index]` directly
        // despite the tag bits coming from untrusted file bytes, panicking on
        // out-of-range values. Bounds-check instead of trusting the tag.
        self.table_names
            .get(index)
            .copied()
            .ok_or(Error::UndefinedMetaDataTableIndex(index as u32))
    }
    fn get_tag_bits(&self) -> usize {
        self.tag_bits
    }
}

impl Default for HasDeclSecurity {
    fn default() -> Self {
        Self {
            tag_bits: 2,
            table_names: vec!["TypeDef", "MethodDef", "Assembly"],
            row_index: 0,
            table: "",
        }
    }
}

#[derive(Debug, Clone)]
pub struct HasSemantics {
    pub tag_bits: usize,
    pub table_names: Vec<&'static str>,
    pub row_index: usize,
    pub table: &'static str,
}

impl CodedIndex for HasSemantics {
    fn table(&self) -> &'static str {
        self.table
    }
    fn row_index(&self) -> usize {
        self.row_index
    }
    fn set_row_index(&mut self, value: usize) {
        self.row_index = value;
    }
    fn set_table(&mut self, value: &'static str) {
        self.table = value;
    }
    fn get_table_name(&self, index: usize) -> Result<&'static str> {
        // ADR 0003 (capa-x): upstream indexed `table_names[index]` directly
        // despite the tag bits coming from untrusted file bytes, panicking on
        // out-of-range values. Bounds-check instead of trusting the tag.
        self.table_names
            .get(index)
            .copied()
            .ok_or(Error::UndefinedMetaDataTableIndex(index as u32))
    }
    fn get_tag_bits(&self) -> usize {
        self.tag_bits
    }
}

impl Default for HasSemantics {
    fn default() -> Self {
        Self {
            tag_bits: 1,
            table_names: vec!["Event", "Property"],
            row_index: 0,
            table: "",
        }
    }
}

#[derive(Debug, Clone)]
pub struct MethodDefOrRef {
    pub tag_bits: usize,
    pub table_names: Vec<&'static str>,
    pub row_index: usize,
    pub table: &'static str,
}

impl CodedIndex for MethodDefOrRef {
    fn table(&self) -> &'static str {
        self.table
    }
    fn row_index(&self) -> usize {
        self.row_index
    }
    fn set_row_index(&mut self, value: usize) {
        self.row_index = value;
    }
    fn set_table(&mut self, value: &'static str) {
        self.table = value;
    }
    fn get_table_name(&self, index: usize) -> Result<&'static str> {
        // ADR 0003 (capa-x): upstream indexed `table_names[index]` directly
        // despite the tag bits coming from untrusted file bytes, panicking on
        // out-of-range values. Bounds-check instead of trusting the tag.
        self.table_names
            .get(index)
            .copied()
            .ok_or(Error::UndefinedMetaDataTableIndex(index as u32))
    }
    fn get_tag_bits(&self) -> usize {
        self.tag_bits
    }
}

impl Default for MethodDefOrRef {
    fn default() -> Self {
        Self {
            tag_bits: 1,
            table_names: vec!["MethodDef", "MemberRef"],
            row_index: 0,
            table: "",
        }
    }
}

#[derive(Debug, Clone)]
pub struct MemberForwarded {
    pub tag_bits: usize,
    pub table_names: Vec<&'static str>,
    pub row_index: usize,
    pub table: &'static str,
}

impl CodedIndex for MemberForwarded {
    fn table(&self) -> &'static str {
        self.table
    }
    fn row_index(&self) -> usize {
        self.row_index
    }
    fn set_row_index(&mut self, value: usize) {
        self.row_index = value;
    }
    fn set_table(&mut self, value: &'static str) {
        self.table = value;
    }
    fn get_table_name(&self, index: usize) -> Result<&'static str> {
        // ADR 0003 (capa-x): upstream indexed `table_names[index]` directly
        // despite the tag bits coming from untrusted file bytes, panicking on
        // out-of-range values. Bounds-check instead of trusting the tag.
        self.table_names
            .get(index)
            .copied()
            .ok_or(Error::UndefinedMetaDataTableIndex(index as u32))
    }
    fn get_tag_bits(&self) -> usize {
        self.tag_bits
    }
}

impl Default for MemberForwarded {
    fn default() -> Self {
        Self {
            tag_bits: 1,
            table_names: vec!["Field", "MethodDef"],
            row_index: 0,
            table: "",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Implementation {
    pub tag_bits: usize,
    pub table_names: Vec<&'static str>,
    pub row_index: usize,
    pub table: &'static str,
}

impl CodedIndex for Implementation {
    fn table(&self) -> &'static str {
        self.table
    }
    fn row_index(&self) -> usize {
        self.row_index
    }
    fn set_row_index(&mut self, value: usize) {
        self.row_index = value;
    }
    fn set_table(&mut self, value: &'static str) {
        self.table = value;
    }
    fn get_table_name(&self, index: usize) -> Result<&'static str> {
        // ADR 0003 (capa-x): upstream indexed `table_names[index]` directly
        // despite the tag bits coming from untrusted file bytes, panicking on
        // out-of-range values. Bounds-check instead of trusting the tag.
        self.table_names
            .get(index)
            .copied()
            .ok_or(Error::UndefinedMetaDataTableIndex(index as u32))
    }
    fn get_tag_bits(&self) -> usize {
        self.tag_bits
    }
}

impl Default for Implementation {
    fn default() -> Self {
        Self {
            tag_bits: 2,
            table_names: vec!["File", "AssemblyRef", "ExportedType"],
            row_index: 0,
            table: "File",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TypeOrMethodDef {
    pub tag_bits: usize,
    pub table_names: Vec<&'static str>,
    pub row_index: usize,
    pub table: &'static str,
}

impl CodedIndex for TypeOrMethodDef {
    fn table(&self) -> &'static str {
        self.table
    }
    fn row_index(&self) -> usize {
        self.row_index
    }
    fn set_row_index(&mut self, value: usize) {
        self.row_index = value;
    }
    fn set_table(&mut self, value: &'static str) {
        self.table = value;
    }
    fn get_table_name(&self, index: usize) -> Result<&'static str> {
        // ADR 0003 (capa-x): upstream indexed `table_names[index]` directly
        // despite the tag bits coming from untrusted file bytes, panicking on
        // out-of-range values. Bounds-check instead of trusting the tag.
        self.table_names
            .get(index)
            .copied()
            .ok_or(Error::UndefinedMetaDataTableIndex(index as u32))
    }
    fn get_tag_bits(&self) -> usize {
        self.tag_bits
    }
}

impl Default for TypeOrMethodDef {
    fn default() -> Self {
        Self {
            tag_bits: 1,
            table_names: vec!["TypeDef", "MethodDef"],
            row_index: 0,
            table: "",
        }
    }
}

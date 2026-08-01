#![allow(clippy::too_many_arguments)]
// The MDTable family of types passes column-set descriptors as `&Vec<&'static str>`
// down to `clr_coded_index_struct_size` — changing the helper to `&[&'static str]`
// would be a public-API break for that helper and ripple through every Default impl.
// The cost is purely stylistic, so silence the lint at module scope.
#![allow(clippy::useless_vec, clippy::ptr_arg)]
// The MDTableRowTrait passes heap references as `&Option<&ClrStream>`. Refactoring
// to `Option<&ClrStream>` is a trait-signature break.
#![allow(clippy::ref_option)]
// Several private helpers take `&u32` / `&usize` for historical consistency.
#![allow(clippy::trivially_copy_pass_by_ref)]
// `if let Some(s) = X { s } else { return Err(..); }` appears in dozens of
// row parsers. Mechanical `let-else` rewrites are tracked separately; allow
// for now to keep the diff focused on perf fixes.
#![allow(clippy::manual_let_else)]

use crate::{Result, error::Error};
use serde::ser::{Serialize, SerializeSeq};

pub mod codedindex;
use codedindex::CodedIndex;
pub mod enums;

// 0.5.0: `Send + Sync` supertraits added so `Box<dyn MDTableTrait>`
// (and the `DnPe<'_>` graph that contains it) can cross thread
// boundaries. Required by downstream consumers (capa-rs 0.4.2)
// that rayon-parallelise function-level analysis. All MDTableTrait
// impls in dnfile-rs are naturally `Send + Sync` (plain-data
// structs of `Vec`/`String`/primitives) so this is non-breaking
// for the in-tree impls — only downstream impls of MDTableTrait
// on non-thread-safe types need to add the bounds.
pub trait MDTableTrait: std::fmt::Debug + MDTableTraitClone + Send + Sync {
    fn set_data(&mut self, data: &[u8]) -> Result<()>;
    fn row_size(&self) -> usize;
    fn get_row(&self, i: usize) -> Result<&dyn MDTableRowTraitT>;
    fn get_mut_row(&mut self, i: usize) -> Result<&mut dyn MDTableRowTraitT>;
    fn row_count(&self) -> usize;
    fn name(&self) -> &str;
}

impl Serialize for dyn MDTableTrait {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let table_serializer = serializer.serialize_seq(Some(self.row_count()))?;
        // for _i in 0..self.row_count() {
        //            let s = self.get_row(i).unwrap().get_row();
        //            table_serializer.serialize_element(s)?;
        // }
        table_serializer.end()
    }
}

// 0.5.0: `Send + Sync` supertraits — see MDTableTrait comment.
pub trait MDTableTraitClone: Send + Sync {
    fn clone_box(&self) -> Box<dyn MDTableTrait>;
}

impl<T: 'static + MDTableTrait + Clone> MDTableTraitClone for T {
    fn clone_box(&self) -> Box<dyn MDTableTrait> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn MDTableTrait> {
    fn clone(&self) -> Box<dyn MDTableTrait> {
        self.clone_box()
    }
}

#[derive(Debug, Clone, Default)]
pub struct MDTable<T>
where
    T: MDTableRowTrait + std::fmt::Debug + Default + Clone,
{
    name: String,
    table: Vec<MDTableRow<T>>,
}

impl<T> MDTable<T>
where
    T: MDTableRowTrait + std::fmt::Debug + Default + Clone,
{
    pub fn new(
        name: &str,
        num_rows: &usize,
        strings_offset_size: usize,
        guids_offset_size: usize,
        blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> Result<MDTable<T>> {
        // Sanity cap on row allocations. ECMA-335 encodes row counts as
        // u32, so a crafted binary can request up to ~4 G rows; each
        // MDTableRow<T> is on the order of 100 bytes, which would pin the
        // process for hundreds of GB. Bound by both an absolute hard cap
        // (8 M rows is far above anything seen in the wild — real .NET
        // binaries top out around 1 M MethodDef rows) and the per-row size.
        const MAX_ROWS: usize = 8 * 1024 * 1024;
        let n = *num_rows;
        if n > MAX_ROWS {
            return Err(Error::NotEnoughData(n, MAX_ROWS));
        }
        Ok(MDTable::<T> {
            name: name.to_string(),
            table: vec![
                MDTableRow::<T>::new(
                    strings_offset_size,
                    guids_offset_size,
                    blobs_offset_size,
                    tables_row_counts
                );
                n
            ],
        })
    }
}

impl<T> MDTableTrait for MDTable<T>
where
    T: 'static + MDTableRowTrait + std::fmt::Debug + Default + Clone,
{
    fn set_data(&mut self, data: &[u8]) -> Result<()> {
        if data.len() < self.table.len() * self.row_size() {
            return Err(Error::NotEnoughData(
                data.len(),
                self.table.len() * self.row_size(),
            ));
        }
        let mut curr_offset = 0;
        let row_size = self.row_size();
        for r in &mut self.table {
            if data.len() - curr_offset < row_size {
                return Err(Error::NotEnoughData(row_size, data.len() - curr_offset));
            }
            r.set_data(&data[curr_offset..curr_offset + row_size])?;
            curr_offset += row_size;
        }
        Ok(())
    }

    fn row_size(&self) -> usize {
        if self.table.is_empty() {
            0
        } else {
            self.table[0].size()
        }
    }

    fn get_row(&self, i: usize) -> Result<&dyn MDTableRowTraitT> {
        if i < self.row_count() {
            Ok(&self.table[i])
        } else {
            Err(Error::RowIndexOutOfBound(i, self.row_count()))
        }
    }

    fn get_mut_row(&mut self, i: usize) -> Result<&mut dyn MDTableRowTraitT> {
        if i < self.row_count() {
            Ok(&mut self.table[i])
        } else {
            Err(Error::RowIndexOutOfBound(i, self.row_count()))
        }
    }

    fn row_count(&self) -> usize {
        self.table.len()
    }

    fn name(&self) -> &str {
        &self.name
    }
}

// 0.5.0: `Send + Sync` supertraits — see MDTableTrait comment.
pub trait MDTableRowTrait: std::fmt::Debug + Send + Sync {
    fn size(
        &self,
        str_offset_size: usize,
        guids_offset_size: usize,
        blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize;
    fn parse(
        &mut self,
        data: &[u8],
        str_offset_size: usize,
        guids_offset_size: usize,
        blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        next_row: Option<&dyn MDTableRowTrait>,
        strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()>;
    fn parse2(
        &mut self,
        _data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        _tables_row_counts: &[usize],
        _tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        Ok(())
    }
    fn as_any(&self) -> &dyn std::any::Any;
}

// 0.5.0: `Send + Sync` supertraits — see MDTableTrait comment.
pub trait MDTableRowTraitT: Send + Sync {
    fn size(&self) -> usize;
    fn parse(
        &mut self,
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        next_row: Option<&dyn MDTableRowTraitT>,
        strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()>;
    fn parse2(
        &mut self,
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        next_row: Option<&dyn MDTableRowTraitT>,
        strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()>;
    fn get_row(&self) -> &dyn MDTableRowTrait;
    fn get_mut_row(&mut self) -> &mut dyn MDTableRowTrait;
}

#[derive(Debug, Clone)]
pub struct MDTableRow<T>
where
    T: MDTableRowTrait,
{
    str_offset_size: usize,
    guids_offset_size: usize,
    blobs_offset_size: usize,
    tables_row_counts: Vec<usize>,
    row: T,
    pub data: Vec<u8>,
}

impl<T> MDTableRowTraitT for MDTableRow<T>
where
    T: MDTableRowTrait,
{
    fn size(&self) -> usize {
        self.row.size(
            self.str_offset_size,
            self.guids_offset_size,
            self.blobs_offset_size,
            &self.tables_row_counts,
        )
    }
    fn parse(
        &mut self,
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        next_row: Option<&dyn MDTableRowTraitT>,
        strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let nn = next_row.map(|n| n.get_row());
        self.row.parse(
            &self.data,
            self.str_offset_size,
            self.guids_offset_size,
            self.blobs_offset_size,
            &self.tables_row_counts,
            tables,
            nn,
            strings_heap,
            blobss_heap,
            guids_heap,
        )
    }

    fn parse2(
        &mut self,
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        next_row: Option<&dyn MDTableRowTraitT>,
        strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let nn = next_row.map(|n| n.get_row());
        self.row.parse2(
            &self.data,
            self.str_offset_size,
            self.guids_offset_size,
            self.blobs_offset_size,
            &self.tables_row_counts,
            tables,
            nn,
            strings_heap,
            blobss_heap,
            guids_heap,
        )
    }

    fn get_row(&self) -> &dyn MDTableRowTrait {
        &self.row
    }
    fn get_mut_row(&mut self) -> &mut dyn MDTableRowTrait {
        &mut self.row
    }
}

impl<T> MDTableRow<T>
where
    T: MDTableRowTrait + Default,
{
    pub fn new(
        str_offset_size: usize,
        guids_offset_size: usize,
        blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> MDTableRow<T> {
        MDTableRow {
            str_offset_size,
            guids_offset_size,
            blobs_offset_size,
            tables_row_counts: tables_row_counts.to_vec(),
            row: T::default(),
            data: vec![],
        }
    }

    pub fn set_data(&mut self, data: &[u8]) -> Result<()> {
        self.data = data.to_owned();
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct Module {
    pub generation: u16,
    pub name: String,
    pub mvid: uuid::Uuid,
    pub enc_id: uuid::Uuid,
    pub enc_base_id: uuid::Uuid,
}

impl MDTableRowTrait for Module {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        str_offset_size: usize,
        guids_offset_size: usize,
        _blobs_offset_size: usize,
        _tables_row_counts: &[usize],
    ) -> usize {
        2 + str_offset_size + 3 * guids_offset_size
    }

    fn parse(
        &mut self,
        data: &[u8],
        str_offset_size: usize,
        guids_offset_size: usize,
        _blobs_offset_size: usize,
        _tables_row_counts: &[usize],
        _tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobs_heap: &Option<&crate::stream::ClrStream<'_>>,
        guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = 2;
        let s2 = str_offset_size;
        let s3 = guids_offset_size;
        let s4 = guids_offset_size;
        let s5 = guids_offset_size;
        let strings_heap = if let Some(s) = strings_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("string"));
        };
        let guids_heap = if let Some(s) = guids_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("blob"));
        };
        self.generation = crate::utils::read_usize(&data[0..s1])? as u16;
        self.name = strings_heap.get_string(&data[s1..s1 + s2])?;
        self.mvid = guids_heap.get_guid(&data[s1 + s2..s1 + s2 + s3])?;
        self.enc_id = guids_heap.get_guid(&data[s1 + s2 + s3..s1 + s2 + s3 + s4])?;
        self.enc_base_id = guids_heap.get_guid(&data[s1 + s2 + s3 + s4..s1 + s2 + s3 + s4 + s5])?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct TypeRef {
    pub resolution_scope: codedindex::ResolutionScope,
    pub type_name: String,
    pub type_namespace: String,
}

impl MDTableRowTrait for TypeRef {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        codedindex::clr_coded_index_struct_size(
            self.resolution_scope.tag_bits,
            &self.resolution_scope.table_names,
            tables_row_counts,
        ) + 2 * str_offset_size
    }

    fn parse(
        &mut self,
        data: &[u8],
        str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let first_size = codedindex::clr_coded_index_struct_size(
            self.resolution_scope.tag_bits,
            &self.resolution_scope.table_names,
            tables_row_counts,
        );
        let strings_heap = if let Some(s) = strings_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("string"));
        };
        self.resolution_scope.set(&data[0..first_size], tables)?;
        self.type_name =
            strings_heap.get_string(&data[first_size..first_size + str_offset_size])?;
        self.type_namespace = strings_heap
            .get_string(&data[first_size + str_offset_size..first_size + 2 * str_offset_size])?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct TypeDef {
    flags: enums::ClrTypeAttr,
    pub type_name: String,
    pub type_namespace: String,
    extends: codedindex::TypeDefOrRef,
    pub field_list: Vec<codedindex::SimpleCodedIndex>, //Field
    pub method_list: Vec<codedindex::SimpleCodedIndex>, //MethodDef
}

impl MDTableRowTrait for TypeDef {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        4 + 2 * str_offset_size
            + codedindex::clr_coded_index_struct_size(
                self.extends.tag_bits,
                &self.extends.table_names,
                tables_row_counts,
            )
            + codedindex::clr_coded_index_struct_size(0, &vec!["Field"], tables_row_counts)
            + codedindex::clr_coded_index_struct_size(0, &vec!["MethodDef"], tables_row_counts)
    }

    fn parse(
        &mut self,
        data: &[u8],
        str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobs_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = 4;
        let s2 = s1 + str_offset_size;
        let s3 = s2 + str_offset_size;
        let s4 = s3
            + codedindex::clr_coded_index_struct_size(
                self.extends.tag_bits,
                &self.extends.table_names,
                tables_row_counts,
            );
        let s5 = s4 + codedindex::clr_coded_index_struct_size(0, &vec!["Field"], tables_row_counts);
        let s6 =
            s5 + codedindex::clr_coded_index_struct_size(0, &vec!["MethodDef"], tables_row_counts);
        let strings_heap = if let Some(s) = strings_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("string"));
        };
        self.flags.set(&data[0..s1])?;
        self.type_name = strings_heap.get_string(&data[s1..s2])?;
        self.type_namespace = strings_heap.get_string(&data[s2..s3])?;
        self.extends.set(&data[s3..s4], tables)?;
        self.field_list = vec![codedindex::SimpleCodedIndex::new(
            vec!["Field"],
            0,
            &data[s4..s5],
            tables,
        )?];
        self.method_list = vec![codedindex::SimpleCodedIndex::new(
            vec!["MethodDef"],
            0,
            &data[s5..s6],
            tables,
        )?];
        Ok(())
    }

    fn parse2(
        &mut self,
        _data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        _tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobs_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        // capa-x patch (see third_party/dnfile/PATCH.md): a `Field`/
        // `MethodDef` table absent from `tables` means the file's metadata
        // legitimately has zero rows in it (ECMA-335's `mask_valid` bitmask
        // simply omits empty tables) -- upstream treated that as an error,
        // which made any TypeDef with no fields or no methods (both common:
        // a static-only or field-only type) fail to parse at all.
        let field_row_count = tables
            .get(&table_name_2_index("Field")?)
            .map(|t| t.row_count())
            .unwrap_or(0);
        let method_def_row_count = tables
            .get(&table_name_2_index("MethodDef")?)
            .map(|t| t.row_count())
            .unwrap_or(0);
        let (first_field_index, first_method_index) = (
            self.field_list[0].row_index(),
            self.method_list[0].row_index(),
        );
        // capa-x patch (see third_party/dnfile/PATCH.md): pinned Python
        // `dnfile` (`base.py _parse_struct_lists`) computes an *inclusive*
        // `run_end_index`, consumed as `range(start, end + 1)`:
        //   end = min(next_row_start - 1, max_row)   if there is a next row
        //   end = max_row                            otherwise
        // The loop below is an *exclusive* Rust range, so what it needs one
        // line down is `end + 1`, not `end`, in both cases:
        //   min(next_row_start - 1, max_row) + 1 == min(next_row_start, max_row + 1)
        //   max_row + 1
        // Using `min(row_count, next_row_start)` (no `+ 1` on either side, as
        // upstream had it) silently drops the table's true last row from a
        // `TypeDef`'s list whenever that row is the last real row *and*
        // either there's no next row, or the next `TypeDef` owns nothing
        // more (its own start already points past the end).
        let (last_field_index, last_method_index) = if let Some(nr) = next_row {
            let nnr = nr
                .as_any()
                .downcast_ref::<TypeDef>()
                .ok_or(Error::IncorrectCastTo("TypeDef", file!(), line!()))?;
            (
                std::cmp::min(field_row_count + 1, nnr.field_list[0].row_index()),
                std::cmp::min(method_def_row_count + 1, nnr.method_list[0].row_index()),
            )
        } else {
            (field_row_count + 1, method_def_row_count + 1)
        };
        // With `last_*_index` now always "true inclusive end + 1" (both
        // branches above), "this `TypeDef` owns at least one row" is exactly
        // `first < last` -- no separate `==` case is reachable: a row that's
        // genuinely this type's alone (including the table's true last row)
        // always has `first < last` already, via the `+ 1`. Upstream's extra
        // `first == last == row_count` clause here was papering over the
        // pre-fix asymmetry between the two branches above and, post-fix, its
        // pre-populated `field_list`/`method_list[0]` (set unconditionally in
        // `parse()`, before either table exists) would spuriously survive
        // into rows that legitimately own zero fields/methods whenever a run
        // of consecutive `TypeDef`s all share the same recorded start.
        if first_field_index < last_field_index {
            for i in self.field_list[0].row_index() + 1..last_field_index {
                self.field_list.push(codedindex::SimpleCodedIndex::new(
                    vec!["Field"],
                    0,
                    &i.to_le_bytes(),
                    tables,
                )?);
            }
        } else {
            self.field_list.clear();
        }
        if first_method_index < last_method_index {
            for i in self.method_list[0].row_index() + 1..last_method_index {
                self.method_list.push(codedindex::SimpleCodedIndex::new(
                    vec!["MethodDef"],
                    0,
                    &i.to_le_bytes(),
                    tables,
                )?);
            }
        } else {
            self.method_list.clear();
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct FieldPtr {
    field: codedindex::SimpleCodedIndex, //Field
}

impl MDTableRowTrait for FieldPtr {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        codedindex::clr_coded_index_struct_size(0, &vec!["Field"], tables_row_counts)
    }

    fn parse(
        &mut self,
        data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = codedindex::clr_coded_index_struct_size(0, &vec!["Field"], tables_row_counts);
        self.field = codedindex::SimpleCodedIndex::new(vec!["Field"], 0, &data[0..s1], tables)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct Field {
    flags: Vec<enums::ClrFieldAttr>,
    pub name: String,
    signature: Vec<u8>,
}

impl MDTableRowTrait for Field {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        _tables_row_counts: &[usize],
    ) -> usize {
        2 + str_offset_size + blobs_offset_size
    }

    fn parse(
        &mut self,
        data: &[u8],
        str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        _tables_row_counts: &[usize],
        _tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        blobs_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = 2;
        let s2 = s1 + str_offset_size;
        let s3 = s2 + blobs_offset_size;
        let strings_heap = if let Some(s) = strings_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("string"));
        };
        let blobs_heap = if let Some(s) = blobs_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("blob"));
        };
        self.flags = enums::ClrFieldAttr::new(crate::utils::read_usize(&data[0..s1])?);
        self.name = strings_heap.get_string(&data[s1..s2])?;
        self.signature = blobs_heap.get_blob(&data[s2..s3])?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct MethodPtr {
    field: codedindex::SimpleCodedIndex, //MethodDef
}

impl MDTableRowTrait for MethodPtr {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        codedindex::clr_coded_index_struct_size(0, &vec!["MethodDef"], tables_row_counts)
    }

    fn parse(
        &mut self,
        data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = codedindex::clr_coded_index_struct_size(0, &vec!["MethodDef"], tables_row_counts);
        self.field = codedindex::SimpleCodedIndex::new(vec!["MethodDef"], 0, &data[0..s1], tables)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct MethodDef {
    pub rva: u32,
    pub impl_flags: Vec<enums::ClrMethodImpl>,
    pub flags: Vec<enums::ClrMethodAttr>,
    pub name: String,
    signature: Vec<u8>,
    param_list: Vec<Param>,
}

impl MDTableRowTrait for MethodDef {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        4 + 2
            + 2
            + str_offset_size
            + blobs_offset_size
            + codedindex::clr_coded_index_struct_size(0, &vec!["Param"], tables_row_counts)
    }

    fn parse(
        &mut self,
        data: &[u8],
        str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        tables_row_counts: &[usize],
        _tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        blobs_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = 4;
        let s2 = s1 + 2;
        let s3 = s2 + 2;
        let s4 = s3 + str_offset_size;
        let s5 = s4 + blobs_offset_size;
        let _s6 =
            s5 + codedindex::clr_coded_index_struct_size(0, &vec!["Param"], tables_row_counts);
        let strings_heap = if let Some(s) = strings_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("string"));
        };
        let blobs_heap = if let Some(s) = blobs_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("blob"));
        };
        self.rva = crate::utils::read_usize(&data[0..s1])? as u32;
        self.impl_flags = enums::ClrMethodImpl::new(crate::utils::read_usize(&data[s1..s2])?);
        self.flags = enums::ClrMethodAttr::new(crate::utils::read_usize(&data[s2..s3])?);
        self.name = strings_heap.get_string(&data[s3..s4])?;
        self.signature = blobs_heap.get_blob(&data[s4..s5])?;
        self.param_list = vec![];
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct ParamPtr {
    field: codedindex::SimpleCodedIndex, //Param
}

impl MDTableRowTrait for ParamPtr {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        codedindex::clr_coded_index_struct_size(0, &vec!["Param"], tables_row_counts)
    }

    fn parse(
        &mut self,
        data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = codedindex::clr_coded_index_struct_size(0, &vec!["Param"], tables_row_counts);
        self.field = codedindex::SimpleCodedIndex::new(vec!["Param"], 0, &data[0..s1], tables)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct Param {
    flags: Vec<enums::ClrParamAttr>,
    sequence: usize,
    name: String,
}

impl MDTableRowTrait for Param {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        _tables_row_counts: &[usize],
    ) -> usize {
        2 + 2 + str_offset_size
    }

    fn parse(
        &mut self,
        data: &[u8],
        str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        _tables_row_counts: &[usize],
        _tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = 2;
        let s2 = s1 + 2;
        let s3 = s2 + str_offset_size;
        let strings_heap = if let Some(s) = strings_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("string"));
        };
        self.flags = enums::ClrParamAttr::new(crate::utils::read_usize(&data[0..s1])?);
        self.sequence = crate::utils::read_usize(&data[s1..s2])?;
        self.name = strings_heap.get_string(&data[s2..s3])?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct InterfaceImpl {
    class: codedindex::SimpleCodedIndex, //TypeDef
    interface: codedindex::TypeDefOrRef,
}

impl MDTableRowTrait for InterfaceImpl {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        codedindex::clr_coded_index_struct_size(0, &vec!["TypeDef"], tables_row_counts)
            + codedindex::clr_coded_index_struct_size(
                self.interface.tag_bits,
                &self.interface.table_names,
                tables_row_counts,
            )
    }

    fn parse(
        &mut self,
        data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = codedindex::clr_coded_index_struct_size(0, &vec!["TypeDef"], tables_row_counts);
        let s2 = s1
            + codedindex::clr_coded_index_struct_size(
                self.interface.tag_bits,
                &self.interface.table_names,
                tables_row_counts,
            );
        self.class = codedindex::SimpleCodedIndex::new(vec!["TypeDef"], 0, &data[0..s1], tables)?;
        self.interface.set(&data[s1..s2], tables)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct MemberRef {
    pub class: codedindex::MemberRefParent,
    pub name: String,
    pub signature: Vec<u8>,
}

impl MDTableRowTrait for MemberRef {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        codedindex::clr_coded_index_struct_size(
            self.class.tag_bits,
            &self.class.table_names,
            tables_row_counts,
        ) + str_offset_size
            + blobs_offset_size
    }

    fn parse(
        &mut self,
        data: &[u8],
        str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        blobs_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = codedindex::clr_coded_index_struct_size(
            self.class.tag_bits,
            &self.class.table_names,
            tables_row_counts,
        );
        let s2 = s1 + str_offset_size;
        let s3 = s2 + blobs_offset_size;
        let strings_heap = if let Some(s) = strings_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("string"));
        };
        let blobs_heap = if let Some(s) = blobs_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("blob"));
        };
        self.class.set(&data[0..s1], tables)?;
        self.name = strings_heap.get_string(&data[s1..s2])?;
        self.signature = blobs_heap.get_blob(&data[s2..s3])?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct Constant {
    _type: u32,
    padding: u32,
    parent: codedindex::HasConstant,
    value: Vec<u8>,
}

impl MDTableRowTrait for Constant {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        1 + 1
            + codedindex::clr_coded_index_struct_size(
                self.parent.tag_bits,
                &self.parent.table_names,
                tables_row_counts,
            )
            + blobs_offset_size
    }

    fn parse(
        &mut self,
        data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        blobs_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = 1;
        let s2 = s1 + 1;
        let s3 = s2
            + codedindex::clr_coded_index_struct_size(
                self.parent.tag_bits,
                &self.parent.table_names,
                tables_row_counts,
            );
        let s4 = s3 + blobs_offset_size;
        let blobs_heap = if let Some(s) = blobs_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("blob"));
        };
        self._type = crate::utils::read_usize(&data[0..s1])? as u32;
        self.padding = crate::utils::read_usize(&data[s1..s2])? as u32;
        self.parent.set(&data[s2..s3], tables)?;
        self.value = blobs_heap.get_blob(&data[s3..s4])?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct CustomAttribute {
    parent: codedindex::HasCustomAttribute,
    _type: codedindex::CustomAttributeType,
    value: Vec<u8>,
}

impl MDTableRowTrait for CustomAttribute {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        codedindex::clr_coded_index_struct_size(
            self.parent.tag_bits,
            &self.parent.table_names,
            tables_row_counts,
        ) + codedindex::clr_coded_index_struct_size(
            self._type.tag_bits,
            &self._type.table_names,
            tables_row_counts,
        ) + blobs_offset_size
    }

    fn parse(
        &mut self,
        data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        blobs_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let first = codedindex::clr_coded_index_struct_size(
            self.parent.tag_bits,
            &self.parent.table_names,
            tables_row_counts,
        );
        let second = codedindex::clr_coded_index_struct_size(
            self._type.tag_bits,
            &self._type.table_names,
            tables_row_counts,
        );
        let blobs_heap = if let Some(s) = blobs_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("blob"));
        };
        self.parent.set(&data[0..first], tables)?;
        self._type.set(&data[first..first + second], tables)?;
        self.value =
            blobs_heap.get_blob(&data[first + second..first + second + blobs_offset_size])?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct FieldMarshal {
    parent: codedindex::HasFieldMarshall,
    native_type: Vec<u8>,
}

impl MDTableRowTrait for FieldMarshal {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        codedindex::clr_coded_index_struct_size(
            self.parent.tag_bits,
            &self.parent.table_names,
            tables_row_counts,
        ) + blobs_offset_size
    }

    fn parse(
        &mut self,
        data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        blobs_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = codedindex::clr_coded_index_struct_size(
            self.parent.tag_bits,
            &self.parent.table_names,
            tables_row_counts,
        );
        let s2 = s1 + blobs_offset_size;
        let blobs_heap = if let Some(s) = blobs_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("blob"));
        };
        self.parent.set(&data[0..s1], tables)?;
        self.native_type = blobs_heap.get_blob(&data[s1..s2])?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct DeclSecurity {
    action: u32,
    parent: codedindex::HasDeclSecurity,
    permission_set: Vec<u8>,
}

impl MDTableRowTrait for DeclSecurity {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        2 + codedindex::clr_coded_index_struct_size(
            self.parent.tag_bits,
            &self.parent.table_names,
            tables_row_counts,
        ) + blobs_offset_size
    }

    fn parse(
        &mut self,
        data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        blobs_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = 2;
        let s2 = s1
            + codedindex::clr_coded_index_struct_size(
                self.parent.tag_bits,
                &self.parent.table_names,
                tables_row_counts,
            );
        let s3 = s2 + blobs_offset_size;
        let blobs_heap = if let Some(s) = blobs_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("blob"));
        };
        self.action = crate::utils::read_usize(&data[0..s1])? as u32;
        self.parent.set(&data[s1..s2], tables)?;
        self.permission_set = blobs_heap.get_blob(&data[s2..s3])?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct ClassLayout {
    packing_size: usize,
    class_size: usize,
    parent: codedindex::SimpleCodedIndex,
}

impl MDTableRowTrait for ClassLayout {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        2 + 4 + codedindex::clr_coded_index_struct_size(0, &vec!["TypeDef"], tables_row_counts)
    }

    fn parse(
        &mut self,
        data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobs_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = 2;
        let s2 = 4;
        let s3 =
            s2 + codedindex::clr_coded_index_struct_size(0, &vec!["TypeDef"], tables_row_counts);
        self.packing_size = crate::utils::read_usize(&data[0..s1])?;
        self.class_size = crate::utils::read_usize(&data[s1..s2])?;
        self.parent = codedindex::SimpleCodedIndex::new(vec!["TypeDef"], 0, &data[s2..s3], tables)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct FieldLayout {
    offset: u32,
    field: codedindex::SimpleCodedIndex, // Field
}

impl MDTableRowTrait for FieldLayout {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        4 + codedindex::clr_coded_index_struct_size(0, &vec!["Field"], tables_row_counts)
    }

    fn parse(
        &mut self,
        data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = 4;
        let s2 = s1 + codedindex::clr_coded_index_struct_size(0, &vec!["Field"], tables_row_counts);
        self.offset = crate::utils::read_usize(&data[0..s1])? as u32;
        self.field = codedindex::SimpleCodedIndex::new(vec!["Field"], 0, &data[s1..s2], tables)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct StandAloneSig {
    signature: Vec<u8>,
}

impl MDTableRowTrait for StandAloneSig {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        _tables_row_counts: &[usize],
    ) -> usize {
        blobs_offset_size
    }

    fn parse(
        &mut self,
        data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        _tables_row_counts: &[usize],
        _tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        blobs_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = blobs_offset_size;
        let blobs_heap = if let Some(s) = blobs_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("blob"));
        };
        self.signature = blobs_heap.get_blob(&data[0..s1])?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct EventMap {
    parent: codedindex::SimpleCodedIndex, //  TypeDef,
    event_list: Vec<Event>,
}

impl MDTableRowTrait for EventMap {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        codedindex::clr_coded_index_struct_size(0, &vec!["TypeDef"], tables_row_counts)
            + codedindex::clr_coded_index_struct_size(0, &vec!["Event"], tables_row_counts)
    }

    fn parse(
        &mut self,
        data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = codedindex::clr_coded_index_struct_size(0, &vec!["TypeDef"], tables_row_counts);
        let _s2 =
            s1 + codedindex::clr_coded_index_struct_size(0, &vec!["Event"], tables_row_counts);
        self.parent = codedindex::SimpleCodedIndex::new(vec!["TypeDef"], 0, &data[0..s1], tables)?;
        self.event_list = vec![];
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct EventPtr {}

impl MDTableRowTrait for EventPtr {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        _tables_row_counts: &[usize],
    ) -> usize {
        0
    }

    fn parse(
        &mut self,
        _data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        _tables_row_counts: &[usize],
        _tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        Err(Error::NotImplementedError)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Event {
    event_flags: Vec<enums::ClrEventAttr>,
    name: String,
    event_type: codedindex::TypeDefOrRef,
}

impl MDTableRowTrait for Event {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        2 + str_offset_size
            + codedindex::clr_coded_index_struct_size(
                self.event_type.tag_bits,
                &self.event_type.table_names,
                tables_row_counts,
            )
    }

    fn parse(
        &mut self,
        data: &[u8],
        str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = 2;
        let s2 = s1 + str_offset_size;
        let s3 = s2
            + codedindex::clr_coded_index_struct_size(
                self.event_type.tag_bits,
                &self.event_type.table_names,
                tables_row_counts,
            );
        let strings_heap = if let Some(s) = strings_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("string"));
        };
        self.event_flags = enums::ClrEventAttr::new(crate::utils::read_usize(&data[0..s1])?);
        self.name = strings_heap.get_string(&data[s1..s2])?;
        self.event_type.set(&data[s2..s3], tables)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct PropertyMap {
    pub parent: codedindex::SimpleCodedIndex, //typedef
    pub property_list: Vec<Property>,
}

impl MDTableRowTrait for PropertyMap {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        codedindex::clr_coded_index_struct_size(0, &vec!["TypeDef"], tables_row_counts)
            + codedindex::clr_coded_index_struct_size(0, &vec!["Property"], tables_row_counts)
    }

    fn parse(
        &mut self,
        data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = codedindex::clr_coded_index_struct_size(0, &vec!["TypeDef"], tables_row_counts);
        let _s2 =
            s1 + codedindex::clr_coded_index_struct_size(0, &vec!["Property"], tables_row_counts);
        self.parent = codedindex::SimpleCodedIndex::new(vec!["TypeDef"], 0, &data[0..s1], tables)?;
        self.property_list = vec![];
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct PropertyPtr {}

impl MDTableRowTrait for PropertyPtr {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        _tables_row_counts: &[usize],
    ) -> usize {
        0
    }

    fn parse(
        &mut self,
        _data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        _tables_row_counts: &[usize],
        _tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        Err(Error::NotImplementedError)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Property {
    pub flags: Vec<enums::ClrPropertyAttr>,
    pub name: String,
    pub _type: Vec<u8>,
}

impl MDTableRowTrait for Property {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        _tables_row_counts: &[usize],
    ) -> usize {
        2 + str_offset_size + blobs_offset_size
    }

    fn parse(
        &mut self,
        data: &[u8],
        str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        _tables_row_counts: &[usize],
        _tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        blobs_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = 2;
        let s2 = s1 + str_offset_size;
        let s3 = s2 + blobs_offset_size;
        let blobs_heap = if let Some(s) = blobs_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("blob"));
        };
        let strings_heap = if let Some(s) = strings_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("blob"));
        };
        self.flags = enums::ClrPropertyAttr::new(crate::utils::read_usize(&data[0..s1])?);
        self.name = strings_heap.get_string(&data[s1..s2])?;
        self._type = blobs_heap.get_blob(&data[s2..s3])?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct MethodSemantics {
    pub semantics: Vec<enums::ClrMethodSemanticsAttr>,
    pub method: codedindex::SimpleCodedIndex,
    pub association: codedindex::HasSemantics,
}

impl MDTableRowTrait for MethodSemantics {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        2 + codedindex::clr_coded_index_struct_size(0, &vec!["MethodDef"], tables_row_counts)
            + codedindex::clr_coded_index_struct_size(
                self.association.tag_bits,
                &self.association.table_names,
                tables_row_counts,
            )
    }

    fn parse(
        &mut self,
        data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = 2;
        let s2 =
            s1 + codedindex::clr_coded_index_struct_size(0, &vec!["MethodDef"], tables_row_counts);
        let s3 = s2
            + codedindex::clr_coded_index_struct_size(
                self.association.tag_bits,
                &self.association.table_names,
                tables_row_counts,
            );
        self.semantics =
            enums::ClrMethodSemanticsAttr::new(crate::utils::read_usize(&data[0..s1])?);
        self.method =
            codedindex::SimpleCodedIndex::new(vec!["MethodDef"], 0, &data[s1..s2], tables)?;
        self.association.set(&data[s2..s3], tables)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct MethodImpl {
    class: codedindex::SimpleCodedIndex, // TypeDef,
    method_body: codedindex::MethodDefOrRef,
    method_declaration: codedindex::MethodDefOrRef,
}

impl MDTableRowTrait for MethodImpl {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        codedindex::clr_coded_index_struct_size(0, &vec!["TypeDef"], tables_row_counts)
            + codedindex::clr_coded_index_struct_size(
                self.method_body.tag_bits,
                &self.method_body.table_names,
                tables_row_counts,
            )
            + codedindex::clr_coded_index_struct_size(
                self.method_declaration.tag_bits,
                &self.method_declaration.table_names,
                tables_row_counts,
            )
    }

    fn parse(
        &mut self,
        data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = codedindex::clr_coded_index_struct_size(0, &vec!["TypeDef"], tables_row_counts);
        let s2 = s1
            + codedindex::clr_coded_index_struct_size(
                self.method_body.tag_bits,
                &self.method_body.table_names,
                tables_row_counts,
            );
        let s3 = s2
            + codedindex::clr_coded_index_struct_size(
                self.method_declaration.tag_bits,
                &self.method_declaration.table_names,
                tables_row_counts,
            );
        self.class = codedindex::SimpleCodedIndex::new(vec!["TypeDef"], 0, &data[0..s1], tables)?;
        self.method_body.set(&data[s1..s2], tables)?;
        self.method_declaration.set(&data[s2..s3], tables)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct ModuleRef {
    pub name: String,
}

impl MDTableRowTrait for ModuleRef {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        _tables_row_counts: &[usize],
    ) -> usize {
        str_offset_size
    }

    fn parse(
        &mut self,
        data: &[u8],
        str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        _tables_row_counts: &[usize],
        _tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = str_offset_size;
        let strings_heap = if let Some(s) = strings_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("blob"));
        };
        self.name = strings_heap.get_string(&data[0..s1])?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct TypeSpec {
    signature: Vec<u8>,
}

impl MDTableRowTrait for TypeSpec {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        _tables_row_counts: &[usize],
    ) -> usize {
        blobs_offset_size
    }

    fn parse(
        &mut self,
        data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        _tables_row_counts: &[usize],
        _tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        blobs_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = blobs_offset_size;
        let blobs_heap = if let Some(s) = blobs_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("blob"));
        };
        self.signature = blobs_heap.get_blob(&data[0..s1])?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct ImplMap {
    pub mapping_flags: Vec<enums::ClrPinvokeMap>,
    pub member_forwarded: codedindex::MemberForwarded,
    pub import_name: String,
    pub import_scope: codedindex::SimpleCodedIndex, //moduleref
}

impl MDTableRowTrait for ImplMap {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        2 + codedindex::clr_coded_index_struct_size(
            self.member_forwarded.tag_bits,
            &self.member_forwarded.table_names,
            tables_row_counts,
        ) + str_offset_size
            + codedindex::clr_coded_index_struct_size(0, &vec!["ModuleRef"], tables_row_counts)
    }

    fn parse(
        &mut self,
        data: &[u8],
        str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = 2;
        let s2 = s1
            + codedindex::clr_coded_index_struct_size(
                self.member_forwarded.tag_bits,
                &self.member_forwarded.table_names,
                tables_row_counts,
            );
        let s3 = s2 + str_offset_size;
        let s4 =
            s3 + codedindex::clr_coded_index_struct_size(0, &vec!["ModuleRef"], tables_row_counts);
        let strings_heap = if let Some(s) = strings_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("blob"));
        };
        self.mapping_flags = enums::ClrPinvokeMap::new(crate::utils::read_usize(&data[0..s1])?);
        self.member_forwarded.set(&data[s1..s2], tables)?;
        self.import_name = strings_heap.get_string(&data[s2..s3])?;
        self.import_scope =
            codedindex::SimpleCodedIndex::new(vec!["ModuleRef"], 0, &data[s3..s4], tables)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct FieldRva {
    rva: u32,
    field: codedindex::SimpleCodedIndex, //Field
}

impl MDTableRowTrait for FieldRva {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        4 + codedindex::clr_coded_index_struct_size(0, &vec!["Field"], tables_row_counts)
    }

    fn parse(
        &mut self,
        data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = 4;
        let s2 = s1 + codedindex::clr_coded_index_struct_size(0, &vec!["Field"], tables_row_counts);
        self.rva = crate::utils::read_usize(&data[0..s1])? as u32;
        self.field = codedindex::SimpleCodedIndex::new(vec!["Field"], 0, &data[s1..s2], tables)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct EncLog {
    token: u32,
    func_code: u32,
}

impl MDTableRowTrait for EncLog {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        _tables_row_counts: &[usize],
    ) -> usize {
        4 + 4
    }

    fn parse(
        &mut self,
        data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        _tables_row_counts: &[usize],
        _tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = 4;
        let s2 = s1 + 4;
        self.token = crate::utils::read_usize(&data[0..s1])? as u32;
        self.func_code = crate::utils::read_usize(&data[s1..s2])? as u32;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct EncMap {
    token: u32,
}
impl MDTableRowTrait for EncMap {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        _tables_row_counts: &[usize],
    ) -> usize {
        4
    }

    fn parse(
        &mut self,
        data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        _tables_row_counts: &[usize],
        _tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = 4;
        self.token = crate::utils::read_usize(&data[0..s1])? as u32;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct Assembly {
    pub hash_alg_id: enums::AssemblyHashAlgorithm,
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    pub revision_number: u32,
    pub flags: Vec<enums::ClrAssemblyFlags>,
    pub public_key: Vec<u8>,
    pub name: String,
    pub culture: String,
}

impl MDTableRowTrait for Assembly {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        _tables_row_counts: &[usize],
    ) -> usize {
        4 + 2 + 2 + 2 + 2 + 4 + blobs_offset_size + str_offset_size + str_offset_size
    }

    fn parse(
        &mut self,
        data: &[u8],
        str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        _tables_row_counts: &[usize],
        _tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        blobs_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = 4;
        let s2 = s1 + 2;
        let s3 = s2 + 2;
        let s4 = s3 + 2;
        let s5 = s4 + 2;
        let s6 = s5 + 4;
        let s7 = s6 + blobs_offset_size;
        let s8 = s7 + str_offset_size;
        let s9 = s8 + str_offset_size;
        let strings_heap = if let Some(s) = strings_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("string"));
        };
        let blobs_heap = if let Some(s) = blobs_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("blob"));
        };
        self.hash_alg_id =
            enums::AssemblyHashAlgorithm::new(crate::utils::read_usize(&data[0..s1])?);
        self.major_version = crate::utils::read_usize(&data[s1..s2])? as u32;
        self.minor_version = crate::utils::read_usize(&data[s2..s3])? as u32;
        self.build_number = crate::utils::read_usize(&data[s3..s4])? as u32;
        self.revision_number = crate::utils::read_usize(&data[s4..s5])? as u32;
        self.flags = enums::ClrAssemblyFlags::new(crate::utils::read_usize(&data[s5..s6])?);
        self.public_key = blobs_heap.get_blob(&data[s6..s7])?;
        self.name = strings_heap.get_string(&data[s7..s8])?;
        self.culture = strings_heap.get_string(&data[s8..s9])?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct AssemblyProcessor {
    processor: u32,
}

impl MDTableRowTrait for AssemblyProcessor {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        _tables_row_counts: &[usize],
    ) -> usize {
        4
    }

    fn parse(
        &mut self,
        data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        _tables_row_counts: &[usize],
        _tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = 4;
        self.processor = crate::utils::read_usize(&data[0..s1])? as u32;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct AssemblyOS {
    os_platform_id: u32,
    os_major_version: u32,
    os_minor_version: u32,
}
impl MDTableRowTrait for AssemblyOS {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        _tables_row_counts: &[usize],
    ) -> usize {
        4 + 4 + 4
    }

    fn parse(
        &mut self,
        data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        _tables_row_counts: &[usize],
        _tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = 4;
        let s2 = s1 + 4;
        let s3 = s2 + 4;
        self.os_platform_id = crate::utils::read_usize(&data[0..s1])? as u32;
        self.os_major_version = crate::utils::read_usize(&data[s1..s2])? as u32;
        self.os_minor_version = crate::utils::read_usize(&data[s2..s3])? as u32;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct AssemblyRef {
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    pub revision_number: u32,
    pub flags: Vec<enums::ClrAssemblyFlags>,
    pub public_key: Vec<u8>,
    pub name: String,
    pub culture: String,
    hash_value: Vec<u8>,
}

impl MDTableRowTrait for AssemblyRef {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        _tables_row_counts: &[usize],
    ) -> usize {
        2 + 2
            + 2
            + 2
            + 4
            + blobs_offset_size
            + str_offset_size
            + str_offset_size
            + blobs_offset_size
    }

    fn parse(
        &mut self,
        data: &[u8],
        str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        _tables_row_counts: &[usize],
        _tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        blobs_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = 2;
        let s2 = s1 + 2;
        let s3 = s2 + 2;
        let s4 = s3 + 2;
        let s5 = s4 + 4;
        let s6 = s5 + blobs_offset_size;
        let s7 = s6 + str_offset_size;
        let s8 = s7 + str_offset_size;
        let s9 = s8 + blobs_offset_size;
        let strings_heap = if let Some(s) = strings_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("string"));
        };
        let blobs_heap = if let Some(s) = blobs_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("blob"));
        };
        self.major_version = crate::utils::read_usize(&data[0..s1])? as u32;
        self.minor_version = crate::utils::read_usize(&data[s1..s2])? as u32;
        self.build_number = crate::utils::read_usize(&data[s2..s3])? as u32;
        self.revision_number = crate::utils::read_usize(&data[s3..s4])? as u32;
        self.flags = enums::ClrAssemblyFlags::new(crate::utils::read_usize(&data[s4..s5])?);
        self.public_key = blobs_heap.get_blob(&data[s5..s6])?;
        self.name = strings_heap.get_string(&data[s6..s7])?;
        self.culture = strings_heap.get_string(&data[s7..s8])?;
        self.hash_value = blobs_heap.get_blob(&data[s8..s9])?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct AssemblyRefProcessor {
    processor: u32,
    assembly_ref: codedindex::SimpleCodedIndex, // AssemblyRef
}

impl MDTableRowTrait for AssemblyRefProcessor {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        4 + codedindex::clr_coded_index_struct_size(0, &vec!["AssemblyRef"], tables_row_counts)
    }

    fn parse(
        &mut self,
        data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = 4;
        let s2 = s1
            + codedindex::clr_coded_index_struct_size(0, &vec!["AssemblyRef"], tables_row_counts);
        self.processor = crate::utils::read_usize(&data[0..s1])? as u32;
        self.assembly_ref =
            codedindex::SimpleCodedIndex::new(vec!["AssemblyRef"], 0, &data[s1..s2], tables)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct AssemblyRefOS {
    os_platform_id: u32,
    os_major_version: u32,
    os_minor_version: u32,
    assembly_ref: codedindex::SimpleCodedIndex, // AssemblyRef
}

impl MDTableRowTrait for AssemblyRefOS {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        4 + 4
            + 4
            + codedindex::clr_coded_index_struct_size(0, &vec!["AssemblyRef"], tables_row_counts)
    }

    fn parse(
        &mut self,
        data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = 4;
        let s2 = s1 + 4;
        let s3 = s2 + 4;
        let s4 = s3
            + codedindex::clr_coded_index_struct_size(0, &vec!["AssemblyRef"], tables_row_counts);
        self.os_platform_id = crate::utils::read_usize(&data[0..s1])? as u32;
        self.os_major_version = crate::utils::read_usize(&data[s1..s2])? as u32;
        self.os_minor_version = crate::utils::read_usize(&data[s2..s3])? as u32;
        self.assembly_ref =
            codedindex::SimpleCodedIndex::new(vec!["AssemblyRef"], 0, &data[s3..s4], tables)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct File {
    pub flags: Vec<enums::ClrFileFlags>,
    pub name: String,
    pub hash_value: Vec<u8>,
}

impl MDTableRowTrait for File {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        _tables_row_counts: &[usize],
    ) -> usize {
        4 + str_offset_size + blobs_offset_size
    }

    fn parse(
        &mut self,
        data: &[u8],
        str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        _tables_row_counts: &[usize],
        _tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        blobs_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = 4;
        let s2 = s1 + str_offset_size;
        let s3 = s2 + blobs_offset_size;
        let strings_heap = if let Some(s) = strings_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("string"));
        };
        let blobs_heap = if let Some(s) = blobs_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("blob"));
        };
        self.flags = enums::ClrFileFlags::new(crate::utils::read_usize(&data[0..s1])?);
        self.name = strings_heap.get_string(&data[s1..s2])?;
        self.hash_value = blobs_heap.get_blob(&data[s2..s3])?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct ExportedType {
    flags: enums::ClrTypeAttr,
    type_def_id: u32,
    type_name: String,
    type_namespace: String,
    implementation: codedindex::Implementation,
}

impl MDTableRowTrait for ExportedType {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        4 + 4
            + str_offset_size
            + str_offset_size
            + codedindex::clr_coded_index_struct_size(
                self.implementation.tag_bits,
                &self.implementation.table_names,
                tables_row_counts,
            )
    }

    fn parse(
        &mut self,
        data: &[u8],
        str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = 4;
        let s2 = s1 + 4;
        let s3 = s2 + str_offset_size;
        let s4 = s3 + str_offset_size;
        let s5 = s4
            + codedindex::clr_coded_index_struct_size(
                self.implementation.tag_bits,
                &self.implementation.table_names,
                tables_row_counts,
            );
        let strings_heap = if let Some(s) = strings_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("string"));
        };
        self.flags.set(&data[0..s1])?;
        self.type_def_id = crate::utils::read_usize(&data[s1..s2])? as u32;
        self.type_name = strings_heap.get_string(&data[s2..s3])?;
        self.type_namespace = strings_heap.get_string(&data[s3..s4])?;
        self.implementation.set(&data[s4..s5], tables)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct ManifestResource {
    pub offset: u32,
    pub flags: Vec<enums::ClrManifestResourceFlags>,
    pub name: String,
    pub implementation: codedindex::Implementation,
}

impl MDTableRowTrait for ManifestResource {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        4 + 4
            + str_offset_size
            + codedindex::clr_coded_index_struct_size(
                self.implementation.tag_bits,
                &self.implementation.table_names,
                tables_row_counts,
            )
    }

    fn parse(
        &mut self,
        data: &[u8],
        str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = 4;
        let s2 = s1 + 4;
        let s3 = s2 + str_offset_size;
        let s4 = s3
            + codedindex::clr_coded_index_struct_size(
                self.implementation.tag_bits,
                &self.implementation.table_names,
                tables_row_counts,
            );
        let strings_heap = if let Some(s) = strings_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("string"));
        };
        self.offset = crate::utils::read_usize(&data[0..s1])? as u32;
        self.flags = enums::ClrManifestResourceFlags::new(crate::utils::read_usize(&data[s1..s2])?);
        self.name = strings_heap.get_string(&data[s2..s3])?;
        self.implementation.set(&data[s3..s4], tables)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct NestedClass {
    nested_class: codedindex::SimpleCodedIndex,    //  TypeDef,
    enclosing_class: codedindex::SimpleCodedIndex, // TypeDef
}

impl NestedClass {
    // capa-x patch (see third_party/dnfile/PATCH.md): both columns were
    // private with no accessor, so a consumer walking the nested-class chain
    // (capa's TypeDef/TypeRef name model) had no way to read either RID.
    /// 1-based RID (into `TypeDef`) of the nested class this row describes.
    pub fn nested_class_row_index(&self) -> usize {
        self.nested_class.row_index
    }

    /// 1-based RID (into `TypeDef`) of the class that encloses it.
    pub fn enclosing_class_row_index(&self) -> usize {
        self.enclosing_class.row_index
    }
}

impl MDTableRowTrait for NestedClass {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        codedindex::clr_coded_index_struct_size(0, &vec!["TypeDef"], tables_row_counts)
            + codedindex::clr_coded_index_struct_size(0, &vec!["TypeDef"], tables_row_counts)
    }

    fn parse(
        &mut self,
        data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = codedindex::clr_coded_index_struct_size(0, &vec!["TypeDef"], tables_row_counts);
        let s2 =
            s1 + codedindex::clr_coded_index_struct_size(0, &vec!["TypeDef"], tables_row_counts);
        self.nested_class =
            codedindex::SimpleCodedIndex::new(vec!["TypeDef"], 0, &data[0..s1], tables)?;
        self.enclosing_class =
            codedindex::SimpleCodedIndex::new(vec!["TypeDef"], 0, &data[s1..s2], tables)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct GenericParam {
    number: u32,
    flags: Vec<enums::ClrGenericParamAttr>,
    owner: codedindex::TypeOrMethodDef,
    name: String,
}

impl MDTableRowTrait for GenericParam {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        2 + 2
            + codedindex::clr_coded_index_struct_size(
                self.owner.tag_bits,
                &self.owner.table_names,
                tables_row_counts,
            )
            + str_offset_size
    }

    fn parse(
        &mut self,
        data: &[u8],
        str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = 2;
        let s2 = s1 + 2;
        let s3 = s2
            + codedindex::clr_coded_index_struct_size(
                self.owner.tag_bits,
                &self.owner.table_names,
                tables_row_counts,
            );
        let s4 = s3 + str_offset_size;
        let strings_heap = if let Some(s) = strings_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("string"));
        };
        self.number = crate::utils::read_usize(&data[0..s1])? as u32;
        self.flags = enums::ClrGenericParamAttr::new(crate::utils::read_usize(&data[s1..s2])?);
        self.owner.set(&data[s2..s3], tables)?;
        self.name = strings_heap.get_string(&data[s3..s4])?;
        Ok(())
    }
}

// ECMA-335 II.22.29 (MethodSpec, labeled `GenericMethod` by this fork --
// see `capa-core/src/extract/dotnet/mod.rs`'s `METHODSPEC_RUST_NAME`): a
// generic method instantiation, e.g. `Foo<int>` for a generic `Foo<T>`.
// `method`/`instantiation` were private with no accessor (`unknown1`/
// `unknown2`) until capa-x needed `method` to resolve a
// CIL `call`/`callvirt`/`newobj` operand through a `MethodSpec` token to its
// underlying `MethodDef`/`MemberRef`, the same way pinned Python capa's
// `dnfile/insn.py::get_callee` does via `row.Method`. No parsing behavior
// changed; see `PATCH.md` fix 10.
#[derive(Debug, Clone, Default)]
pub struct GenericMethod {
    pub method: codedindex::MethodDefOrRef,
    pub instantiation: Vec<u8>,
}

impl MDTableRowTrait for GenericMethod {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        codedindex::clr_coded_index_struct_size(
            self.method.tag_bits,
            &self.method.table_names,
            tables_row_counts,
        ) + blobs_offset_size
    }

    fn parse(
        &mut self,
        data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        blobs_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 = codedindex::clr_coded_index_struct_size(
            self.method.tag_bits,
            &self.method.table_names,
            tables_row_counts,
        );
        let s2 = s1 + blobs_offset_size;
        let blobs_heap = if let Some(s) = blobs_heap {
            s
        } else {
            return Err(Error::RefToUndefinedHeap("blob"));
        };
        self.method.set(&data[0..s1], tables)?;
        self.instantiation = blobs_heap.get_blob(&data[s1..s2])?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct GenericParamConstraint {
    owner: codedindex::SimpleCodedIndex, //  GenericParam,
    constraint: codedindex::TypeDefOrRef,
}

impl MDTableRowTrait for GenericParamConstraint {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> usize {
        codedindex::clr_coded_index_struct_size(0, &vec!["GenericParam"], tables_row_counts)
            + codedindex::clr_coded_index_struct_size(
                self.constraint.tag_bits,
                &self.constraint.table_names,
                tables_row_counts,
            )
    }

    fn parse(
        &mut self,
        data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        tables_row_counts: &[usize],
        tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        let s1 =
            codedindex::clr_coded_index_struct_size(0, &vec!["GenericParam"], tables_row_counts);
        let s2 = s1
            + codedindex::clr_coded_index_struct_size(
                self.constraint.tag_bits,
                &self.constraint.table_names,
                tables_row_counts,
            );
        self.owner =
            codedindex::SimpleCodedIndex::new(vec!["GenericParam"], 0, &data[0..s1], tables)?;
        self.constraint.set(&data[s1..s2], tables)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct Unused {}

impl MDTableRowTrait for Unused {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        _tables_row_counts: &[usize],
    ) -> usize {
        0
    }

    fn parse(
        &mut self,
        _data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        _tables_row_counts: &[usize],
        _tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        Err(Error::NotImplementedError)
    }
}

#[derive(Debug, Clone, Default)]
pub struct MaxTable {}

impl MDTableRowTrait for MaxTable {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn size(
        &self,
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        _tables_row_counts: &[usize],
    ) -> usize {
        0
    }

    fn parse(
        &mut self,
        _data: &[u8],
        _str_offset_size: usize,
        _guids_offset_size: usize,
        _blobs_offset_size: usize,
        _tables_row_counts: &[usize],
        _tables: &std::collections::BTreeMap<usize, MetaDataTable>,
        _next_row: Option<&dyn MDTableRowTrait>,
        _strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        _blobss_heap: &Option<&crate::stream::ClrStream<'_>>,
        _guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<()> {
        Err(Error::NotImplementedError)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MetaDataTable {
    number: usize,
    is_sorted: bool,
    pub row_size: usize,
    pub num_rows: usize,
    pub rva: u32,
    pub table: Box<dyn MDTableTrait>,
}

impl MetaDataTable {
    pub fn set_data(&mut self, data: &[u8]) -> Result<()> {
        self.table.set_data(data)
    }
    pub fn row_count(&self) -> usize {
        self.table.row_count()
    }
    pub fn get_row(&self, i: usize) -> Result<&dyn MDTableRowTraitT> {
        self.table.get_row(i)
    }
    pub fn get_mut_row(&mut self, i: usize) -> Result<&mut dyn MDTableRowTraitT> {
        self.table.get_mut_row(i)
    }

    pub fn row<T>(&self, i: usize) -> Result<&T>
    where
        T: MDTableRowTrait + 'static,
    {
        let r = self.get_row(i)?;
        let res = r
            .get_row()
            .as_any()
            .downcast_ref::<T>()
            .ok_or_else(|| Error::RowIndexOutOfBound(i, self.row_count()))?;
        Ok(res)
    }
}

impl<'a> crate::DnPe<'a> {
    pub fn create_md_table(
        &self,
        i: &usize,
        table_rowcounts: &[usize],
        is_sorted: bool,
        strings_offset_size: usize,
        guids_offset_size: usize,
        blobs_offset_size: usize,
    ) -> Result<MetaDataTable> {
        let num_rows = table_rowcounts[*i];
        let table = self.new_mdtable(
            *i,
            &num_rows,
            strings_offset_size,
            guids_offset_size,
            blobs_offset_size,
            table_rowcounts,
        )?;
        let table = MetaDataTable {
            number: *i,
            is_sorted,
            row_size: table.row_size(),
            num_rows,
            rva: 0,
            table,
        };
        Ok(table)
    }

    pub fn new_table<T>(
        &self,
        name: &str,
        num_rows: &usize,
        strings_offset_size: usize,
        guids_offset_size: usize,
        blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> Result<MDTable<T>>
    where
        T: std::fmt::Debug + Default + Clone + MDTableRowTrait,
    {
        MDTable::<T>::new(
            name,
            num_rows,
            strings_offset_size,
            guids_offset_size,
            blobs_offset_size,
            tables_row_counts,
        )
    }

    pub fn new_mdtable(
        &self,
        i: usize,
        num_rows: &usize,
        strings_offset_size: usize,
        guids_offset_size: usize,
        blobs_offset_size: usize,
        tables_row_counts: &[usize],
    ) -> Result<Box<dyn MDTableTrait>> {
        match i {
            0 => Ok(Box::new(self.new_table::<Module>(
                "Module",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            1 => Ok(Box::new(self.new_table::<TypeRef>(
                "TypeRef",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            2 => Ok(Box::new(self.new_table::<TypeDef>(
                "TypeDef",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            3 => Ok(Box::new(self.new_table::<FieldPtr>(
                "FieldPtr",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            4 => Ok(Box::new(self.new_table::<Field>(
                "Field",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            5 => Ok(Box::new(self.new_table::<MethodPtr>(
                "MethodPtr",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            6 => Ok(Box::new(self.new_table::<MethodDef>(
                "MethodDef",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            7 => Ok(Box::new(self.new_table::<ParamPtr>(
                "ParamPtr",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            8 => Ok(Box::new(self.new_table::<Param>(
                "Param",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            9 => Ok(Box::new(self.new_table::<InterfaceImpl>(
                "InterfaceImpl",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            10 => Ok(Box::new(self.new_table::<MemberRef>(
                "MemberRef",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            11 => Ok(Box::new(self.new_table::<Constant>(
                "Constant",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            12 => Ok(Box::new(self.new_table::<CustomAttribute>(
                "CustomAttribute",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            13 => Ok(Box::new(self.new_table::<FieldMarshal>(
                "FieldMarshal",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            14 => Ok(Box::new(self.new_table::<DeclSecurity>(
                "DeclSecurity",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            15 => Ok(Box::new(self.new_table::<ClassLayout>(
                "ClassLayout",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            16 => Ok(Box::new(self.new_table::<FieldLayout>(
                "FieldLayout",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            17 => Ok(Box::new(self.new_table::<StandAloneSig>(
                "StandAloneSig",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            18 => Ok(Box::new(self.new_table::<EventMap>(
                "EventMap",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            19 => Ok(Box::new(self.new_table::<EventPtr>(
                "EventPtr",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            20 => Ok(Box::new(self.new_table::<Event>(
                "Event",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            21 => Ok(Box::new(self.new_table::<PropertyMap>(
                "PropertyMap",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            22 => Ok(Box::new(self.new_table::<PropertyPtr>(
                "PropertyPtr",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            23 => Ok(Box::new(self.new_table::<Property>(
                "Property",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            24 => Ok(Box::new(self.new_table::<MethodSemantics>(
                "MethodSemantics",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            25 => Ok(Box::new(self.new_table::<MethodImpl>(
                "MethodImpl",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            26 => Ok(Box::new(self.new_table::<ModuleRef>(
                "ModuleRef",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            27 => Ok(Box::new(self.new_table::<TypeSpec>(
                "TypeSpec",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            28 => Ok(Box::new(self.new_table::<ImplMap>(
                "ImplMap",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            29 => Ok(Box::new(self.new_table::<FieldRva>(
                "FieldRva",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            30 => Ok(Box::new(self.new_table::<EncLog>(
                "EncLog",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            31 => Ok(Box::new(self.new_table::<EncMap>(
                "EncMap",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            32 => Ok(Box::new(self.new_table::<Assembly>(
                "Assembly",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            33 => Ok(Box::new(self.new_table::<AssemblyProcessor>(
                "AssemblyProcessor",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            34 => Ok(Box::new(self.new_table::<AssemblyOS>(
                "AssemblyOS",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            35 => Ok(Box::new(self.new_table::<AssemblyRef>(
                "AssemblyRef",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            36 => Ok(Box::new(self.new_table::<AssemblyRefProcessor>(
                "AssemblyRefProcessor",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            37 => Ok(Box::new(self.new_table::<AssemblyRefOS>(
                "AssemblyRefOS",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            38 => Ok(Box::new(self.new_table::<File>(
                "File",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            39 => Ok(Box::new(self.new_table::<ExportedType>(
                "ExportedType",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            40 => Ok(Box::new(self.new_table::<ManifestResource>(
                "ManifestResource",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            41 => Ok(Box::new(self.new_table::<NestedClass>(
                "NestedClass",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            42 => Ok(Box::new(self.new_table::<GenericParam>(
                "GenericParam",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            43 => Ok(Box::new(self.new_table::<GenericMethod>(
                "GenericMethod",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            44 => Ok(Box::new(self.new_table::<GenericParamConstraint>(
                "GenericParamConstraint",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            // 45 through 63 are not used
            62 => Ok(Box::new(self.new_table::<Unused>(
                "Unused",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            63 => Ok(Box::new(self.new_table::<MaxTable>(
                "MaxTable",
                num_rows,
                strings_offset_size,
                guids_offset_size,
                blobs_offset_size,
                tables_row_counts,
            )?)),
            _ => Err(Error::UndefinedMetaDataTableIndex(i as u32)),
        }
    }

    pub fn parse_rows(
        &self,
        table: &MetaDataTable,
        _rva: &u32,
        table_data: &[u8],
    ) -> Result<MetaDataTable> {
        let mut table = table.clone();
        table.set_data(table_data)?;
        Ok(table)
    }

    pub fn parse_table(
        &self,
        table: &MetaDataTable,
        ttables: &std::collections::BTreeMap<usize, MetaDataTable>,
        strings_heap: &Option<&crate::stream::ClrStream<'_>>,
        blobs_heap: &Option<&crate::stream::ClrStream<'_>>,
        guids_heap: &Option<&crate::stream::ClrStream<'_>>,
    ) -> Result<MetaDataTable> {
        let mut ttable = table.clone();
        for i in 0..ttable.row_count() {
            let mut next_row = None;
            if i + 1 < table.row_count() {
                next_row = Some(table.get_row(i + 1)?);
            }
            ttable.get_mut_row(i)?.parse(
                ttables,
                next_row,
                strings_heap,
                blobs_heap,
                guids_heap,
            )?;
        }
        let mut tttable = ttable.clone();
        for i in 0..tttable.row_count() {
            let mut next_row = None;
            if i + 1 < ttable.row_count() {
                next_row = Some(ttable.get_row(i + 1)?);
            }
            tttable.get_mut_row(i)?.parse2(
                ttables,
                next_row,
                strings_heap,
                blobs_heap,
                guids_heap,
            )?;
        }
        Ok(tttable)
    }
}

pub fn table_name_2_index(name: &'static str) -> Result<usize> {
    match name {
        "Module" => Ok(0),
        "TypeRef" => Ok(1),
        "TypeDef" => Ok(2),
        "FieldPtr" => Ok(3),
        "Field" => Ok(4),
        "MethodPtr" => Ok(5),
        "MethodDef" => Ok(6),
        "ParamPtr" => Ok(7),
        "Param" => Ok(8),
        "InterfaceImpl" => Ok(9),
        "MemberRef" => Ok(10),
        "Constant" => Ok(11),
        "CustomAttribute" => Ok(12),
        "FieldMarshal" => Ok(13),
        "DeclSecurity" => Ok(14),
        "ClassLayout" => Ok(15),
        "FieldLayout" => Ok(16),
        "StandAloneSig" => Ok(17),
        "EventMap" => Ok(18),
        "EventPtr" => Ok(19),
        "Event" => Ok(20),
        "PropertyMap" => Ok(21),
        "PropertyPtr" => Ok(22),
        "Property" => Ok(23),
        "MethodSemantics" => Ok(24),
        "MethodImpl" => Ok(25),
        "ModuleRef" => Ok(26),
        "TypeSpec" => Ok(27),
        "ImplMap" => Ok(28),
        "FieldRva" => Ok(29),
        "EncLog" => Ok(30),
        "EncMap" => Ok(31),
        "Assembly" => Ok(32),
        "AssemblyProcessor" => Ok(33),
        "AssemblyOS" => Ok(34),
        "AssemblyRef" => Ok(35),
        "AssemblyRefProcessor" => Ok(36),
        "AssemblyRefOS" => Ok(37),
        "File" => Ok(38),
        "ExportedType" => Ok(39),
        "ManifestResource" => Ok(40),
        "NestedClass" => Ok(41),
        "GenericParam" => Ok(42),
        "GenericMethod" => Ok(43),
        "GenericParamConstraint" => Ok(44),
        // 45 through 63 are not used
        "Unused" => Ok(62),
        "MaxTable" => Ok(63),
        _ => Err(Error::UndefinedMetaDataTableName(name)),
    }
}
